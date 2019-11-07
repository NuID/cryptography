(ns nuid.cryptography
  (:refer-clojure :exclude [bytes])
  (:require
   [nuid.base64 :as base64]
   [nuid.bytes :as bytes]
   [nuid.bn :as bn]
   #?@(:clj
       [[clojure.spec-alpha2.gen :as gen]
        [clojure.spec-alpha2 :as s]]
       :cljs
       [[clojure.spec.gen.alpha :as gen]
        [clojure.test.check.generators]
        [clojure.spec.alpha :as s]
        ["brorand" :as secure-random]
        ["scryptsy" :as scryptjs]
        ["hash.js" :as h]]))
  #?@(:clj
      [(:import
        (org.bouncycastle.crypto.generators SCrypt)
        (java.security MessageDigest SecureRandom)
        (java.text Normalizer Normalizer$Form))]))

(def secure-random-bytes
  #?(:clj (let [secure-random (SecureRandom.)]
            (fn [num-bytes]
              (let [bs (byte-array num-bytes)]
                (.nextBytes secure-random bs)
                bs)))
     :cljs (comp bytes/from secure-random)))

(s/def ::secure-random-bytes
  (s/with-gen
    bytes/bytes?
    (fn []
      (->>
       (gen/gen-for-pred pos-int?)
       (gen/fmap secure-random-bytes)))))

(defn secure-random-bytes-generator
  [num-bytes]
  (->>
   (gen/return num-bytes)
   (gen/fmap secure-random-bytes)))

(defn secure-random-bn-generator
  [num-bytes]
  (->>
   (secure-random-bytes-generator num-bytes)
   (gen/fmap bn/from)))

(defn secure-random-bn-lt-generator
  [num-bytes lt]
  (let [g (secure-random-bn-generator num-bytes)]
    (gen/such-that (fn [n] (bn/lt? n lt)) g 500)))

(defn generate-secure-random-bn-lt
  [num-bytes lt]
  (gen/generate
   (secure-random-bn-lt-generator num-bytes lt)))

(defn secure-random-base64-generator
  [num-bytes]
  (->>
   (secure-random-bytes-generator num-bytes)
   (gen/fmap base64/encode)))

(s/def ::nonce
  (s/with-gen
    ::bn/bn
    (fn [] (secure-random-bn-generator 32))))

(s/def ::salt
  (s/with-gen
    ::base64/encoded
    (fn [] (secure-random-base64-generator 32))))

(s/def ::normalization-form #{"NFC" "NFKC" "NFD" "NFKD"})

(defprotocol Normalizable
  (normalize [x] [x form]))

#?(:clj
   (extend-protocol Normalizable
     java.lang.String
     (normalize
       ([x] (normalize x "NFKC"))
       ([x form]
        (let [form (condp = form
                     "NFKC" Normalizer$Form/NFKC
                     "NFKD" Normalizer$Form/NFKD
                     "NFC"  Normalizer$Form/NFC
                     "NFD"  Normalizer$Form/NFD)]
          (Normalizer/normalize x form))))))

#?(:cljs
   (extend-protocol Normalizable
     string
     (normalize
       ([x] (normalize x "NFKC"))
       ([x form] (.normalize x form)))))

(s/def ::id #{"scrypt" "sha512" "sha256"})

;; TODO: clean up once cljs supports `s/select`
(s/def ::sha2-base-parameters
  (s/keys :req-un [::id ::normalization-form]
          :opt-un [::salt]))

(s/def ::sha256-parameters
  (s/with-gen
    (s/and ::sha2-base-parameters
           (fn [m] (= "sha256" (:id m))))
    (fn []
      (->>
       (s/gen ::sha2-base-parameters)
       (gen/fmap (fn [m] (merge m {:id "sha256"})))))))

(def default-sha256-parameters-generator
  (->>
   (s/gen ::sha256-parameters)
   (gen/fmap (fn [m] (assoc m :normalization-form "NFKC")))
   (gen/fmap (fn [m] (dissoc m :salt)))))

(def default-sha256-parameters
  (gen/generate
   default-sha256-parameters-generator))

(s/def ::salted? (s/keys :req-un [::salt]))

(s/def ::salted-sha256-parameters
  (s/merge ::salted? ::sha256-parameters))

(s/def ::sha512-parameters
  (s/with-gen
    (s/and ::sha2-base-parameters
           (fn [m] (= "sha512" (:id m))))
    (fn []
      (->>
       (s/gen ::sha2-base-parameters)
       (gen/fmap (fn [m] (merge m {:id "sha512"})))))))

(s/def ::n #{1024 2048 4096 8192 16384 32768 65536})
(s/def ::r #{8 16 24})
(s/def ::p #{1})
(s/def ::key-length #{10 12 16 20 24 32 64})

(s/def ::scrypt-base-parameters
  (s/merge
   ::sha2-base-parameters
   (s/keys :req-un [::n ::r ::p ::key-length ::salt])))

(s/def ::scrypt-parameters
  (s/with-gen
    (s/and ::scrypt-base-parameters
           (fn [m] (= "scrypt" (:id m))))
    (fn []
      (->>
       (s/gen ::scrypt-base-parameters)
       (gen/fmap (fn [m] (merge m {:id "scrypt"})))))))

(def default-scrypt-parameters-generator
  (->>
   (s/gen ::scrypt-parameters)
   (gen/fmap (fn [m] (merge m {:n                  16384
                               :r                  8
                               :key-length         32
                               :normalization-form "NFKC"})))))

(def generate-default-scrypt-parameters
  (partial
   gen/generate
   default-scrypt-parameters-generator))

(s/def ::keyfn-parameters
  (s/or
   ::sha256 ::salted-sha256-parameters
   ::scrypt ::scrypt-parameters))

(s/def ::hashfn-parameters
  (s/or
   ::sha256 ::sha256-parameters
   ::sha512 ::sha512-parameters
   ::scrypt ::scrypt-parameters))

(defprotocol Hashable
  (sha256 [x] [x opts])
  (sha512 [x] [x opts])
  (scrypt [x] [x opts]))

#?(:clj
   (extend-protocol Hashable
     java.lang.String
     (sha256
       ([x] (sha256 x {:normalization-form "NFKC"}))
       ([x opts]
        (let [x (if-let [s (:salt opts)] (str x s) x)
              n (normalize x (:normalization-form opts))]
          (let [md (MessageDigest/getInstance "SHA-256")]
            (.digest md (bytes/from n))))))

     (sha512
       ([x] (sha512 x {:normalization-form "NFKC"}))
       ([x opts]
        (let [x (if-let [s (:salt opts)] (str x s) x)
              n (normalize x (:normalization-form opts))]
          (let [md (MessageDigest/getInstance "SHA-512")]
            (.digest md (bytes/from n))))))

     (scrypt
       ([x] (scrypt x (generate-default-scrypt-parameters)))
       ([x {:keys [salt n r p key-length normalization-form]}]
        (let [x (bytes/from (normalize x normalization-form))
              s (bytes/from salt)]
          (SCrypt/generate x s n r p key-length))))))

#?(:cljs
   (extend-protocol Hashable
     string
     (sha256
       ([x] (sha256 x {:normalization-form "NFKC"}))
       ([x opts]
        (let [x (if-let [s (:salt opts)] (str x s) x)
              n (normalize x (:normalization-form opts))]
          (bytes/from (.digest (.update (h/sha256) n))))))

     (sha512
       ([x] (sha512 x {:normalization-form "NFKC"}))
       ([x opts]
        (let [x (if-let [s (:salt opts)] (str x s) x)
              n (normalize x (:normalization-form opts))]
          (bytes/from (.digest (.update (h/sha512) n))))))

     (scrypt
       ([x] (scrypt x (generate-default-scrypt-parameters)))
       ([x {:keys [salt n r p key-length normalization-form]}]
        (let [b (bytes/from (normalize x normalization-form))]
          (scryptjs b salt n r p key-length))))))

(defmulti generate-hashfn
  (fn [opts]
    (let [opts (s/conform ::hashfn-parameters opts)]
      (if (s/invalid? opts)
        opts
        (first opts)))))

(defmethod generate-hashfn ::sha256
  [opts]
  (fn [x] (assoc opts :digest (sha256 x opts))))

(defmethod generate-hashfn ::sha512
  [opts]
  (fn [x] (assoc opts :digest (sha512 x opts))))

(defmethod generate-hashfn ::scrypt
  [opts]
  (let [opts (merge (generate-default-scrypt-parameters) opts)]
    (fn [x] (assoc opts :digest (scrypt x opts)))))

(s/def ::conformed-hashfn
  (s/and
   fn?
   #(s/valid? ::hashfn-parameters (::opts (meta %)))))

(s/def ::hashfn
  (s/with-gen
    (s/conformer
     (fn [x]
       (if (s/valid? ::conformed-hashfn x)
         x
         (let [x (s/conform ::hashfn-parameters x)]
           (if (s/invalid? x)
             x
             (with-meta
               (generate-hashfn (second x))
               {::opts (second x)})))))
     (fn [x]
       (if (s/valid? ::hashfn-parameters x)
         x
         (if (s/valid? ::hashfn-parameters (::opts (meta x)))
           (::opts (meta x))
           ::s/invalid))))
    (fn [] (s/gen ::hashfn-parameters))))

#?(:cljs (def exports #js {}))
