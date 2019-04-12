(ns nuid.cryptography
  (:require
   [nuid.exception :as exception]
   [nuid.base64 :as base64]
   [nuid.bytes :as bytes]
   [nuid.bn :as bn]
   #?@(:cljs
       [["scryptsy" :as scryptjs]
        ["brorand" :as brand]
        ["hash.js" :as h]]))
  #?@(:clj
      [(:import
        (java.security MessageDigest SecureRandom)
        (java.text Normalizer Normalizer$Form))]))

(def secure-random-bytes
  #?(:clj (let [srand (SecureRandom.)]
            (fn [n] (let [b (byte-array n)]
                      (.nextBytes srand b)
                      b)))
     :cljs brand))

(def secure-random-bn (comp bn/from secure-random-bytes))

(defn secure-random-bn-lt [n lt]
  (let [ret (secure-random-bn n)]
    (if (bn/lt? ret lt) ret (recur n lt))))

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
          (Normalizer/normalize x form)))))

   :cljs
   (extend-protocol Normalizable
     string
     (normalize
       ([x] (normalize x "NFKC"))
       ([x form] (.normalize x form)))))

(def salt (comp base64/encode secure-random-bytes))

(defn scrypt-parameters
  [& [{:keys [salt n r p key-length normalization-form]
       :or {salt (salt 32)
            n 16384
            r 16
            p 1
            key-length 32
            normalization-form "NFKC"}}]]
  {:id :scrypt
   :salt salt
   :n n
   :r r
   :p p
   :key-length key-length
   :normalization-form normalization-form})

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
       ([x] (sha512 x {:normalization-from "NFKC"}))
       ([x opts]
        (let [x (if-let [s (:salt opts)] (str x s) x)
              n (normalize x (:normalization-form opts))]
          (let [md (MessageDigest/getInstance "SHA-512")]
            (.digest md (bytes/from n))))))
     (scrypt
       ([x] (scrypt x (scrypt-parameters)))
       ([x opts]
        (let [m "nuid.cryptoraphy does not yet provide scrypt on the jvm."]
          (exception/throw! {:message m})))))

   :cljs
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
       ([x] (scrypt x (scrypt-parameters)))
       ([x {:keys [salt n r p key-length normalization-form]}]
        (let [b (bytes/from (normalize x normalization-form))]
          (scryptjs b salt n r p key-length))))))

(defmulti hashfn :id)
(defmethod hashfn :sha256 [opts]
  (fn [a] (assoc opts :digest (sha256 a opts))))
(defmethod hashfn :sha512 [opts]
  (fn [a] (assoc opts :digest (sha512 a opts))))
(defmethod hashfn :scrypt [opts]
  (let [opts (scrypt-parameters opts)]
    (fn [a] (assoc opts :digest (scrypt a opts)))))

#?(:cljs
   (defn wrap-export [f]
     (let [xf (fn [a] (let [a (js->clj a :keywordize-keys true)]
                        (if (:id a) (update a :id keyword) a)))]
       (fn [& args] (clj->js (apply f (map xf args)))))))

#?(:cljs
   (def exports
     #js {:scryptParameters (wrap-export scrypt-parameters)
          :secureRandomBytes secure-random-bytes
          :secureRandomBnLt secure-random-bn-lt
          :secureRandomBn secure-random-bn
          :scrypt (wrap-export scrypt)
          :sha512 (wrap-export sha512)
          :sha256 (wrap-export sha256)
          :hashFn (wrap-export hashfn)
          :salt salt}))
