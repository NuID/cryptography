(ns nuid.cryptography
  (:require
   [nuid.utils :as utils]
   [nuid.bn :as bn]
   #?@(:cljs
       [["scryptsy" :as scryptjs]
        ["brorand" :as brand]
        ["hash.js" :as h]
        ["buffer" :as b]]))
  #?@(:clj
      [(:import
        (java.security MessageDigest SecureRandom)
        (java.text Normalizer Normalizer$Form))]))

(def secure-random-bytes
  #?(:clj
     (let [srand (SecureRandom.)]
       (fn [n]
         (let [b (byte-array n)]
           (.nextBytes srand b)
           b)))
     :cljs
     (fn [n] (brand n))))

(defn secure-random-bn [n]
  #?(:clj (bn/->BN (BigInteger. 1 (secure-random-bytes n)))
     :cljs (bn/str->bn (secure-random-bytes n))))

(defn randlt [n lt]
  (let [ret (secure-random-bn n)]
    (if (bn/lte? ret lt) ret (recur n lt))))

(defn normalize-string
  [{:keys [normalization-form] :or {normalization-form "NFKC"}} a]
  #?(:clj (let [form (cond (= normalization-form "NFKC") Normalizer$Form/NFKC
                           (= normalization-form "NFKD") Normalizer$Form/NFKD
                           (= normalization-form "NFC" Normalizer$Form/NFC)
                           (= normalization-form "NFD" Normalizer$Form/NFD))]
            (Normalizer/normalize a form))
     :cljs (.normalize a normalization-form)))

(defn sha256 [opts a]
  (let [a (normalize-string opts (if-let [s (:salt opts)] (str a s) a))]
    #?(:clj (let [md (MessageDigest/getInstance "SHA-256")]
              (->> a .getBytes (.digest md)))
       :cljs (-> (h/sha256) (.update a) .digest))))

(defn sha512 [opts a]
  (let [a (normalize-string opts (if-let [s (:salt opts)] (str a s) a))]
    #?(:clj (let [md (MessageDigest/getInstance "SHA-512")]
              (->> a .getBytes (.digest md)))
       :cljs (-> (h/sha512) (.update a) .digest))))

(def generate-salt (comp utils/str->base64 secure-random-bytes))

(defn generate-scrypt-parameters
  [{:keys [salt n r p key-length normalization-form]
    :or {salt (generate-salt 32)
         n 16384
         r 16
         p 1
         key-length 32
         normalization-form "NFKC"}
    :as parameters}]
  {:id :scrypt
   :salt salt
   :n n
   :r r
   :p p
   :key-length key-length
   :normalization-form normalization-form})

(defn scrypt
  [{:keys [salt n r p key-length normalization-form] :as opts} a]
  (let [a (normalize-string opts a)]
    #?(:cljs (scryptjs (b/Buffer.from a) salt n r p key-length))))

(defmulti generate-hashfn :id)
(defmethod generate-hashfn :scrypt
  [opts]
  (let [params (generate-scrypt-parameters opts)]
    (fn [a] (assoc params :result (scrypt params a)))))
(defmethod generate-hashfn :sha512
  [opts]
  (fn [a] (assoc opts :result (sha512 opts a))))
(defmethod generate-hashfn :sha256
  [opts]
  (fn [a] (assoc opts :result (sha256 opts a))))

#?(:cljs (def exports
           #js {:generate-scrypt-parameters generate-scrypt-parameters
                :secure-random-bytes secure-random-bytes
                :secure-random-bn secure-random-bn
                :generate-hashfn generate-hashfn
                :generate-salt generate-salt
                :scrypt scrypt
                :sha512 sha512
                :sha256 sha256
                :randlt randlt}))
