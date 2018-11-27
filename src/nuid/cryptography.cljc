(ns nuid.cryptography
  (:require
   [nuid.bn :as bn]
   #?@(:cljs
       [["scryptsy" :as scryptjs]
        ["brorand" :as brand]
        ["hash.js" :as h]
        ["buffer" :as b]]))
  #?@(:clj
      [(:import
        (java.security
         MessageDigest
         SecureRandom))]))

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
    (if (bn/lte ret lt) ret (recur n lt))))

(defn sha256 [a]
  #?(:cljs (-> (h/sha256) (.update a) .digest)))

(defn sha512 [a]
  #?(:clj
     (let [md (MessageDigest/getInstance "SHA-512")]
       (->> a .getBytes (.digest md)))
     :cljs
     (-> (h/sha512) (.update a) .digest)))

(defn generate-salt [n]
  #?(:cljs (.toString (b/Buffer.from (secure-random-bytes n)) "base64")))

(defn generate-scrypt-parameters
  [{:keys [salt n r p key-length normalization-form]}]
  {:fn :scrypt
   :salt (or salt (generate-salt 32))
   :normalization-form (or normalization-form "NFKC")
   :key-length (or key-length 32)
   :n (or n 16384)
   :r (or r 16)
   :p (or p 1)})

(defn scrypt
  [{:keys [salt n r p key-length normalization-form]} a]
  #?(:cljs
     (let [form (or normalization-form "NFKC")
           a' (if (string? a)
                (b/Buffer.from (.normalize a form))
                a)]
       (scryptjs a' salt n r p key-length))))

(defmulti generate-hashfn :fn)
(defmethod generate-hashfn :scrypt
  [opts]
  (let [params (generate-scrypt-parameters opts)]
    (fn [a] (assoc params :result (scrypt params a)))))

(defmethod generate-hashfn :sha512
  [opts]
  (fn [a] (assoc opts :result (sha512 a))))

#?(:cljs (def exports
           #js {:generate-scrypt-parameters generate-scrypt-parameters
                :secure-random-bytes secure-random-bytes
                :secure-random-bn secure-random-bn
                :generate-hashfn generate-hashfn
                :generate-salt generate-salt
                :sha256 sha256
                :sha512 sha512
                :scrypt scrypt
                :randlt randlt}))
