(ns nuid.cryptography
  (:require
   [nuid.exception :as exception]
   [nuid.base64 :as base64]
   [nuid.bytes :as bytes]
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
  #?(:clj (let [srand (SecureRandom.)]
            (fn [n] (let [b (byte-array n)]
                      (.nextBytes srand b)
                      b)))
     :cljs brand))

(def secure-random-bn (comp bn/from secure-random-bytes))

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

(defn sha256
  ([a] (sha256 nil a))
  ([opts a]
   (let [a (normalize-string opts (if-let [s (:salt opts)] (str a s) a))]
     #?(:clj (let [md (MessageDigest/getInstance "SHA-256")]
               (.digest md (.getBytes a)))
        :cljs (bytes/from (.digest (.update (h/sha256) a)))))))

(defn sha512
  ([a] (sha512 nil a))
  ([opts a]
   (let [a (normalize-string opts (if-let [s (:salt opts)] (str a s) a))]
     #?(:clj (let [md (MessageDigest/getInstance "SHA-512")]
               (.digest md (.getBytes a)))
        :cljs (bytes/from (.digest (.update (h/sha512) a)))))))

(def generate-salt (comp base64/encode secure-random-bytes))

(defn generate-scrypt-parameters
  [& [{:keys [salt n r p key-length normalization-form]
       :or {salt (generate-salt 32)
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

(defn scrypt
  ([a] (scrypt (generate-scrypt-parameters) a))
  ([{:keys [salt n r p key-length normalization-form] :as opts} a]
   (let [a (normalize-string opts a)]
     #?(:clj (exception/throw! {:message "nuid.cryptography does not yet provide scrypt on the jvm."})
        :cljs (scryptjs (b/Buffer.from a) salt n r p key-length)))))

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

#?(:cljs (defn wrap-export [f]
           (let [xf (fn [a] (let [a (js->clj a :keywordize-keys true)]
                              (if (:id a) (update a :id keyword) a)))]
             (fn [& args] (clj->js (apply f (map xf args)))))))

#?(:cljs (def exports
           #js {:generateScryptParameters (wrap-export generate-scrypt-parameters)
                :secureRandomBytes secure-random-bytes
                :secureRandomBn secure-random-bn
                :generateHashFn (wrap-export generate-hashfn)
                :generateSalt generate-salt
                :scrypt (wrap-export scrypt)
                :sha512 (wrap-export sha512)
                :sha256 (wrap-export sha256)
                :randlt randlt}))
