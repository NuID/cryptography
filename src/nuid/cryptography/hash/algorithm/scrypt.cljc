(ns nuid.cryptography.hash.algorithm.scrypt
  (:refer-clojure :exclude [bytes])
  (:require
   [clojure.spec.alpha :as s]
   [clojure.spec.gen.alpha :as gen]
   [clojure.test.check.generators]
   [nuid.bytes :as bytes]
   [nuid.cryptography.base64 :as crypt.base64]
   [nuid.cryptography.hash.algorithm :as alg]
   [nuid.cryptography.hash.lib :as lib]
   #?@(:cljs
       [["scryptsy" :as scryptjs]]))
  #?@(:clj
      [(:import
        (org.bouncycastle.crypto.generators SCrypt))]))

(s/def ::N #{1024 2048 4096 8192 16384 32768 65536})
(s/def ::r #{8 16 24 32})
(s/def ::p #{1 2})
(s/def ::length #{10 12 16 20 24 32 64})

(s/def ::parameters
  (s/keys
   :req
   [::crypt.base64/salt
    :string.normalization/form
    ::N
    ::r
    ::p
    ::length]))

(def default-N 16384)
(def default-r 8)
(def default-p 1)
(def default-length 32)

(defn default-parameters
  [& [{::crypt.base64/keys        [salt]
       :string.normalization/keys [form]
       ::keys                     [N r p length]
       :as                        params
       :or                        {salt   (gen/generate (s/gen ::crypt.base64/salt))
                                   form   lib/default-string-normalization-form
                                   N      default-N
                                   r      default-r
                                   p      default-p
                                   length default-length}}]]
  (->>
   {::crypt.base64/salt        salt
    :string.normalization/form form
    ::N                        N
    ::r                        r
    ::p                        p
    ::length                   length}
   (into (or params {}))))

(defn digest
  ([input] (digest nil input))
  ([{::crypt.base64/keys        [salt]
     :string.normalization/keys [form]
     ::keys                     [N r p length]
     :or                        {salt   (gen/generate (s/gen ::crypt.base64/salt))
                                 form   lib/default-string-normalization-form
                                 N      default-N
                                 r      default-r
                                 p      default-p
                                 length default-length}}
    input]
   (let [bs (bytes/from (lib/normalize input form))]
     #?(:clj  (SCrypt/generate bs (bytes/from salt) N r p length)
        :cljs (scryptjs bs salt N r p length)))))

(defmethod alg/parameters-multi-spec ::alg/scrypt [_]      ::parameters)
(defmethod alg/default-parameters    ::alg/scrypt [params] (default-parameters params))
(defmethod alg/digest                ::alg/scrypt
  ([{:nuid.cryptography.hash/keys [input] :as params}]
   (digest params input))
  ([params input]
   (digest params input)))
