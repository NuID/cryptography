(ns nuid.cryptography.hash.algorithm.sha256
  (:refer-clojure :exclude [bytes])
  (:require
   [nuid.bytes :as bytes]
   [nuid.cryptography.base64 :as crypt.base64]
   [nuid.cryptography.hash.algorithm :as alg]
   [nuid.cryptography.hash.lib :as lib]
   #?@(:clj  [[clojure.alpha.spec :as s]]
       :cljs [[clojure.spec.alpha :as s]
              ["hash.js" :as h]]))
  #?@(:clj
      [(:import
        (java.security MessageDigest))]))

(s/def ::parameters
  (s/keys
   :req [:string.normalization/form]
   :opt [::crypt.base64/salt]))

(s/def ::keyfn-parameters
  (s/keys
   :req
   [::crypt.base64/salt
    :string.normalization/form]))

(defn default-parameters
  [& [params]]
  (into lib/default-normalization-parameters params))

(defn digest
  ([input] (digest nil input))
  ([{::crypt.base64/keys        [salt]
     :string.normalization/keys [form]
     :or                        {form lib/default-normalization-form}}
    input]
   (let [salted     (str input salt)
         normalized (lib/normalize salted form)]
     #?(:clj  (.digest (MessageDigest/getInstance "SHA-256") (bytes/from normalized))
        :cljs (bytes/from (.digest (.update (h/sha256) normalized)))))))

(defmethod alg/parameters-multi-spec ::alg/sha256 [_]      ::parameters)
(defmethod alg/default-parameters    ::alg/sha256 [params] (default-parameters params))
(defmethod alg/digest                ::alg/sha256
  ([{:nuid.cryptography.hash/keys [input] :as params}]
   (digest params input))
  ([params input]
   (digest params input)))
