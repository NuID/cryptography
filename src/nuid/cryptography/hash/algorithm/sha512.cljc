(ns nuid.cryptography.hash.algorithm.sha512
  (:refer-clojure :exclude [bytes])
  (:require
   [clojure.spec.alpha :as s]
   [nuid.bytes :as bytes]
   [nuid.cryptography.base64 :as crypt.base64]
   [nuid.cryptography.hash.algorithm :as alg]
   [nuid.cryptography.hash.lib :as lib]
   #?@(:cljs [["hash.js" :as h]]))
  #?@(:clj
      [(:import
        (java.security MessageDigest))]))


   ;;;
   ;;; NOTE: specs, generators
   ;;;


(s/def ::parameters
  (s/keys
   :req [:string.normalization/form]
   :opt [::crypt.base64/salt]))

(s/def ::keyfn-parameters
  (s/keys
   :req
   [::crypt.base64/salt
    :string.normalization/form]))


   ;;;
   ;;; NOTE: helper functions, internal logic
   ;;;


(defn default-parameters
  [& [params]]
  (into lib/default-string-normalization-parameters params))


   ;;;
   ;;; NOTE: api
   ;;;


(defn digest
  ([input] (digest nil input))
  ([{::crypt.base64/keys        [salt]
     :string.normalization/keys [form]
     :or                        {form lib/default-string-normalization-form}}
    input]
   (let [salted     (str input salt)
         normalized (lib/normalize salted form)]
     #?(:clj  (.digest (MessageDigest/getInstance "SHA-512") (bytes/from normalized))
        :cljs (bytes/from (.digest (.update (h/sha512) normalized)))))))


   ;;;
   ;;; NOTE: interface implementations
   ;;;


(defmethod alg/parameters-multi-spec ::alg/sha512
  [_]
  ::parameters)

(defmethod alg/default-parameters ::alg/sha512
  [params]
  (default-parameters params))

(defmethod alg/digest ::alg/sha512
  ([{:nuid.cryptography.hash/keys [input] :as params}]
   (digest params input))
  ([params input]
   (digest params input)))
