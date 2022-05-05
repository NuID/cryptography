(ns nuid.cryptography.hash.bn
  (:require
   [clojure.spec.alpha :as s]
   [clojure.spec.gen.alpha :as gen]
   [clojure.test.check.generators]
   [nuid.bn :as bn]
   [nuid.cryptography.base64 :as crypt.base64]
   [nuid.cryptography.hash :as hash]
   [nuid.cryptography.hash.algorithm :as alg]
   [nuid.cryptography.hash.algorithm.scrypt :as scrypt]))


   ;;;
   ;;; NOTE: specs, generators
   ;;;


(s/def ::conformed-hashfn
  (s/and
   ::hash/conformed-hashfn
   (fn [f] (::conformed? (meta f)))))

;; NOTE: used for converting a data representation to a hash function,
;;       and the reverse operation
(s/def ::parameters<>hashfn
  (s/conformer
   (fn [x]
     (if (s/valid? ::conformed-hashfn x)
       x
       (let [f (s/conform ::hash/parameters<>hashfn x)]
         (if (s/invalid? f)
           f
           (with-meta
             (comp bn/from ::hash/digest f)
             (assoc (meta f) ::conformed? true))))))
   (fn [x]
     (cond
       (s/valid? ::hash/parameters x)  (dissoc x ::conformed?)
       (s/valid? ::conformed-hashfn x) (dissoc (meta x) ::conformed?)
       :else                           ::s/invalid))))

(s/def ::sha-hashfn-parameters
  (s/keys
   :req [:string.normalization/form]))

(defmulti  hashfn-parameters-multi-spec ::hash/algorithm)
(defmethod hashfn-parameters-multi-spec ::alg/sha256 [_] ::sha-hashfn-parameters)
(defmethod hashfn-parameters-multi-spec ::alg/sha512 [_] ::sha-hashfn-parameters)

(s/def ::hashfn-parameters
  (s/multi-spec hashfn-parameters-multi-spec ::hash/algorithm))

(s/def ::hashfn
  (s/with-gen
    ::parameters<>hashfn
    (fn []
      (->>
       (s/gen ::hashfn-parameters)
       (gen/fmap (partial s/conform ::parameters<>hashfn))))))

(s/def ::sha-keyfn-parameters
  (s/keys
   :req
   [::crypt.base64/salt
    :string.normalization/form]))

(defmulti  keyfn-parameters-multi-spec ::hash/algorithm)
(defmethod keyfn-parameters-multi-spec ::alg/sha256 [_] ::sha-keyfn-parameters)
(defmethod keyfn-parameters-multi-spec ::alg/sha512 [_] ::sha-keyfn-parameters)
(defmethod keyfn-parameters-multi-spec ::alg/scrypt [_] ::scrypt/parameters)

(s/def ::keyfn-parameters
  (s/multi-spec keyfn-parameters-multi-spec ::hash/algorithm))

(s/def ::keyfn
  (s/with-gen
    ::parameters<>hashfn
    (fn []
      (->>
       (s/gen ::keyfn-parameters)
       (gen/fmap (partial s/conform ::parameters<>hashfn))))))
