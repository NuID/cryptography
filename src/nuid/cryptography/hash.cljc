(ns nuid.cryptography.hash
  (:require
   [nuid.cryptography.hash.algorithm :as alg]
   [nuid.cryptography.hash.algorithm.scrypt :as scrypt]
   [nuid.cryptography.hash.algorithm.sha256 :as sha256]
   [nuid.cryptography.hash.algorithm.sha512 :as sha512]
   [nuid.cryptography.hash.proto :as proto]
   #?@(:clj
       [[clojure.alpha.spec.gen :as gen]
        [clojure.alpha.spec :as s]]
       :cljs
       [[clojure.spec.gen.alpha :as gen]
        [clojure.test.check.generators]
        [clojure.spec.alpha :as s]])))

(def algorithms
  #{::alg/sha256
    ::alg/sha512
    ::alg/scrypt})

(s/def ::algorithm
  algorithms)

(s/def ::parameters
  (s/multi-spec
   alg/parameters-multi-spec
   ::algorithm))

(def default-parameters alg/default-parameters)
(def digest             alg/digest)
(def parameters->fn     alg/parameters->fn)

  ;; TODO: throw if no ::algorithm
(defmethod alg/parameters->fn :default
  [params]
  (let [params (alg/default-parameters params)]
    (with-meta
      (fn [input]
        (->>
         (alg/digest params input)
         (assoc params ::digest)))
      params)))

(s/def ::conformed-hashfn
  (s/and
   fn?
   (fn [x] (s/valid? ::parameters (meta x)))))

(s/def ::parameters<>hashfn
  (s/conformer
   (fn [x]
     (if (s/valid? ::conformed-hashfn x)
       x
       (let [params (s/conform ::parameters x)]
         (if (s/invalid? params)
           params
           (alg/parameters->fn params)))))
   (fn [x]
     (cond
       (s/valid? ::parameters x)       x
       (s/valid? ::conformed-hashfn x) (meta x)
       :else                           ::s/invalid))))

(s/def ::hashfn
  (s/with-gen
    ::parameters<>hashfn
    (fn []
      (->>
       (s/gen ::parameters)
       (gen/fmap (partial s/conform ::parameters<>hashfn))))))

(extend-protocol proto/Hashable
  #?@(:clj  [java.lang.String]
      :cljs [string])
  (sha256
    ([x]            (sha256/digest nil x))
    ([x parameters] (sha256/digest parameters x)))
  (sha512
    ([x]            (sha512/digest nil x))
    ([x parameters] (sha512/digest parameters x)))
  (scrypt
    ([x]            (scrypt/digest nil x))
    ([x parameters] (scrypt/digest parameters x))))

(def sha256 proto/sha256)
(def sha512 proto/sha512)
(def scrypt proto/scrypt)
