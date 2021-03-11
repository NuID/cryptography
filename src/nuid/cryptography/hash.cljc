(ns nuid.cryptography.hash
  (:require
   [clojure.spec.alpha :as s]
   [clojure.spec.gen.alpha :as gen]
   [clojure.test.check.generators]
   [nuid.cryptography.hash.algorithm :as alg]
   [nuid.cryptography.hash.impl]
   [nuid.cryptography.hash.proto :as proto]))

(s/def ::algorithm alg/algorithms)

(s/def ::parameters
  (s/multi-spec
   alg/parameters-multi-spec
   ::algorithm))

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

(def default-parameters alg/default-parameters)
(def digest             alg/digest)
(def parameters->fn     alg/parameters->fn)

(defn sha256
  ([x]            (proto/sha256 x))
  ([x parameters] (proto/sha256 x parameters)))

(defn sha512
  ([x]            (proto/sha512 x))
  ([x parameters] (proto/sha512 x parameters)))

(defn scrypt
  ([x]            (proto/scrypt x))
  ([x parameters] (proto/scrypt x parameters)))

(defmethod alg/parameters->fn :default
  [params]
  (let [params (alg/default-parameters params)]
    (with-meta
      (fn [input]
        (->>
         (alg/digest params input)
         (assoc params ::digest)))
      params)))
