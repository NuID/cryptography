(ns nuid.cryptography.base64
  (:require
   [clojure.spec.alpha :as s]
   [clojure.spec.gen.alpha :as gen]
   [clojure.test.check.generators]
   [nuid.base64 :as base64]
   [nuid.cryptography :as crypt]))

(defn secure-random-generator
  [num-bytes]
  (->>
   (crypt/secure-random-bytes-generator num-bytes)
   (gen/fmap base64/encode)))

(s/def ::salt
  (s/with-gen
    ::base64/encoded
    (fn [] (secure-random-generator 32))))
