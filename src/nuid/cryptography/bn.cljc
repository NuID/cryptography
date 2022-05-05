(ns nuid.cryptography.bn
  (:require
   [clojure.spec.alpha :as s]
   [clojure.spec.gen.alpha :as gen]
   [clojure.test.check.generators]
   [nuid.bn :as bn]
   [nuid.cryptography :as crypt]))


   ;;;
   ;;; NOTE: specs, generators
   ;;;

(defn secure-random-generator
  [num-bytes]
  (->>
   (crypt/secure-random-bytes-generator num-bytes)
   (gen/fmap bn/from)))

(s/def ::nonce
  (s/with-gen
    ::bn/bn
    (fn [] (secure-random-generator 32))))

(defn secure-random-lt-generator
  [num-bytes lt]
  (let [g (secure-random-generator num-bytes)]
    (gen/such-that (fn [n] (bn/lt? n lt)) g 500)))


   ;;;
   ;;; NOTE: api
   ;;;


(defn generate-secure-random-lt
  [num-bytes lt]
  (gen/generate
   (secure-random-lt-generator num-bytes lt)))

(defn generate-nonce []
  (->> (gen/generate (s/gen ::nonce))
       (s/unform ::nonce)))
