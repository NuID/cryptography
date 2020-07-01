(ns nuid.cryptography.bn
  (:require
   [nuid.bn :as bn]
   [nuid.cryptography :as crypt]
   #?@(:clj
       [[clojure.alpha.spec.gen :as gen]
        [clojure.alpha.spec :as s]]
       :cljs
       [[clojure.spec.gen.alpha :as gen]
        [clojure.test.check.generators]
        [clojure.spec.alpha :as s]])))

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

(defn generate-secure-random-lt
  [num-bytes lt]
  (gen/generate
   (secure-random-lt-generator num-bytes lt)))
