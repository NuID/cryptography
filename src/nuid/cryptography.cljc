(ns nuid.cryptography
  (:refer-clojure :exclude [bytes])
  (:require
   [nuid.bytes :as bytes]
   #?@(:clj
       [[clojure.alpha.spec.gen :as gen]
        [clojure.alpha.spec :as s]]
       :cljs
       [[clojure.spec.gen.alpha :as gen]
        [clojure.test.check.generators]
        [clojure.spec.alpha :as s]
        ["brorand" :as secure-random]]))
  #?@(:clj
      [(:import
        (java.security SecureRandom))]))

(def secure-random-bytes
  #?(:clj  (let [secure-random (SecureRandom.)]
             (fn [num-bytes]
               (let [bs (byte-array num-bytes)]
                 (.nextBytes secure-random bs)
                bs)))
     :cljs (comp bytes/from secure-random)))

(s/def ::secure-random-bytes
  (s/with-gen
    bytes/bytes?
    (fn []
      (->>
       (gen/gen-for-pred pos-int?)
       (gen/fmap secure-random-bytes)))))

(defn secure-random-bytes-generator
  [num-bytes]
  (->>
   (gen/return num-bytes)
   (gen/fmap secure-random-bytes)))
