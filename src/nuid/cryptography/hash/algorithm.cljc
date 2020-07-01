(ns nuid.cryptography.hash.algorithm
  (:require
   [nuid.ident.cryptography :as ident.crypt]))

(def algorithms ident.crypt/hash-algorithms)

(defmulti parameters-multi-spec :nuid.cryptography.hash/algorithm)
(defmulti default-parameters    :nuid.cryptography.hash/algorithm)
(defmulti digest                (fn
                                  ([params]   (:nuid.cryptography.hash/algorithm params))
                                  ([params _] (:nuid.cryptography.hash/algorithm params))))
(defmulti parameters->fn        :nuid.cryptography.hash/algorithm)
