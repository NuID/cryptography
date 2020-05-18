(ns nuid.cryptography.hash.algorithm)

(defmulti parameters-multi-spec :nuid.cryptography.hash/algorithm)
(defmulti default-parameters    :nuid.cryptography.hash/algorithm)
(defmulti digest                (fn
                                  ([params]   (:nuid.cryptography.hash/algorithm params))
                                  ([params _] (:nuid.cryptography.hash/algorithm params))))
(defmulti parameters->fn        :nuid.cryptography.hash/algorithm)
