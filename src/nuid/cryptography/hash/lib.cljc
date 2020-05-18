(ns nuid.cryptography.hash.lib
  (:require
   #?@(:clj  [[clojure.alpha.spec :as s]]
       :cljs [[clojure.spec.alpha :as s]]))
  #?@(:clj
      [(:import
        (java.text Normalizer Normalizer$Form))]))

(defprotocol Normalizable
  (normalize
    [x]
    [x form]))

(s/def :string.normalization/form
  #{:string.normalization/NFC
    :string.normalization/NFD
    :string.normalization/NFKC
    :string.normalization/NFKD})

(def default-normalization-form
  :string.normalization/NFKC)

(def default-normalization-parameters
  {:string.normalization/form
   default-normalization-form})

#?(:clj
   (extend-protocol Normalizable
     java.lang.String
     (normalize
       ([x] (normalize x default-normalization-form))
       ([x form]
        (let [form (case form
                     :string.normalization/NFC  Normalizer$Form/NFC
                     :string.normalization/NFD  Normalizer$Form/NFD
                     :string.normalization/NFKC Normalizer$Form/NFKC
                     :string.normalization/NFKD Normalizer$Form/NFKD)]
          (Normalizer/normalize x form))))))

#?(:cljs
   (extend-protocol Normalizable
     string
     (normalize
       ([x] (normalize x default-normalization-form))
       ([x form]
        (let [form (case form
                     :string.normalization/NFC  "NFC"
                     :string.normalization/NFD  "NFD"
                     :string.normalization/NFKC "NFKC"
                     :string.normalization/NFKD "NFKD")]
          (.normalize x form))))))
