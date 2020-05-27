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

(def string-normalization-forms
  #{:string.normalization/NFC
    :string.normalization/NFD
    :string.normalization/NFKC
    :string.normalization/NFKD})

(s/def :string.normalization/form
  string-normalization-forms)

(def default-string-normalization-form
  :string.normalization/NFKC)

(def default-string-normalization-parameters
  {:string.normalization/form
   default-string-normalization-form})

#?(:clj
   (extend-protocol Normalizable
     java.lang.String
     (normalize
       ([x] (normalize x default-string-normalization-form))
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
       ([x] (normalize x default-string-normalization-form))
       ([x form]
        (let [form (case form
                     :string.normalization/NFC  "NFC"
                     :string.normalization/NFD  "NFD"
                     :string.normalization/NFKC "NFKC"
                     :string.normalization/NFKD "NFKD")]
          (.normalize x form))))))
