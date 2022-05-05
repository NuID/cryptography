(ns nuid.cryptography.hash.impl
  (:require
   [nuid.cryptography.hash.algorithm.scrypt :as scrypt]
   [nuid.cryptography.hash.algorithm.sha256 :as sha256]
   [nuid.cryptography.hash.algorithm.sha512 :as sha512]
   [nuid.cryptography.hash.proto :as proto]))


   ;;;
   ;;; NOTE: clj; extend hash algoritms to platform `string`
   ;;;


(extend-protocol proto/Hashable
  java.lang.String
  (sha256
    ([x]            (sha256/digest nil x))
    ([x parameters] (sha256/digest parameters x)))
  (sha512
    ([x]            (sha512/digest nil x))
    ([x parameters] (sha512/digest parameters x)))
  (scrypt
    ([x]            (scrypt/digest nil x))
    ([x parameters] (scrypt/digest parameters x))))
