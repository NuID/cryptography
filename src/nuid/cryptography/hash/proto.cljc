(ns nuid.cryptography.hash.proto)

(defprotocol Hashable
  (sha256 [x] [x parameters])
  (sha512 [x] [x parameters])
  (scrypt [x] [x parameters]))
