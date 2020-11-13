<p align="right"><a href="https://nuid.io"><img src="https://nuid.io/svg/logo.svg" width="20%"></a></p>

# nuid.cryptography

Cross-platform cryptographic facilities.

Git issues and other communications are warmly welcomed. [dev@nuid.io](mailto:dev@nuid.io)

## Requirements

[`jvm`](https://www.java.com/en/download/), [`node + npm`](https://nodejs.org/en/download/), [`clj`](https://clojure.org/guides/getting_started), [`shadow-cljs`](https://shadow-cljs.github.io/docs/UsersGuide.html#_installation)

## Clojure and ClojureScript

### tools.deps:

`{nuid/cryptography {:git/url "https://github.com/nuid/cryptography" :sha "..."}}`

## Notes

`nuid.cryptography` primarily exists to abstract over platform-specific
differences and provide a common interface to the provided functionality across
host platforms. `nuid.cryptography` delegates directly to host implementions
(e.g. `SecureRandom`, `MessageDigest`, etc. on the `jvm`, and `brorand`,
`hash.js`, etc., in `node` and the browser).

## Licensing

Apache v2.0 or MIT

## ⚠️  Disclaimer

This library is [property tested](https://github.com/clojure/test.check#testcheck)
to help verify implementation, but has not yet been audited by an independent
third party.
