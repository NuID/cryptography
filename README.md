# nuid.cryptography

Cross-platform cryptographic facilities.

## ⚠️  This library has not been independently audited.

`nuid.cryptography` primarily exists to abstract over platform-specific differences and provide a common interface to the provided functionality across host platforms. In most cases, `nuid.cryptography` delegates directly to a host implemention (e.g. `SecureRandom`, `MessageDigest`, etc. on the `jvm`, and `brorand`, `hash.js`, etc. in `node` and the browser).

## Git issues and other communications are warmly welcomed. [dev@nuid.io](mailto:dev@nuid.io)

## Requirements

[`jvm`](https://www.java.com/en/download/), [`node + npm`](https://nodejs.org/en/download/), [`clj`](https://clojure.org/guides/getting_started), [`shadow-cljs`](https://shadow-cljs.github.io/docs/UsersGuide.html#_installation)

## From Clojure and ClojureScript

### tools.deps:

`{nuid/cryptography {:git/url "https://github.com/nuid/cryptography" :sha "..."}}`

### usage:

```
$ clj # or shadow-cljs node-repl
=> (require '[nuid.cryptography :as crypt])
=> (require '[nuid.bn :as bn])

;; CSRNG
=> (crypt/secure-random-bytes 32)      ;; => 32 CSR bytes
=> (def a (crypt/secure-random-bn 32)) ;; => 32 CSR bytes as a BN
=> (bn/add a (bn/from "1"))

;; hashing
=> (crypt/sha256 "bye!")
=> (def salt (crypt/salt 32))
=> (crypt/sha256 "salted" {:salt salt})

;; The nuid.cryptography/hashfn multifn allows for the specification and
;; hydration of hash functions from data.
;; NOTE: scrypt is currently only implemented for node and the browser.
;; NOTE: see nuid.cryptography/scrypt-parameters defaults
=> (def hfn (crypt/hashfn (crypt/scrypt-parameters)))

;; hash functions generated this way add a :digest key to the input opts
=> (:digest (hfn "bye!"))
```

## From JavaScript

This library aims to be usable from JavaScript. More work is necessary to establish the most convient consumption patterns.

Currently the main snag is when using `Crypt.hashFn`; see below for more information.

### node:

```
$ node
> var Crypt = require('@nuid/cryptography');
> Crypt.secureRandomBytes(32);
> Crypt.secureRandomBn(32);
> Crypt.sha256("bye!");
> Crypt.scrypt("ess-crypt not skreeyupt");
> var hfn = Crypt.hashFn(Crypt.scryptParameters());

// NOTE: This will work, but will return clojure types.
// In advanced compilation, fields will be named non-deterministically
// which makes this facility essentially unusable.
> hfn("script?");
```

### browser:

The `npm` package is browser compatible in Webpack-like workflows.

## From Java

To call `nuid.cryptography` from Java or other JVM languages, use one of the recommended interop strategies ([var/IFn](https://clojure.org/reference/java_interop#_calling_clojure_from_java) or [uberjar/aot](https://push-language.hampshire.edu/t/calling-clojure-code-from-java/865)). Doing so may require modifications or additions to the API for convenience.

## From CLR

Coming soon.

## Notes

The purpose of `nuid.cryptography` and sibling `nuid` libraries (e.g. [`nuid.elliptic`](https://github.com/nuid/elliptic)) is to abstract over platform-specific differences and provide a common interface to fundamental dependencies. This allows us to express dependent logic (e.g. [`nuid.zk`](https://github.com/nuid/zk)) once in pure Clojure(Script), and use it from each of the host platforms (Java, JavaScript, CLR). This is particularly useful for generating and verifying proofs across service boundaries. Along with [`tools.deps`](https://clojure.org/guides/deps_and_cli), this approach yields the code-sharing, circular-dependency avoidance, and local development benefits of a monorepo, with the modularity and orthogonality of an isolated library.

## Licensing

Apache v2.0 or MIT

## Contributing

### formatting:

```
$ clojure -A:cljfmt            # check
$ clojure -A:cljfmt:cljfmt/fix # fix
```

### dependencies:

```
## check
$ npm outdated
$ clojure -A:depot

## update
$ npm upgrade -s
$ clojure -A:depot:depot/update
```
