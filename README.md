# nuid.cryptography

Cross-platform cryptographic facilities.

## ⚠️  This library has not been independently audited.

`nuid.cryptography` primarily exists as a way to abstract over platform-specific differences and provide a common interface to the provided functionality across host platforms. In most cases, `nuid.cryptography` delegates directly to a host implemention (e.g. `jvm` `SecureRandom`, `MessageDigest`, etc.., or `brorand`, `hash.js`, etc.. in node and the browser).

## Git issues and other communications are warmly welcomed. [dev@nuid.io](mailto:dev@nuid.io)

## Requirements

[`jvm`](https://www.java.com/en/download/), [`node + npm`](https://nodejs.org/en/download/), [`clj`](https://clojure.org/guides/getting_started), [`shadow-cljs`](https://shadow-cljs.github.io/docs/UsersGuide.html#_installation)

## From Clojure and ClojureScript

### tools.deps:

`{nuid/cryptography {:git/url "https://github.com/nuid/cryptography" :sha "..."}`

### usage:

```
$ clj # or shadow-cljs node-repl
=> (require '[nuid.cryptography :as crypt])
=> (require '[nuid.bn :as bn])

;; CSRNG
=> (crypt/secure-random-bytes 32)      ;; => 32 CSR bytes
=> (def a (crypt/secure-random-bn 32)) ;; => 32 CSR bytes as a nuid.bn/BN
=> (bn/add a (bn/from "1"))

;; hashing
=> (crypt/sha256 nil "bye!")
=> (def salt (crypt/generate-salt 32))
=> (crypt/sha256 {:salt salt} "salted")

;; The nuid.cryptography/generate-hashfn multifn allows for the specification and
;; hydration of hash functions from data.
;; NOTE: scrypt is currently only implemented for node and the browser.
;; NOTE: see nuid.cryptography/generate-scrypt-parameters defaults
=> (def scrypt-params (crypt/generate-scrypt-parameters {:n 8192}))
=> (def hfn (crypt/generate-hashfn scrypt-params))

;; hash functions generated this way add a :result key to the input opts which is the hash digest
=> (:result (hfn "bye!"))
```

## From JavaScript

This library aims to be usable from JavaScript. More work is necessary to establish the most convient consumption patterns, which will likely ultimatlye involve [`transit-js`](https://github.com/cognitect/transit-js) in place of the calls to `clj->js` and `js->clj` in `nuid.cryptography/wrap-export`.

Currently the main snag is when using `Crypt.generateHashFn`; see below for more information.

### node:

```
$ shadow-cljs release node
$ node
> var Crypt = require('./target/node/nuid_cryptography');
> Crypt.secureRandomBytes(32);
> Crypt.secureRandomBn(32);
> Crypt.sha256("bye!");
> Crypt.scrypt("ess-crypt, not skreeyupt!");
> var hfn = Crypt.generateHashFn(Crypt.generateScryptParameters());

// NOTE: This will work, but will return clojure types.
// In advanced compilation, fields will be named non-deterministically
// which makes this facility essentially unusable.
// transit-js may alleviate this issue.
> hfn("script?");
```

### browser:

```
$ shadow-cljs release browser
## go use ./target/browser/nuid_cryptography.js in a browser script
```

## From Java

To call `nuid.cryptography` from Java or other JVM languages, use one of the recommended interop strategies ([var/IFn](https://clojure.org/reference/java_interop#_calling_clojure_from_java) or [uberjar/aot](https://push-language.hampshire.edu/t/calling-clojure-code-from-java/865)). Doing so may require modifications or additions to the API for convenience.

## From CLR

Coming soon.

## Notes

The purpose of `nuid.cryptography` and sibling `nuid` libraries (e.g. [`nuid.ecc`](https://github.com/nuid/ecc)) is to abstract over platform-specific differences and provide a common interface to fundamental dependencies. This allows us to express dependent logic (e.g. [`nuid.zka`](https://github.com/nuid/zka)) once in pure Clojure(Script), and use it from each of the host platforms (Java, JavaScript, CLR). This is particularly useful for generating and verifying proofs across service boundaries. Along with [`tools.deps`](https://clojure.org/guides/deps_and_cli), this approach yields the code-sharing, circular-dependency avoidance, and local development benefits of a monorepo, with the modularity and orthogonality of an isolated library.

## Contributing

Install [`git-hooks`](https://github.com/icefox/git-hooks) and fire away. Make sure not to get bitten by [`externs`](https://clojurescript.org/guides/externs) if modifying `npm` dependencies.

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
