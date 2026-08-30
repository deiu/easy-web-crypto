# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases made before this file existed are listed under
[Releases](https://github.com/deiu/easy-web-crypto/releases).

## [2.0.0] - 2026-08-30

### Added

- `jwk` in the type of `importKey` and `exportKey`. Both already accepted it
  at runtime and both document `raw|jwk`, but the published type rejected it
  ([#3]).
- A `Uint8Array` signature and a `raw` format in `verify`, which is what
  `sign(..., 'raw')` returns. The type said `string` and `BufferEncoding` only
  ([#3]).
- Tests for the decryption failure paths: a wrong key, a tampered ciphertext,
  a wrong iv, and the mapping of a browser specific error to
  `Unable to decrypt data`. Line coverage of `src` is now 100% ([#2]).
- A GitHub Actions workflow that typechecks, builds and tests on every push to
  `master` and every pull request. It replaces the Travis config that
  ([#1]) deleted ([#2], [#3]).
- A `prepare` script. `dist/` is no longer committed, so without it
  `npm publish` and an install from the git url both shipped a package with no
  build in it ([#2]).
- `typecheck` and `test:coverage` scripts. `typecheck` covers the tests as
  well as the sources ([#3]).

### Changed

- The build moves from webpack to tsup and emits ESM, CJS and a browser
  bundle, each with its own declarations ([#1]).
- The tests move from mocha-headless-chrome to vitest, so they need no browser
  ([#1]).
- `exportKey` returns a precise type per format: `Uint8Array<ArrayBuffer>` for
  `raw`, `JsonWebKey` for `jwk`, `ArrayBuffer` for the rest. Before it returned
  `ArrayBuffer | Uint8Array<ArrayBuffer>` whatever the format, and every caller
  had to narrow it by hand ([#3]).
- `verify`, `importKey` and `exportKey` are overload pairs, so a format can no
  longer be paired with a value shape the runtime rejects. Three calls that
  used to typecheck and then throw are now compile errors: `verify` with a
  string signature and a `raw` format, `importKey` with a `JsonWebKey` and the
  default `raw` type, and `exportKey<'jwk'>` with the argument left out
  ([#3]).
- **The `<script>` tag bundle moved to `dist/easy-web-crypto.global.js`.**
  `dist/cjs/web-crypto.js` was a UMD bundle that set a `WebCrypto` global;
  since the tsup move it is plain CommonJS and fails in a browser. A page that
  loads that path from a CDN without pinning a version must update the URL
  ([#1], [#2]).

### Removed

- `dist/` is no longer committed to the repository ([#1]).

### Known limitation

`sign`, `exportPublicKey` and `exportPrivateKey` still type their `raw` result
as a bare `Uint8Array`, meaning `Uint8Array<ArrayBufferLike>`, so the result
cannot be passed straight to a `BufferSource` parameter such as
`crypto.subtle.digest`. This predates the changes above and is unchanged, so it
breaks nothing that worked before. A naive fix is not safe: the same type is
used in the parameter positions of `importPublicKey` and `importPrivateKey`,
where narrowing it would reject callers that compile today. It needs a separate
type for the return positions.

### On compatibility

Code that compiled against 1.4.0 still compiles. The type changes accept more
than the old types did, and where a type became narrower it became more
precise, not less. `Parameters<>` and `ReturnType<>` of every changed function
give what they gave before. Runtime behaviour is unchanged: the only
behavioural differences in the built JavaScript are two no-ops, one in `verify`
where `Buffer.from(u8, encoding)` equals `Buffer.from(u8)`, and one in
`importKey` where the `jwk` branch passes the arguments the single call already
passed.

[#1]: https://github.com/deiu/easy-web-crypto/pull/1
[#2]: https://github.com/deiu/easy-web-crypto/pull/2
[#3]: https://github.com/deiu/easy-web-crypto/pull/3
[2.0.0]: https://github.com/deiu/easy-web-crypto/releases/tag/2.0.0
