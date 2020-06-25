# Compact JWT implementation in Rust

[![Docs.rs](https://docs.rs/jwt-compact-preview/badge.svg)](https://docs.rs/jwt-compact-preview/)

Minimalistic [JSON web token (JWT)][JWT] implementation with focus on type safety
and secure cryptographic primitives.

This is a fork of [`jwt-compact`](https://docs.rs/jwt-compact/) with several additions:

- RSA support (`RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`)
- `ed25519-compact` backend for Ed25519 signatures
- Backend-agnostic helpers to import and generate RSA and ECDSA keys
- Can be compiled to WebAssembly; compatible with Fastly Compute@Edge.

## Usage

See the crate docs for the examples of usage.

## Features

- Algorithm-specific signing and verifying keys (i.e., type safety).
- Easy to extend to support new signing algorithms.
- The crate supports more compact [CBOR] encoding of the claims.
- `HS256`, `HS384` and `HS512` algorithms are implemented via pure Rust [`sha2`] crate.
- The crate supports `EdDSA` algorithm with the Ed25519 elliptic curve, and `ES256K` algorithm
  with the secp256k1 elliptic curve. Both curves are widely used in crypto community
  and believed to be securely generated (there are some doubts about parameter generation
  for elliptic curves used in standard `ES*` algorithms).
- The crate also optionally supports `RSA` variants (`RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`).

### Missing features

- Support of standard elliptic curve (`ES*`) algorithms.
- Built-in checks of some claims (e.g., `iss` – the token issuer).
  This is intentional: depending on the use case, such claims can have different semantics
  and thus be represented by different datatypes (e.g., `iss` may be a human-readable short ID,
  a hex-encoded key digest, etc.)

## Alternatives

[`jsonwebtoken`], [`frank_jwt`] or [`biscuit`] may be viable alternatives depending on the use case
(e.g., none of them seems to implement `EdDSA` or `ES256K` algorithms).

## License

Licensed under the [Apache-2.0 license](LICENSE).

[JWT]: https://jwt.io/
[CBOR]: https://tools.ietf.org/html/rfc7049
[`sha2`]: https://crates.io/crates/sha2
[`jsonwebtoken`]: https://crates.io/crates/jsonwebtoken
[`frank_jwt`]: https://crates.io/crates/frank_jwt
[`biscuit`]: https://crates.io/crates/biscuit
