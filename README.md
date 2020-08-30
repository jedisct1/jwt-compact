# Compact JWT implementation in Rust

[![Docs.rs](https://docs.rs/jwt-compact-preview/badge.svg)](https://docs.rs/jwt-compact-preview/)

# DEPRECATED - This crate has been replaced by [`jwt-simple`](https://github.com/jedisct1/rust-jwt-simple)

Minimalistic [JSON web token (JWT)][JWT] implementation with focus on type safety
and secure cryptographic primitives.

This is a fork of [`jwt-compact`](https://docs.rs/jwt-compact/) with several additions:

- RSA support (`RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`)
- `ed25519-compact` backend for Ed25519 signatures
- Standard p256 (`ES256`) support
- Pure Rust `secp256k1` (`ES256k`) support
- Backend-agnostic helpers to import and generate RSA and ECDSA keys
- Can be compiled to WebAssembly; compatible with Fastly Compute@Edge.
