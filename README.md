# boring2

[![CI](https://github.com/0x676e67/boring2/actions/workflows/ci.yml/badge.svg)](https://github.com/0x676e67/boring2/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/boring2.svg)](https://crates.io/crates/boring2)

BoringSSL bindings are available for the Rust programming language, and the HTTP [Client](https://github.com/0x676e67/rquest) is built on top of it.

## Non-goals

This package implements only the TLS extensions specification and supports the original [boring](https://github.com/cloudflare/boring) library with the following features:

- Required TLS extensions for Safari and Firefox
- kDHE, ffdhe2048, and ffdhe3072 implementations
- RPK is not supported
- Support for LoongArch P64 and P32 architectures

## Documentation
 - Boring API: <https://docs.rs/boring2>
 - tokio TLS adapters: <https://docs.rs/tokio-boring2>
 - FFI bindings: <https://docs.rs/boring-sys2>

## Native Symbol Isolation

The optional `prefix-symbols` feature builds BoringSSL with a versioned C symbol
namespace so it can coexist with OpenSSL in one executable. It leaves the Rust
API and TLS implementation unchanged. The build discovers the native exports,
generates BoringSSL's prefix headers, rebuilds the archives, and rejects missing
or unprefixed exports before generating the Rust bindings.

This feature requires Go 1.19 or newer at build time. It supports the bundled
non-FIPS source, not precompiled archives or externally supplied source trees.
The Dockerfile in `ci/openssl-coexistence.Dockerfile` verifies the namespace and
TLS interoperability with vendored OpenSSL on Linux.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed under the terms of both the Apache License,
Version 2.0 and the MIT license without any additional terms or conditions.

## Accolades

The project is based on a fork of [boring](https://github.com/cloudflare/boring).
