[![pipeline status](https://gitlab.com/solidninja/pinentry-rs/badges/main/pipeline.svg)](https://gitlab.com/solidninja/pinentry-rs/commits/main)
[![crates.io Status](https://img.shields.io/crates/v/pinentry-rs.svg)](https://crates.io/crates/pinentry-rs)
[![docs.rs build](https://docs.rs/pinentry-rs/badge.svg)](https://docs.rs/crate/pinentry-rs/)

# pinentry-rs - Rust library to invoke `pinentry`

A tiny Rust library to invoke the password prompt program [`pinentry`](https://www.gnupg.org/related_software/pinentry/index.en.html)

## Example

```rust
extern crate pinentry_rs;
use pinentry_rs::pinentry;

let pw = pinentry().pin("Please enter password:".to_string());
```

This library uses [secstr](https://crates.io/crates/secstr) crate to protect the password in memory.

__No memory analysis has been done on how much the password leaks before getting into the `SecStr` - use at your own risk!__

## Contributing

`pinentry-rs` is the work of its contributors and is a free software project licensed under the
LGPLv3 or later.

If you would like to contribute, please follow the [C4](https://rfc.zeromq.org/spec:42/C4/) process.
