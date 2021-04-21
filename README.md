# Hexagon

Hexagon is a Command Line Tool written in Rust that can be used to perform symmetric and asymmetric encryption tasks.

Internally the library provides conveninet wrappers around [sodiumoxide](https://docs.rs/sodiumoxide/0.2.6/sodiumoxide/) and [openssl](https://docs.rs/openssl/0.10.33/openssl/) for managing the creation of public/private key-pairs as well as symmetric and asymmetric encryption and decryption.
Currently symmetric encryption is implemented by using [XSalsa20Poly1305](https://en.wikipedia.org/wiki/Authenticated_encryption) while [asymmetric encryption](https://en.wikipedia.org/wiki/Public-key_cryptography) is achived using [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)).
More implemtatinon can be added in the future by providing different implementations of the trait exported by the `cryto` module.

This project is an exploration of the main concepts behind cryptographic systems and the Rust programming langauge. As such it should not necessarily be seen as a correct and secure cryptographic tool.

## Status
[![Actions Status](https://github.com/ocramh/hexagon/workflows/Build%20and%20test/badge.svg)](https://github.com/ocramh/hexagon/actions)

In progress
- [x] XSalsa20Poly1305 based symmetric encryption and decryption
- [x] XSalsa20Poly1305 encryption and decryption unit testing
- [x] RSA encryption and decryption implementation
- [ ] RSA encryption and decryption implementation
- [x] RSA key public/private key generation
- [x] CLI interface definition
- [ ] CLI tasks implementation
- [ ] Write decryption output to file

## Dependencies
Rust v 1.36 or greater

## Usage
Build the project from the root directory with cargo
```
cargo build
```

Execute the compiled debug executable and see the available CLI commands
```
 ./target/debug/hexagon -h
```
