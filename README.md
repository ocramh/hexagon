# Hexagon

Hexagon is a Command Line Tool written in Rust that performs symmetric and asymmetric encryption.

Internally the library provides conveninet wrappers around [sodiumoxide](https://docs.rs/sodiumoxide/0.2.6/sodiumoxide/) and [openssl](https://docs.rs/openssl/0.10.33/openssl/) for managing the creation of public/private key-pairs as well as encrypting or decrypting content using secrets (In case of [AES encryption](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)) or public key (in case of [RSA encryption](https://en.wikipedia.org/wiki/RSA_(cryptosystem))).

This project is an exploration of the main concepts behind cryptographic systems and the Rust programming langauge. As such it should not necessarily be seen as a correct and secure cryptographic tool.

## Status
https://github.com/ocramh/hexagon/actions/workflows/rust.yaml/badge.svg

In prgress
- [x] AES encryption and decryption implementation
- [x] AES encryption and decryption unit testing
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
