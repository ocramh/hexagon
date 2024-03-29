# Hexagon

Hexagon is a Command Line Tool written in Rust for managing cryptographic tasks.

The hexagon toolkit provides convenient wrappers around [sodiumoxide](https://docs.rs/sodiumoxide/0.2.6/sodiumoxide/) and [openssl](https://docs.rs/openssl/0.10.33/openssl/) for managing the creation of public/private key-pairs as well as symmetric and asymmetric encryption and decryption.
Symmetric encryption is implemented using [XSalsa20Poly1305](https://en.wikipedia.org/wiki/Authenticated_encryption) while [asymmetric encryption](https://en.wikipedia.org/wiki/Public-key_cryptography) is achieved using [RSA](<https://en.wikipedia.org/wiki/RSA_(cryptosystem)>).
Alternative cryptographic strategies can be added in the future by providing different implementations of the trait exported by the `crypto` module.

This project explores cryptographic systems and the Rust programming language and as such it should not necessarily be seen as a secure cryptographic tool.

## Status

[![Actions Status](https://github.com/ocramh/hexagon/workflows/Build%20and%20test/badge.svg)](https://github.com/ocramh/hexagon/actions)

In progress

- [x] XSalsa20Poly1305 based symmetric encryption and decryption
- [x] RSA encryption and decryption implementation
- [x] RSA key public/private key generation
- [ ] Elliptic-curve key public/private key generation
- [ ] Elliptic-curve encryption and decryption implementation
- [x] command-line interface
- [ ] Output encryption/decryption to file

## Dependencies

- Rust v 1.36 or greater.
- OpenSSL libraries and headers

## Usage

Build the project from the root directory with cargo to generate an executable in the /target/release' folder.

```shell
cargo build --release
```

Once compiled the executable exposes the following command-line tools

```shell
 ./target/release/hexagon -h

USAGE:
    hexagon <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    decrypt    decrypt ciphertext
    encrypt    encrypt plaintext
    help       Prints this message or the help of the given subcommand(s)
    keygen     generates public/private key pair
```
