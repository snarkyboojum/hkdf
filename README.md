## Overview 

This library implements an HMAC based key derivation function (HKDF) written in Rust. It can be used to derive cryptographically strong pseudorandom keys, and support protocols like TLS (where a shared secret is used to derive a shared key between a client and server).

### Resources

- [HMAC-based Extract-and-Expand Key Derivation Function (HKDF)](https://tools.ietf.org/html/rfc5869)
- [HMAC: Keyed-Hashing for Message Authentication](https://www.ietf.org/rfc/rfc2104.txt)
- [Cryptographic Extraction and Key Derivation: The HKDF Scheme](https://eprint.iacr.org/2010/264.pdf) aka "HKDF-paper"