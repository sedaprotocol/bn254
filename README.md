# bn254
[![](https://img.shields.io/crates/v/bn254.svg)](https://crates.io/crates/bn254) [![](https://docs.rs/bn254/badge.svg)](https://docs.rs/bn254)

`bn254` is an open source Rust implementation of aggregate signatures over the pairing friendly elliptic curve BN254 ([Barreto-Naehrig (BN)](https://www.cryptojedi.org/papers/pfcpo.pdf)).

The name `bn254` stands for the number of bits in the prime associated to the base field.
The bits of security of `bn254` dropped from 128 to around 100 after new algorithms of [Kim-Barbulescu](https://eprint.iacr.org/2015/1027.pdf).

This curve is also known as `bn256` or `bn128` (`alt-bn128`) referred to the bits of security.

_DISCLAIMER_: This is experimental software. Be careful!

## Usage

This module uses the [substrate-bn](https://github.com/paritytech/bn) library to perform elliptic curve operations over the appropriate fields. It provides the following functionalities:

* `sign`: Sign a message given a secret key.
* `verify`: Given a public key, a signature and a message it verifies whether the signature is valid.

Signature and public aggregation can be done directly by using the `+` operator.

## Hashing to G1

The algorithm utilized to hash a given message into a point in G1 is try and increment. We discourage its usage in the cases of hashing secret messages since its running time leaks information about the input.
 In any other cases, where the message to be hashed is public, try and increment should be safe. The hashing algorithm utilized is `sha256`.

## Example

Sign, aggregate and verify by using the BN256 curve:

```rust
use bn254::{PrivateKey, PublicKey, ECDSA};

fn main() {
    // Inputs: Secret Key, Public Key (derived) & Message

    // Secret key one
    let private_key_1_bytes = hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();
    let private_key_1 = PrivateKey::try_from(private_key_1_bytes.as_ref()).unwrap();

    // Secret key two
    let private_key_2_bytes = hex::decode("a55e93edb1350916bf5beea1b13d8f198ef410033445bcb645b65be5432722f1").unwrap();
    let private_key_2 = PrivateKey::try_from(private_key_2_bytes.as_ref()).unwrap();

    // Derive public keys from secret key
    let public_key_1 = PublicKey::from_private_key(&private_key_1);
    let public_key_2 = PublicKey::from_private_key(&private_key_2);

    let message: &[u8] = b"sample";

    // Sign identical message with two different secret keys
    let signature_1 = ECDSA::sign(&message, &private_key_1).unwrap();
    let signature_2 = ECDSA::sign(&message, &private_key_2).unwrap();

    // Aggregate public keys
    let aggregate_pub_key = public_key_1 + public_key_2;

    // Aggregate signatures
    let aggregate_sig = signature_1 + signature_2;

    // Check whether the aggregate signature corresponds to the aggregated
    // public_key
    ECDSA::verify(&message, &aggregate_sig, &aggregate_pub_key).unwrap();
    println!("Successful aggregate signature verification");
}
```

## License

`bn254` is published under the [MIT license](https://github.com/sedaprotocol/bn254/blob/main/LICENSE.md)