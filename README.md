# bls-signatures-rs

`bls-signatures-rs` is an open source implementation of [Bonneh-Lynn-Shacham (BLS) signatures](https://en.wikipedia.org/wiki/Boneh%E2%80%93Lynn%E2%80%93Shacham) written in Rust. At the moment this implementation only supports the BN256 pairing friendly.

_DISCLAIMER_: This is experimental software. Be careful!
# BN256
This module uses the [BN library](https://github.com/paritytech/bn) to perform elliptic curve operations over the appropriate fields. It provides the following functionalities on top of the bn256 library:

* `derive_public_key`: Derive a public key over the bn256 curve given a secret key.
* `sign`: Sign a message given a secret key.
* `verify`: Given a public key, a signature and a message it verifies whether the signature is valid.
* `aggregate_public_keys`: Aggregate a set of public keys into a single aggregated one.
* `aggregate_signatures`: Aggregate a set of signatures into a single aggregated one.

## Hashing to G1
The algorithm utilized to hash a given message into a point in G1 is try and increment. We discourage its usage in the cases of hashing secret messages since its running time leaks information about the input.
 In any other cases, where the message to be hashed is public, try and increment should be safe. The hashing algorithm utilized is `sha256`.

## Example

Sign, aggregate and verify by using the BN256 curve:

```rust
use bls_signatures_rs::MultiSignature;
use bls_signatures_rs::bn256::Bn256;

fn main() {
    // Inputs: Secret Key, Public Key (derived) & Message

    // Secret key one
    let secret_key_1 =
        hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();

    // Secret key two
    let secret_key_2 =
        hex::decode("a55e93edb1350916bf5beea1b13d8f198ef410033445bcb645b65be5432722f1").unwrap();

    // Derive public keys from secret key
    let public_key_1 = Bn256.derive_public_key(&secret_key_1).unwrap();
    let public_key_2 = Bn256.derive_public_key(&secret_key_2).unwrap();

    let message: &[u8] = b"sample";

    // Sign identical message with two different secret keys
    let sig_1 = Bn256.sign(&secret_key_1, &message).unwrap();
    let sig_2 = Bn256.sign(&secret_key_2, &message).unwrap();

    // Aggregate public keys
    let agg_pub_key = Bn256.aggregate_public_keys(&[&public_key_1, &public_key_2]).unwrap();

    // Aggregate signatures
    let agg_sig = Bn256.aggregate_signatures(&[&sig_1, &sig_2]).unwrap();

    // Check whether the aggregated signature corresponds to the aggregated public key
    let beta = Bn256.verify(&agg_sig, &message, &agg_pub_key).unwrap();
    println!("Successful verification");
}
```
## Adding unsupported curves
This library defines a MultiSignature trait which can be extended in order to use different curves and algorithms.

```rust
pub trait MultiSignature<PublicKey, SecretKey, Signature> {
    type Error;

    fn derive_public_key(&mut self, secret_key: SecretKey) -> Result<Vec<u8>, Self::Error>;

    fn sign(&mut self, secret_key: SecretKey, message: &[u8]) -> Result<Vec<u8>, Self::Error>;

    fn verify(
           &mut self,
           signature: Signature,
           message: &[u8],
           public_key: PublicKey,
     ) -> Result<(), Self::Error>;

    fn aggregate_public_keys(&mut self, public_key: &[PublicKey]) -> Result<Vec<u8>, Self::Error>;

    fn aggregate_signatures(&mut self, public_key: &[Signature]) -> Result<Vec<u8>, Self::Error>;
}
```
## License
`bls-signatures-rs` is published under the [MIT license](https://github.com/witnet/bls-signatures-rs/blob/master/LICENSE)