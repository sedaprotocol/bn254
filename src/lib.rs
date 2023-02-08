//! Elliptic Curve Digital Signature Algorithm (ECDSA) using the `bn254` curve,
//! also known as `bn128` or `bn256`.
//!
//! This module has been designed with the goal of being compatible with the
//! bn256Add(G1), bn256ScalarMul(G1) and bn256Pairing provided by precompiled
//! contracts on the Ethereum Virtual Machine (EVM).
//!
//! <b>Signature verification</b>: <em>e(H(m), PubKey) = e(Signature,
//! G2::one)</em>
//!
//! This module handles public keys in G2 in order to avoid performing the
//! hashing to G2, which involves a costly multiplication with the cofactor.
//!
//!<b>Test vectors</b>: the following resources have been used for testing
//! BN256 functionalities
//! - test vectors from <a href="https://github.com/ethereum/go-ethereum/blob/7b189d6f1f7eedf46c6607901af291855b81112b/core/vm/contracts_test.go">Ethereum</a>
//! - test vectors from <a href="https://asecuritysite.com/encryption/bn">Asecurity</a>
//!
//! <b>Hashing to G1</b>: In order to hash a specific message to G1 this module
//! uses the try and increment algorithm. The running time of this algorithm is
//! dependant on the input message, so it should be used only with public
//! inputs. Alternatively different hashing methods can be implemented as
//! specified in:
//! - <a href="https://tools.ietf.org/html/draft-irtf-cfrg-hash-to--04#page-37">hash_to_ algorithms</a>
//!
//!<b>Resources</b>: The following resources have been used as a reference
//! to implement aggregate signatures:
//!
//! - <a href="https://github.com/cfrg/draft-irtf-cfrg-bls-signature/blob/master/draft-irtf-cfrg-bls-signature-00.txt">BLS IRTF draft</a>
//! - <a href="https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html">
//!   BLSmultisig</a>
//! - <a href="https://medium.com/cryptoadvance/bls-signatures-better-than-schnorr-5a7fe30ea716">bls-signatures-better-than-schnorr</a>
//!
//! # Disclaimer
//!
//! This module does not implement a defense against Rogue-key attacks, which
//! means it should be used in protocols where the possession of the private key
//! of each individual has been proven (i.e., by signing a message).

use bn::{pairing_batch, Group, Gt, G2};
use error::Bn254Error;

pub mod error;
pub mod types;

#[cfg(test)]
mod types_test;

mod hash;
mod utils;

pub use types::{PrivateKey, PublicKey, Signature};

/// Multi signatures with curve `bn254`.
pub struct ECDSA;

impl ECDSA {
    /// Function to sign a message given a private key (as a point in G1).
    ///
    /// # Arguments
    ///
    /// * `message` ß    - The message bytes
    /// * `private_key` - The private key
    ///
    /// # Returns
    ///
    /// * If successful, the signature as a G1 point
    pub fn sign(message: &[u8], private_key: &PrivateKey) -> Result<Signature, Bn254Error> {
        // 1. Hash_to_try_and_increment --> H(m) as point in G1 (only if it exists)
        let hash_point = hash::hash_to_try_and_increment(&message)?;

        // 2. Multiply hash_point times private_key --> Signature in G1
        let g1_point = hash_point * private_key.into();

        // 3. Return signature
        Ok(Signature(g1_point))
    }

    /// Function to verify a signature (point in G1) given a public key (point
    /// in G2).
    ///
    /// # Arguments
    ///
    /// * `message`     - The message to be signed
    /// * `signature`   - The signature
    /// * `public_key`  - The public key
    ///
    /// # Returns
    ///
    /// * If successful, `Ok(())`; otherwise `Error`
    pub fn verify(message: &[u8], signature: &Signature, public_key: &PublicKey) -> Result<(), Bn254Error> {
        let mut vals = Vec::new();
        // First pairing input: e(H(m), PubKey)
        let hash_point = hash::hash_to_try_and_increment(&message)?;
        vals.push((hash_point, public_key.into()));
        // Second pairing input:  e(-Signature,G2::one())
        vals.push((signature.into(), -G2::one()));
        // Pairing batch with one negated point
        let mul = pairing_batch(&vals);
        if mul == Gt::one() {
            Ok(())
        } else {
            Err(Bn254Error::VerificationFailed)
        }
    }
}

#[cfg(test)]
mod test {
    pub use types::{PrivateKey, PublicKey};

    use super::*;

    /// Test for the `sign`` function with own test vector
    #[test]
    fn test_sign_1() {
        // Inputs: private key and message "sample" in ASCII
        let private_key = hex::decode("2009da7287c158b126123c113d1c85241b6e3294dd75c643588630a8bc0f934c").unwrap();
        let data = hex::decode("73616d706c65").unwrap();

        let private_key = PrivateKey::try_from(private_key.as_ref()).unwrap();

        // Sign data with private key
        let signature = ECDSA::sign(&data, &private_key).unwrap();

        let expected_signature = "020f047a153e94b5f109e4013d1bd078112817cf0d58cdf6ba8891f9849852ba5b";
        assert_eq!(hex::encode(signature.to_compressed().unwrap()), expected_signature);
    }

    /// Test `verify` function with own signed message
    #[test]
    fn test_verify_signed_msg() {
        // Public key
        let private_key = hex::decode("2009da7287c158b126123c113d1c85241b6e3294dd75c643588630a8bc0f934c").unwrap();
        let private_key = PrivateKey::try_from(private_key.as_ref()).unwrap();
        let public_key = PublicKey::from_private_key(&private_key);

        // Signature
        let signature_vec = hex::decode("020f047a153e94b5f109e4013d1bd078112817cf0d58cdf6ba8891f9849852ba5b").unwrap();
        let signature = Signature::from_compressed(&signature_vec).unwrap();

        // Message signed
        let msg = hex::decode("73616d706c65").unwrap();

        // Verify signature
        assert!(
            ECDSA::verify(&msg, &signature, &public_key).is_ok(),
            "Verification failed"
        );
    }
}
