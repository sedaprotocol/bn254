//! BLS aggregate signatures with bn256.
//!
//! This module has been designed with the goal of being compatible with the
//! bn256Add(G1), bn256ScalarMul(G1) and bn256Pairing provided by Ethereum.
//!
//! <b>BLS verification</b>: <em>e(H(m), PubKey) = e(Signature, G2::one)</em>
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
//!<b>BLS resources</b>: The following resources have been used as a reference
//! to implement BLS signatures:
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
//! of each individual has been proven (i.e., by signing a message)

use bn::{pairing_batch, Fr, Group, Gt, G1, G2};
use error::Bn254Error;

pub mod error;
pub mod keys;

mod hash;
mod utils;

pub use keys::{PrivateKey, PublicKey};

/// Multi signatures with curve bn254.
pub struct ECDSA;

impl ECDSA {
    // /// Function to derive public key (point in G2) given a secret key.
    // ///
    // /// # Arguments
    // ///
    // /// * `secret_key` - The secret key bytes
    // ///
    // /// # Returns
    // ///
    // /// * If successful, a vector of bytes with the public key
    // pub fn derive_public_key(&mut self, secret_key: &[u8]) -> Result<Vec<u8>,
    // Bn254Error> {     let scalar = Fr::from_slice(&secret_key[0..32])?;
    //     let key = PrivateKey(scalar);
    //     let public = PublicKey::from_private_key(key);

    //     public.to_compressed()
    // }

    /// Function to sign a message given a private key (as a point in G1).
    ///
    /// # Arguments
    ///
    /// * `message`     - The message bytes
    /// * `secret_key`  - The secret key bytes
    ///
    /// # Returns
    ///
    /// * If successful, a vector of bytes with the signature
    pub fn sign(&mut self, secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, Bn254Error> {
        // 1. Hash_to_try_and_increment --> H(m) as point in G1 (only if it exists)
        let hash_point = hash::hash_to_try_and_increment(&message)?;

        // 2. Multiply hash_point times secret_key --> Signature in G1
        let sk = Fr::from_slice(&secret_key)?;
        let signature = hash_point * sk;

        // 3. Return signature as compressed bytes
        utils::to_compressed_g1(signature)
    }

    /// Function to verify a signature (point in G1) given a public key (point
    /// in G2).
    ///
    /// # Arguments
    ///
    /// * `signature`   - The signature bytes
    /// * `message`     - The message to be signed
    /// * `public_key`  - The public key bytes
    ///
    /// # Returns
    ///
    /// * If successful, `Ok(())`; otherwise `Error`
    pub fn verify(&mut self, signature: &[u8], message: &[u8], public_key: &[u8]) -> Result<(), Bn254Error> {
        let mut vals = Vec::new();
        // First pairing input: e(H(m), PubKey)
        let hash_point = hash::hash_to_try_and_increment(&message)?;
        let public_key_point = G2::from_compressed(&public_key)?;
        vals.push((hash_point, public_key_point));
        // Second pairing input:  e(-Signature,G2::one())
        let signature_point = G1::from_compressed(&signature)?;
        vals.push((signature_point, -G2::one()));
        // Pairing batch with one negated point
        let mul = pairing_batch(&vals);
        if mul == Gt::one() {
            Ok(())
        } else {
            Err(Bn254Error::VerificationFailed)
        }
    }

    // /// Function to aggregate public keys (sum of points in G2).
    // ///
    // /// # Arguments
    // ///
    // /// * `public_keys`  - An array of public key bytes to be aggregated
    // ///
    // /// # Returns
    // ///
    // /// * If successful, a vector of bytes with the aggregated public key
    // pub fn aggregate_public_keys(&mut self, public_keys: &[&[u8]]) ->
    // Result<Vec<u8>, Bn254Error> {     let agg_public_key: Result<G2,
    // Bn254Error> = public_keys.iter().try_fold(G2::zero(), |acc, &compressed| {
    //         let public_key = PublicKey::from_compressed(&compressed)?;

    //         Ok(acc + public_key.0)
    //     });

    //     PublicKey(agg_public_key?).to_compressed()
    // }

    // /// Function to aggregate signatures (sum of points in G1).
    // ///
    // /// # Arguments
    // ///
    // /// * `signatures`  - An array of signature bytes to be aggregated
    // ///
    // /// # Returns
    // ///
    // /// * If successful, a vector of bytes with the aggregated signature
    // pub fn aggregate_signatures(&mut self, signatures: &[&[u8]]) ->
    // Result<Vec<u8>, Bn254Error> {     let agg_signatures: Result<G1,
    // Bn254Error> = signatures.iter().try_fold(G1::zero(), |acc, &compressed| {
    //         let signature = G1::from_compressed(&compressed)?;

    //         Ok(acc + signature)
    //     });

    //     utils::to_compressed_g1(agg_signatures?)
    // }
}

#[cfg(test)]
mod test {
    pub use keys::{PrivateKey, PublicKey};

    use super::*;

    /// Test for the `sign`` function with own test vector
    #[test]
    fn test_sign_1() {
        // Inputs: secret key and message "sample" in ASCII
        let secret_key = hex::decode("2009da7287c158b126123c113d1c85241b6e3294dd75c643588630a8bc0f934c").unwrap();
        let data = hex::decode("73616d706c65").unwrap();

        // Sign data with secret key
        let signature = ECDSA.sign(&secret_key, &data).unwrap();

        let expected_signature = "020f047a153e94b5f109e4013d1bd078112817cf0d58cdf6ba8891f9849852ba5b";

        assert_eq!(hex::encode(signature), expected_signature);
    }

    /// Test `verify` function with own signed message
    #[test]
    fn test_verify_signed_msg() {
        // Public key
        let secret_key = hex::decode("2009da7287c158b126123c113d1c85241b6e3294dd75c643588630a8bc0f934c").unwrap();
        let private_key = PrivateKey::try_from(secret_key.as_ref()).unwrap();
        let public_key = PublicKey::from_private_key(private_key);

        // Signature
        let signature = hex::decode("020f047a153e94b5f109e4013d1bd078112817cf0d58cdf6ba8891f9849852ba5b").unwrap();

        // Message signed
        let msg = hex::decode("73616d706c65").unwrap();

        // Verify signature
        assert!(
            ECDSA
                .verify(&signature, &msg, &public_key.to_compressed().unwrap())
                .is_ok(),
            "Verification failed"
        );
    }
}
