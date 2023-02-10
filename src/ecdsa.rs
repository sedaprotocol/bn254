use bn::{pairing_batch, Group, Gt, G1, G2};

use crate::{
    error::{Error, Result},
    hash,
    PrivateKey,
    PublicKey,
    PublicKeyG1,
    Signature,
};

/// ECDSA with curve `bn254`.
pub struct ECDSA;

impl ECDSA {
    /// Function to sign a message given a private key (as a point in [G1]).
    ///
    /// # Arguments
    ///
    /// * `message`     - The message bytes
    /// * `private_key` - The private key
    ///
    /// # Returns
    ///
    /// * If successful, the signature as a [G1] point
    pub fn sign<T: AsRef<[u8]>>(message: T, private_key: &PrivateKey) -> Result<Signature> {
        // 1. Hash_to_try_and_increment --> H(m) as point in G1 (only if it exists)
        let hash_point = hash::hash_to_try_and_increment(message)?;

        // 2. Multiply hash_point times private_key --> Signature in G1
        let g1_point = hash_point * private_key.into();

        // 3. Return signature
        Ok(Signature(g1_point))
    }

    /// Function to verify a signature (point in [G1]) given a public key
    /// (point in [G2]).
    ///
    /// # Arguments
    ///
    /// * `message`     - The message to be signed
    /// * `signature`   - The signature
    /// * `public_key`  - The public key
    ///
    /// # Returns
    ///
    /// * If successful, `Ok(())`; otherwise [Error]
    pub fn verify<T: AsRef<[u8]>>(message: T, signature: &Signature, public_key: &PublicKey) -> Result<()> {
        // Pairing batch with one negated point
        let mut vals = Vec::new();
        // First pairing input: e(H(m), PubKey)
        let hash_point = hash::hash_to_try_and_increment(message)?;
        vals.push((hash_point, public_key.into()));
        // Second pairing input:  e(-Signature,G2::one())
        vals.push((signature.into(), -G2::one()));
        let mul = pairing_batch(&vals);

        if mul == Gt::one() {
            Ok(())
        } else {
            Err(Error::VerificationFailed)
        }
    }
}

/// Function to check if 2 Public Keys in [G1] and [G2] are valid
///
/// # Arguments
///
/// * `message`     - The message to be signed
/// * `signature`   - The signature
/// * `public_key`  - The public key
///
/// # Returns
///
/// * If successful, `Ok(())`; otherwise [Error]
pub fn check_public_keys(public_key_g2: &PublicKey, public_key_g1: &PublicKeyG1) -> Result<()> {
    // Pairing batch with one negated point
    let vals = vec![
        // First pairing input: e(H(m), PubKey)
        (G1::one(), public_key_g2.into()),
        // Second pairing input:  e(PubKey_G1, G2::one())
        (public_key_g1.into(), -G2::one()),
    ];
    let mul = pairing_batch(&vals);

    if mul == Gt::one() {
        Ok(())
    } else {
        Err(Error::VerificationFailed)
    }
}
