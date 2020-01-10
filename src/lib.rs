//! This crate provides:
//!
//! - `MultiSignature` trait for specifying curves with multi signature support.
//! - `bn256` module implementing the aforementioned trait for the BLS curve bn256.

pub mod bn256;

/// The `MultiSignature` trait specifies an interface common for curves with multi signature support.
///
/// This trait requires to define the types for `PublicKey`, `SecretKey` and `Signature`.
pub trait MultiSignature<PublicKey, SecretKey, Signature> {
    type Error;

    /// Function to derive public key given a secret key.
    ///
    /// # Arguments
    ///
    /// * `secret_key` - The secret key to derive the public key
    ///
    /// # Returns
    ///
    /// * If successful, a vector of bytes with the public key
    fn derive_public_key(&mut self, secret_key: SecretKey) -> Result<Vec<u8>, Self::Error>;

    /// Function to sign a message given a private key.
    ///
    /// # Arguments
    ///
    /// * `message`     - The message to be signed
    /// * `secret_key`  - The secret key for signing
    ///
    /// # Returns
    ///
    /// * If successful, a vector of bytes with the signature
    fn sign(&mut self, secret_key: SecretKey, message: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// Function to verify a signature given a public key.
    ///
    /// # Arguments
    ///
    /// * `signature`   - The signature
    /// * `message`     - The message to be signed
    /// * `public_key`  - The public key to verify
    ///
    /// # Returns
    ///
    /// * If successful, `Ok(())`; otherwise `Error`
    fn verify(
        &mut self,
        signature: Signature,
        message: &[u8],
        public_key: PublicKey,
    ) -> Result<(), Self::Error>;

    /// Function to aggregate public keys in their corresponding group.
    ///
    /// # Arguments
    ///
    /// * `public_key`  - An array of public keys to be aggregated
    ///
    /// # Returns
    ///
    /// * If successful, a vector of bytes with the aggregated public key
    fn aggregate_public_keys(&mut self, public_keys: &[PublicKey]) -> Result<Vec<u8>, Self::Error>;

    /// Function to aggregate signatures in their corresponding group.
    ///
    /// # Arguments
    ///
    /// * `signatures`   - An array of signatures to be aggregated
    ///
    /// # Returns
    ///
    /// * If successful, a vector of bytes with the aggregated signature
    fn aggregate_signatures(&mut self, signatures: &[Signature]) -> Result<Vec<u8>, Self::Error>;
}
