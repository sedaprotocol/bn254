//! TODO: Document BLS aggregate signatures with curve bn128 (for Ethereum)
//! TODO: why &mut self -> crypto libs often require mutable contexts

mod bn128;

pub trait BLS<PublicKey, SecretKey, Signature> {
    type Error;

    /// TODO: derive public key from private key
    fn derive_public_key(&mut self, secret_key: SecretKey) -> Result<PublicKey, Self::Error>;

    /// TODO: sign using BLS curve
    fn sign(&mut self, secret_key: SecretKey, msg: &[u8]) -> Result<Signature, Self::Error>;

    /// TODO: verify using BLS curve
    fn verify(&mut self, public_key: PublicKey, signature: Signature, msg: &[u8]) -> Result<bool, Self::Error>;

    /// TODO:
    fn aggregate_public_keys(&mut self, public_key: &[PublicKey]) -> Result<PublicKey, Self::Error>;

    /// TODO:
    fn aggregate_signatures(&mut self, public_key: &[Signature]) -> Result<Signature, Self::Error>;
}
