use std::ops::{Add, Neg, Sub};

use bn::{Fr, Group, G1, G2};

use crate::{error::Bn254Error, utils};

/// The Private Key as an element of `Fr`
pub struct PrivateKey(bn::Fr);

impl TryFrom<&[u8]> for PrivateKey {
    type Error = Bn254Error;

    fn try_from(private_key: &[u8]) -> Result<Self, Self::Error> {
        Ok(PrivateKey(Fr::from_slice(&private_key[0..32])?))
    }
}

impl Into<bn::Fr> for PrivateKey {
    fn into(self) -> bn::Fr {
        self.0
    }
}

impl Into<bn::Fr> for &PrivateKey {
    fn into(self) -> bn::Fr {
        self.0
    }
}

impl PrivateKey {
    /// Function to derive a private key.
    pub fn new(rng: &[u8]) -> Result<PrivateKey, Bn254Error> {
        // This function throws an error if the slice does not have a proper length.
        let private_key = Fr::from_slice(&rng)?;

        Ok(PrivateKey(private_key))
    }

    /// Function to obtain a private key in bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Bn254Error> {
        utils::fr_to_bytes(self.into())
    }
}

/// The Public Key as a point in G2
#[derive(Copy, Clone, Debug)]
pub struct PublicKey(pub bn::G2);

impl PublicKey {
    /// Function to derive the `bn254` public key from the private key.
    pub fn from_private_key(private_key: &PrivateKey) -> Self {
        PublicKey(G2::one() * private_key.into())
    }

    /// Function to create a `PublicKey` from bytes representing a G2 point in
    /// compressed format.
    pub fn from_compressed(bytes: &[u8]) -> Result<Self, Bn254Error> {
        Ok(PublicKey(G2::from_compressed(&bytes)?))
    }

    /// Function to create a `PublicKey` from bytes representing a G2 point in
    /// uncompressed format.
    pub fn from_uncompressed(bytes: &[u8]) -> Result<Self, Bn254Error> {
        Ok(PublicKey(utils::from_uncompressed_to_g2(bytes)?))
    }

    /// Function to serialize the `PublicKey` to vector of bytes in compressed
    /// format.
    pub fn to_compressed(&self) -> Result<Vec<u8>, Bn254Error> {
        utils::g2_to_compressed(self.into())
    }

    /// Function to serialize the `PublicKey` to vector of bytes in uncompressed
    /// format.
    pub fn to_uncompressed(&self) -> Result<Vec<u8>, Bn254Error> {
        utils::g2_to_uncompressed(self.into())
    }
}

impl Into<bn::G2> for PublicKey {
    fn into(self) -> bn::G2 {
        self.0
    }
}

impl Into<bn::G2> for &PublicKey {
    fn into(self) -> bn::G2 {
        self.0
    }
}

impl Add for PublicKey {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        Self(self.0.add(other.0))
    }
}

impl Sub for PublicKey {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        Self(self.0 - other.0)
    }
}

impl Neg for PublicKey {
    type Output = Self;

    fn neg(self) -> Self {
        Self(-self.0)
    }
}

// /// The Public Key as a point in G1
// pub struct PublicKeyG1(pub bn::G1);

// impl PublicKeyG1 {
//     /// Function to derive the `bn254` public key from the private key.
//     pub fn from_private_key(private_key: PrivateKey) -> Self {
//         PublicKeyG1(G1::one() * private_key.into())
//     }

//     pub fn to_compressed(&self) -> Result<Vec<u8>, Bn254Error> {
//         utils::g1_to_compressed(self.0)
//     }

//     pub fn from_compressed(bytes: &[u8]) -> Result<Self, Bn254Error> {
//         Ok(PublicKeyG1(G1::from_compressed(&bytes)?))
//     }
// }

/// The Signature as a point in G1
#[derive(Copy, Clone, Debug)]
pub struct Signature(pub bn::G1);

impl Signature {
    pub fn to_compressed(&self) -> Result<Vec<u8>, Bn254Error> {
        utils::g1_to_compressed(self.0)
    }

    pub fn from_compressed(bytes: &[u8]) -> Result<Self, Bn254Error> {
        let uncompressed = G1::from_compressed(&bytes)?;

        Ok(Signature(uncompressed))
    }
}

impl Into<bn::G1> for Signature {
    fn into(self) -> bn::G1 {
        self.0
    }
}

impl Into<bn::G1> for &Signature {
    fn into(self) -> bn::G1 {
        self.0
    }
}

impl Add for Signature {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        Self(self.0.add(other.0))
    }
}

impl Sub for Signature {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        Self(self.0 - other.0)
    }
}

impl Neg for Signature {
    type Output = Self;

    fn neg(self) -> Self {
        Self(-self.0)
    }
}
