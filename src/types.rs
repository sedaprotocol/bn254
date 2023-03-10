use std::ops::{Add, Neg, Sub};

use bn::{Fr, Group, G1, G2};
use rand::Rng;

use crate::{
    error::{Error, Result},
    utils,
};

/// The Private Key as an element of [Fr]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateKey(pub Fr);

impl PrivateKey {
    /// Function to create a random [PrivateKey].
    pub fn random<R>(rng: &mut R) -> Self
    where
        R: Rng,
    {
        // This function throws an error if the slice does not have a proper length.
        let private_key = Fr::random(rng);

        Self(private_key)
    }

    /// Function to obtain a private key in bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        utils::fr_to_bytes(self.into())
    }
}

impl TryFrom<&[u8]> for PrivateKey {
    type Error = Error;

    fn try_from(private_key: &[u8]) -> Result<Self, Self::Error> {
        Ok(PrivateKey(Fr::from_slice(private_key)?))
    }
}

impl TryFrom<&str> for PrivateKey {
    type Error = Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        let bytes = hex::decode(value)?;
        Self::try_from(bytes.as_slice())
    }
}

impl TryFrom<String> for PrivateKey {
    type Error = Error;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl From<PrivateKey> for Fr {
    fn from(private_key: PrivateKey) -> Self {
        private_key.0
    }
}

impl From<&PrivateKey> for Fr {
    fn from(private_key: &PrivateKey) -> Self {
        private_key.0
    }
}

/// The Public Key as a point in [G2]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(pub G2);

impl PublicKey {
    /// Function to derive the `bn254` public key from the [PrivateKey].
    pub fn from_private_key(private_key: &PrivateKey) -> Self {
        Self(G2::one() * private_key.into())
    }

    /// Function to create a [PublicKey] from bytes representing a [G2] point in
    /// compressed format.
    pub fn from_compressed<T: AsRef<[u8]>>(bytes: T) -> Result<Self> {
        Ok(Self(G2::from_compressed(bytes.as_ref())?))
    }

    /// Function to create a [PublicKey] from bytes representing a [G2] point in
    /// uncompressed format.
    pub fn from_uncompressed<T: AsRef<[u8]>>(bytes: T) -> Result<Self> {
        Ok(Self(utils::from_uncompressed_to_g2(bytes.as_ref())?))
    }

    /// Function to serialize the [PublicKey] to vector of bytes in compressed
    /// format.
    pub fn to_compressed(&self) -> Result<Vec<u8>> {
        utils::g2_to_compressed(self.into())
    }

    /// Function to serialize the [PublicKey] to vector of bytes in uncompressed
    /// format.
    pub fn to_uncompressed(&self) -> Result<Vec<u8>> {
        utils::g2_to_uncompressed(self.into())
    }
}

impl From<PublicKey> for G2 {
    fn from(public_key: PublicKey) -> Self {
        public_key.0
    }
}

impl From<&PublicKey> for G2 {
    fn from(public_key: &PublicKey) -> Self {
        public_key.0
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

/// The Public Key as a point in [G1]
pub struct PublicKeyG1(pub G1);

impl PublicKeyG1 {
    /// Function to derive the `bn254` public key from the [PrivateKey].
    pub fn from_private_key(private_key: &PrivateKey) -> Self {
        Self(G1::one() * private_key.into())
    }

    /// Function to serialize the [PublicKeyG1] to vector of bytes in compressed
    /// format.
    pub fn to_compressed(&self) -> Result<Vec<u8>> {
        utils::g1_to_compressed(self.0)
    }

    /// Function to create a [PublicKeyG1] from bytes representing a [G1] point
    /// in compressed format.
    pub fn from_compressed<T: AsRef<[u8]>>(bytes: T) -> Result<Self> {
        Ok(Self(G1::from_compressed(bytes.as_ref())?))
    }

    /// Function to create a [Signature] from bytes representing a [G1] point in
    /// uncompressed format.
    pub fn from_uncompressed<T: AsRef<[u8]>>(bytes: T) -> Result<Self> {
        Ok(Self(utils::from_uncompressed_to_g1(bytes.as_ref())?))
    }

    /// Function to serialize the [Signature] to vector of bytes in uncompressed
    /// format.
    pub fn to_uncompressed(&self) -> Result<Vec<u8>> {
        utils::g1_to_uncompressed(self.into())
    }
}

impl From<PublicKeyG1> for G1 {
    fn from(public_key: PublicKeyG1) -> Self {
        public_key.0
    }
}

impl From<&PublicKeyG1> for G1 {
    fn from(public_key: &PublicKeyG1) -> Self {
        public_key.0
    }
}

impl Add for PublicKeyG1 {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        Self(self.0.add(other.0))
    }
}

impl Sub for PublicKeyG1 {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        Self(self.0 - other.0)
    }
}

impl Neg for PublicKeyG1 {
    type Output = Self;

    fn neg(self) -> Self {
        Self(-self.0)
    }
}

/// The Signature as a point in [G1]
#[derive(Copy, Clone, Debug)]
pub struct Signature(pub G1);

impl Signature {
    /// Function to serialize the [Signature] to vector of bytes in compressed
    /// format.
    pub fn to_compressed(&self) -> Result<Vec<u8>> {
        utils::g1_to_compressed(self.0)
    }

    /// Function to create a [Signature] from bytes representing a [G1] point in
    /// compressed format.
    pub fn from_compressed<T: AsRef<[u8]>>(bytes: T) -> Result<Self> {
        let uncompressed = G1::from_compressed(bytes.as_ref())?;

        Ok(Self(uncompressed))
    }

    /// Function to create a [Signature] from bytes representing a [G1] point in
    /// uncompressed format.
    pub fn from_uncompressed<T: AsRef<[u8]>>(bytes: T) -> Result<Self> {
        Ok(Self(utils::from_uncompressed_to_g1(bytes.as_ref())?))
    }

    /// Function to serialize the [Signature] to vector of bytes in uncompressed
    /// format.
    pub fn to_uncompressed(&self) -> Result<Vec<u8>> {
        utils::g1_to_uncompressed(self.into())
    }
}

impl From<Signature> for G1 {
    fn from(signature: Signature) -> Self {
        signature.0
    }
}

impl From<&Signature> for G1 {
    fn from(signature: &Signature) -> Self {
        signature.0
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
