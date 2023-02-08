use std::ops::Add;

use bn::{arith, AffineG2, Fq, Fq2, Fr, Group, G1, G2};
use byteorder::{BigEndian, ByteOrder};

use crate::{error::Bn254Error, utils};

/// The scalar used as private key
pub struct PrivateKey(bn::Fr);

impl TryFrom<&[u8]> for PrivateKey {
    type Error = Bn254Error;

    fn try_from(secret_key: &[u8]) -> Result<Self, Self::Error> {
        Ok(PrivateKey(Fr::from_slice(&secret_key[0..32])?))
    }
}

impl Into<bn::Fr> for PrivateKey {
    fn into(self) -> bn::Fr {
        self.0
    }
}

/// The public key as point in G2
#[derive(Copy, Clone, Debug)]
pub struct PublicKey(pub bn::G2);

impl Add for PublicKey {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        PublicKey(self.0.add(other.0))
    }
}

/// The public key as point in G1
pub struct PublicKeyG1(pub bn::G1);

impl PublicKey {
    /// Function to derive the bn256 public key from the private key.
    pub fn from_private_key(private_key: PrivateKey) -> Self {
        PublicKey(G2::one() * private_key.into())
    }
}

impl PublicKeyG1 {
    /// Function to derive the bn256 public key from the private key.
    pub fn from_private_key(private_key: PrivateKey) -> Self {
        PublicKeyG1(G1::one() * private_key.into())
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
        let mut result: [u8; 32] = [0; 32];
        // to_big_endian from bn::Fr does not work here.
        self.0.into_u256().to_big_endian(&mut result)?;

        Ok(result.to_vec())
    }
}

impl PublicKey {
    /// Function to create a `PublicKey` from bytes representing a G2 point in
    /// compressed format.
    pub fn from_compressed(bytes: &[u8]) -> Result<Self, Bn254Error> {
        let uncompressed = G2::from_compressed(&bytes)?;

        Ok(PublicKey(uncompressed))
    }

    /// Function to create a `PublicKey` from bytes representing a G2 point in
    /// uncompressed format.
    pub fn from_uncompressed(bytes: &[u8]) -> Result<Self, Bn254Error> {
        if bytes.len() != 128 {
            return Err(Bn254Error::InvalidLength {});
        }
        let x = Fq2::new(Fq::from_slice(&bytes[0..32])?, Fq::from_slice(&bytes[32..64])?);
        let y = Fq2::new(Fq::from_slice(&bytes[64..96])?, Fq::from_slice(&bytes[96..128])?);
        let pub_key = AffineG2::new(x, y)?;

        Ok(PublicKey(pub_key.into()))
    }

    /// Function to serialize the `PublicKey` to vector of bytes in compressed
    /// format.
    pub fn to_compressed(&self) -> Result<Vec<u8>, Bn254Error> {
        let modulus = Fq::modulus();
        // From Jacobian to Affine first!
        let affine_coords = AffineG2::from_jacobian(self.0).ok_or(Bn254Error::PointInJacobian)?;

        // Get X real coordinate
        let x_real = Fq::into_u256(affine_coords.x().real());
        // Get X imaginary coordinate
        let x_imaginary = Fq::into_u256(affine_coords.x().imaginary());
        // Get Y and get sign
        let y = affine_coords.y();
        let y_neg = -y;
        let sign: u8 = if utils::to_u512(y) > utils::to_u512(y_neg) {
            0x0b
        } else {
            0x0a
        };

        // To U512 and its compressed representation
        let compressed = arith::U512::new(&x_imaginary, &x_real, &modulus);
        // To slice
        let mut buf: [u8; 64] = [0; (4 * 16)];
        for (l, i) in (0..4).rev().zip((0..4).map(|i| i * 16)) {
            BigEndian::write_u128(&mut buf[i..], compressed.0[l]);
        }

        // Result = sign || compressed
        let mut result: Vec<u8> = Vec::new();
        result.push(sign);
        result.append(&mut buf.to_vec());

        Ok(result)
    }

    /// Function to serialize the `PublicKey` to vector of bytes in uncompressed
    /// format.
    pub fn to_uncompressed(&self) -> Result<Vec<u8>, Bn254Error> {
        // From Jacobian to Affine first!
        let affine_coords = AffineG2::from_jacobian(self.0).ok_or(Bn254Error::PointInJacobian)?;
        let mut result: [u8; 32 * 4] = [0; (4 * 32)];

        // Get X real coordinate
        Fq::into_u256(affine_coords.x().real()).to_big_endian(&mut result[0..32])?;

        // Get X imaginary coordinate
        Fq::into_u256(affine_coords.x().imaginary()).to_big_endian(&mut result[32..64])?;

        // Get Y real coordinate
        Fq::into_u256(affine_coords.y().real()).to_big_endian(&mut result[64..96])?;

        // Get Y imaginary coordinate
        Fq::into_u256(affine_coords.y().imaginary()).to_big_endian(&mut result[96..128])?;

        Ok(result.to_vec())
    }
}

// Test vectors taken from https://asecuritysite.com/encryption/go_bn256. The public keys in G2 are changed in order in the website, i.e., imaginary goes first.
// In order to construct the test vectors we need to do the following
// Get the modulus of Fq
// Get the components (real, imaginary) of x and y
// perform (imaginary*modulus) +  real
// Compress with 0x0a or 0x0b depending on the value of y

#[test]
fn test_valid_private_key() {
    let compressed = hex::decode("023aed31b5a9e486366ea9988b05dba469c6206e58361d9c065bbea7d928204a").unwrap();
    let private_key = PrivateKey::new(&compressed.as_slice());
    assert_eq!(private_key.is_err(), false);
    assert_eq!(private_key.unwrap().to_bytes().unwrap(), compressed);
}

#[test]
fn test_invalid_private_key_1() {
    let compressed = hex::decode(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .unwrap();
    let private_key = PrivateKey::new(&compressed.as_slice());
    assert_eq!(private_key.is_err(), true);
}

#[test]
fn test_invalid_private_key_2() {
    let compressed = hex::decode("aaaa").unwrap();
    let private_key = PrivateKey::new(&compressed.as_slice());
    assert_eq!(private_key.is_err(), true);
}

#[test]
fn test_compressed_public_key_1() {
    let compressed = hex::decode("0a023aed31b5a9e486366ea9988b05dba469c6206e58361d9c065bbea7d928204a761efc6e4fa08ed227650134b52c7f7dd0463963e8a4bf21f4899fe5da7f984a").unwrap();
    let public_key = PublicKey::from_compressed(&compressed).unwrap();
    let compressed_again = public_key.to_compressed().unwrap();
    assert_eq!(compressed, compressed_again);
}

#[test]
fn test_uncompressed_public_key() {
    let uncompressed = hex::decode(
        "28fe26becbdc0384aa67bf734d08ec78ecc2330f0aa02ad9da00f56c37907f78\
             2cd080d897822a95a0fb103c54f06e9bf445f82f10fe37efce69ecb59514abc8\
             237faeb0351a693a45d5d54aa9759f52a71d76edae2132616d6085a9b2228bf9\
             0f46bd1ef47552c3089604c65a3e7154e3976410be01149b60d5a41a6053e6c2",
    )
    .unwrap();
    let public_key = PublicKey::from_uncompressed(&uncompressed).unwrap();

    let uncompressed_again = public_key.to_uncompressed().unwrap();
    assert_eq!(uncompressed_again, uncompressed);
}

#[test]
fn test_to_public_key_1() {
    let secret_key = hex::decode("1ab1126ff2e37c6e6eddea943ccb3a48f83b380b856424ee552e113595525565").unwrap();
    let expected = hex::decode(
        "28fe26becbdc0384aa67bf734d08ec78ecc2330f0aa02ad9da00f56c37907f78\
             2cd080d897822a95a0fb103c54f06e9bf445f82f10fe37efce69ecb59514abc8\
             237faeb0351a693a45d5d54aa9759f52a71d76edae2132616d6085a9b2228bf9\
             0f46bd1ef47552c3089604c65a3e7154e3976410be01149b60d5a41a6053e6c2",
    )
    .unwrap();
    let expected_public_key = PublicKey::from_uncompressed(&expected).unwrap();

    let private_key = PrivateKey::try_from(secret_key.as_ref()).unwrap();
    let public_key = PublicKey::from_private_key(private_key);
    assert_eq!(public_key.0, expected_public_key.0);
}

#[test]
fn test_to_public_key_2() {
    let secret_key = hex::decode("2009da7287c158b126123c113d1c85241b6e3294dd75c643588630a8bc0f934c").unwrap();
    let expected = hex::decode(
        "1cd5df38ed2f184b9830bfd3c2175d53c1455352307ead8cbd7c6201202f4aa8\
             02ce1c4241143cc61d82589c9439c6dd60f81fa6f029625d58bc0f2e25e4ce89\
             0ba19ae3b5a298b398b3b9d410c7e48c4c8c63a1d6b95b098289fbe1503d00fb\
             2ec596e93402de0abc73ce741f37ed4984a0b59c96e20df8c9ea1c4e6ec04556",
    )
    .unwrap();

    let expected_public_key = PublicKey::from_uncompressed(&expected).unwrap();

    let private_key = PrivateKey::try_from(secret_key.as_ref()).unwrap();
    let public_key = PublicKey::from_private_key(private_key);
    assert_eq!(public_key.0, expected_public_key.0);
}

#[test]
fn test_to_public_key_3() {
    let secret_key = hex::decode("26fb4d661491b0a623637a2c611e34b6641cdea1743bee94c17b67e5ef14a550").unwrap();
    let expected = hex::decode(
        "077dfcf14e940b69bf88fa1ad99b6c7e1a1d6d2cb8813ac53383bf505a17f8ff\
             2d1a9b04a2c5674373353b5a25591292e69c37c0b84d9ef1c780a57bb98638e6\
             2dc52f109b333c4125bccf55bc3a839ce57676514405656c79e577e231519273\
             2410eee842807d9325f22d087fa6bc79d9bbea07f5fa8c345e1e57b28ad54f84",
    )
    .unwrap();

    let expected_public_key = PublicKey::from_uncompressed(&expected).unwrap();

    let private_key = PrivateKey::try_from(secret_key.as_ref()).unwrap();
    let public_key = PublicKey::from_private_key(private_key);
    assert_eq!(public_key.0, expected_public_key.0);
}

#[test]
fn test_to_public_key_4() {
    let secret_key = hex::decode("0f6b8785374476a3b3e4bde2c64dfb12964c81c7930d32367c8e318609387872").unwrap();
    let expected = hex::decode(
        "270567a05b56b02e813281d554f46ce0c1b742b622652ef5a41d69afb6eb8338\
             1bab5671c5107de67fe06007dde240a84674c8ff13eeac6d64bad0caf2cfe53e\
             0142f4e04fc1402e17ae7e624fd9bd15f1eae0a1d8eda4e26ab70fd4cd793338\
             02b54a5deaaf86dc7f03d080c8373d62f03b3be06dac42b2d9426a8ebd0caf4a",
    )
    .unwrap();

    let expected_public_key = PublicKey::from_uncompressed(&expected).unwrap();

    let private_key = PrivateKey::try_from(secret_key.as_ref()).unwrap();
    let public_key = PublicKey::from_private_key(private_key);
    assert_eq!(public_key.0, expected_public_key.0);
}

/// Test `aggregate_public_keys`
#[test]
fn test_aggregate_public_keys_1() {
    // Public keys
    let public_key_1 = PublicKey(G2::one());
    let public_key_2 = PublicKey(G2::one());

    // Aggregation
    let agg_public_key = public_key_1 + public_key_2;

    // Check
    let expected = hex::decode("0b061848379c6bccd9e821e63ff6932738835b78e1e10079a0866073eba5b8bb444afbb053d16542e2b839477434966e5a9099093b6b3351f84ac19fe28f096548").unwrap();
    assert_eq!(agg_public_key.to_compressed().unwrap(), expected);
}
