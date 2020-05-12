//! BLS aggregate signatures with bn256.
//!
//! This module has been designed with the goal of being compatible with the bn256Add(G1), bn256ScalarMul(G1) and bn256Pairing provided by Ethereum.
//!
//! <b>BLS verification</b>: <em>e(H(m), PubKey) = e(Signature, G2::one)</em>
//!
//! This module handles public keys in G2 in order to avoid performing the hashing to G2, which involves a costly multiplication with the cofactor.
//!
//!<b>Test vectors</b>: the following resources have been used for testing BN256 functionalities
//! - test vectors from <a href="https://github.com/ethereum/go-ethereum/blob/7b189d6f1f7eedf46c6607901af291855b81112b/core/vm/contracts_test.go">Ethereum</a>
//! - test vectors from <a href="https://asecuritysite.com/encryption/bn">Asecurity</a>
//!
//! <b>Hashing to G1</b>: In order to hash a specific message to G1 this module uses the try and increment algorithm. The running time of this algorithm is dependant on the input message, so it should be used only with public inputs. Alternatively different hashing methods can be implemented as specified in:
//! - <a href="https://tools.ietf.org/html/draft-irtf-cfrg-hash-to--04#page-37">hash_to_ algorithms</a>
//!
//!<b>BLS resources</b>: The following resources have been used as a reference to implement BLS signatures:
//!
//! - <a href="https://github.com/cfrg/draft-irtf-cfrg-bls-signature/blob/master/draft-irtf-cfrg-bls-signature-00.txt">BLS IRTF draft</a>
//! - <a href="https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html"> BLSmultisig</a>
//! - <a href="https://medium.com/cryptoadvance/bls-signatures-better-than-schnorr-5a7fe30ea716">bls-signatures-better-than-schnorr</a>
//!
//! # Disclaimer
//!
//! This module does not implement a defense against Rogue-key attacks, which means it should be used in protocols where the possession of the private key of each individual has been proven (i.e., by signing a message)
//!
use crate::MultiSignature;

/// This is 0xf1f5883e65f820d099915c908786b9d3f58714d70a38f4c22ca2bc723a70f263, the last mulitple of the modulus before 2^256
const LAST_MULTIPLE_OF_FQ_MODULUS_LOWER_THAN_2_256: arith::U256 = arith::U256([
    0xf587_14d7_0a38_f4c2_2ca2_bc72_3a70_f263,
    0xf1f5_883e_65f8_20d0_9991_5c90_8786_b9d3,
]);

use bn::{arith, pairing_batch, AffineG1, AffineG2, Fq, Fq2, Fr, Group, Gt, G1, G2};
use byteorder::{BigEndian, ByteOrder};
use digest::Digest;

pub mod error;
use error::Error;

/// BLS multi signatures with curve bn256.
pub struct Bn256;

/// Function to calculate the modulus of a U256.
///
/// # Arguments
///
/// * `num` - the number we want to reduce.
/// * `modulus` - the modulus we want to apply.
///
/// # Returns
///
/// * If successful, a `U256` representing num % modulus.
fn mod_u256(num: arith::U256, modulus: arith::U256) -> arith::U256 {
    let mut reduced = num;
    // the library does not provide a function to do a modulo reduction
    // we use the provided add function adding a 0
    // we also need to iterate here as the library does the modulus only once
    while reduced > modulus {
        reduced.add(&arith::U256::zero(), &modulus);
    }

    reduced
}

impl Bn256 {
    /// Function to convert an arbitrary string to a point in the curve G1.
    ///
    /// # Arguments
    ///
    /// * `data` - A slice representing the data to be converted to a G1 point.
    ///
    /// # Returns
    ///
    /// * If successful, a `G1` representing the converted point.
    fn arbitrary_string_to_g1(&self, data: &[u8]) -> Result<G1, Error> {
        let mut v = vec![0x02];
        v.extend(data);

        let point = G1::from_compressed(&v)?;

        Ok(point)
    }

    /// Function to convert a `Hash(DATA|COUNTER)` to a point in the curve.
    /// Similar to [VRF-draft-05](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05) (section 5.4.1.1).
    ///
    /// Point multiplication by the cofactor is not required for curve `bn256` as it has cofactor 1.
    ///
    /// # Arguments
    ///
    /// * `msg` - A slice containing the input data.
    ///
    /// # Returns
    ///
    /// * If successful, a point in the `G1` group representing the hashed point.
    fn hash_to_try_and_increment(&self, message: &[u8]) -> Result<G1, Error> {
        let mut c = 0..255;

        // Add counter suffix
        // This message should be: ciphersuite || 0x01 || message || ctr
        // For the moment we work with message || ctr until a tag is decided
        let mut v = [&message[..], &[0x00]].concat();
        let position = v.len() - 1;

        // `Hash(data||ctr)`
        // The modulus of bn256 is low enough to trigger several iterations of this loop
        // We instead compute attempted_hash = `Hash(data||ctr)` mod Fq::modulus
        // This should trigger less iterations of the loop
        let point = c.find_map(|ctr| {
            v[position] = ctr;
            let hash = &self.calculate_sha256(&v)[0..32];
            // this should never fail as the length of sha256 is max 256
            let attempted_hash = arith::U256::from_slice(hash).unwrap();

            // Reducing the hash modulo the field modulus biases point odds
            // As a prevention, we should discard hashes above the highest multiple of the modulo
            if attempted_hash >= LAST_MULTIPLE_OF_FQ_MODULUS_LOWER_THAN_2_256 {
                return None;
            }

            let module_hash = mod_u256(attempted_hash, Fq::modulus());
            let mut s = [0u8; 32];
            module_hash
                .to_big_endian(&mut s)
                .ok()
                .and_then(|_| self.arbitrary_string_to_g1(&s).ok())
        });

        // Return error if no valid point was found
        point.ok_or(Error::HashToPointError)
    }

    /// Function to convert `G1` point into compressed form (`0x02` if Y is even and `0x03` if Y is odd).
    ///
    /// # Arguments
    ///
    /// * `point` - A `G1` point.
    ///
    /// # Returns
    ///
    /// * If successful, a `Vec<u8>` with the compressed `G1` point.
    fn to_compressed_g1(&self, point: G1) -> Result<Vec<u8>, Error> {
        // From Jacobian to Affine first!
        let affine_coords = AffineG1::from_jacobian(point).ok_or(Error::PointInJacobian)?;
        // Get X coordinate
        let x = Fq::into_u256(affine_coords.x());
        // Get Y coordinate
        let y = Fq::into_u256(affine_coords.y());
        // Get parity of Y
        let parity = y.get_bit(0).ok_or(Error::IndexOutOfBounds)?;

        // Take x as big endian into slice
        let mut s = [0u8; 32];
        x.to_big_endian(&mut s)?;
        let mut result: Vec<u8> = Vec::new();
        // Push 0x02 or 0x03 depending on parity
        result.push(if parity { 3 } else { 2 });
        // Append x
        result.append(&mut s.to_vec());

        Ok(result)
    }

    /// Function to get the digest given some input data using SHA256 algorithm.
    ///
    /// # Arguments
    ///
    /// * `data` - A slice containing the input data.
    ///
    /// # Returns
    ///
    /// * The SHA256 digest as a slice.
    fn calculate_sha256(&self, bytes: &[u8]) -> [u8; 32] {
        let mut hasher = sha2::Sha256::new();
        hasher.input(&bytes);
        let mut hash = [0; 32];
        hash.copy_from_slice(&hasher.result());

        hash
    }
}

/// The scalar used as private key
pub struct PrivateKey(bn::Fr);

/// The public key as point in G2
pub struct PublicKey(bn::G2);

impl PrivateKey {
    /// Function to derive a private key.
    pub fn new(rng: &[u8]) -> Result<PrivateKey, Error> {
        // This function throws an error if the slice does not have a proper length.
        let private_key = Fr::from_slice(&rng)?;

        Ok(PrivateKey(private_key))
    }

    /// Function to obtain a private key in bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut result: [u8; 32] = [0; 32];
        // to_big_endian from bn::Fr does not work here.
        self.0.into_u256().to_big_endian(&mut result)?;

        Ok(result.to_vec())
    }

    /// Function to derive the bn256 public key from the private key.
    pub fn derive_public_key(self) -> Result<PublicKey, Error> {
        let PrivateKey(sk) = self;

        Ok(PublicKey(G2::one() * sk))
    }
}

impl PublicKey {
    /// Function to convert a complex coordinate (`Fq2`) to `U512`.
    pub fn to_u512(&self, coord: Fq2) -> arith::U512 {
        let c0: arith::U256 = (coord.real()).into_u256();
        let c1: arith::U256 = (coord.imaginary()).into_u256();

        arith::U512::new(&c1, &c0, &Fq::modulus())
    }

    /// Function to create a `PublicKey` from bytes representing a G2 point in compressed format.
    pub fn from_compressed(bytes: &[u8]) -> Result<Self, Error> {
        let uncompressed = G2::from_compressed(&bytes)?;

        Ok(PublicKey(uncompressed))
    }

    /// Function to create a `PublicKey` from bytes representing a G2 point in uncompressed format.
    pub fn from_uncompressed(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 128 {
            return Err(Error::InvalidLength {});
        }
        let x = Fq2::new(
            Fq::from_slice(&bytes[0..32])?,
            Fq::from_slice(&bytes[32..64])?,
        );
        let y = Fq2::new(
            Fq::from_slice(&bytes[64..96])?,
            Fq::from_slice(&bytes[96..128])?,
        );
        let pub_key = AffineG2::new(x, y)?;

        Ok(PublicKey(pub_key.into()))
    }

    /// Function to serialize the `PublicKey` to vector of bytes in compressed format.
    pub fn to_compressed(&self) -> Result<Vec<u8>, Error> {
        let modulus = Fq::modulus();
        // From Jacobian to Affine first!
        let affine_coords = AffineG2::from_jacobian(self.0).ok_or(Error::PointInJacobian)?;

        // Get X real coordinate
        let x_real = Fq::into_u256(affine_coords.x().real());
        // Get X imaginary coordinate
        let x_imaginary = Fq::into_u256(affine_coords.x().imaginary());
        // Get Y and get sign
        let y = affine_coords.y();
        let y_neg = -y;
        let sign: u8 = if self.to_u512(y) > self.to_u512(y_neg) {
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

    /// Function to serialize the `PublicKey` to vector of bytes in uncompressed format.
    pub fn to_uncompressed(&self) -> Result<Vec<u8>, Error> {
        // From Jacobian to Affine first!
        let affine_coords = AffineG2::from_jacobian(self.0).ok_or(Error::PointInJacobian)?;
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

impl MultiSignature<&[u8], &[u8], &[u8]> for Bn256 {
    type Error = Error;

    /// Function to derive public key (point in G2) given a secret key.
    ///
    /// # Arguments
    ///
    /// * `secret_key` - The secret key bytes
    ///
    /// # Returns
    ///
    /// * If successful, a vector of bytes with the public key
    fn derive_public_key(&mut self, secret_key: &[u8]) -> Result<Vec<u8>, Error> {
        let scalar = Fr::from_slice(&secret_key[0..32])?;
        let key = PrivateKey(scalar);
        let public = key.derive_public_key()?;

        public.to_compressed()
    }

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
    fn sign(&mut self, secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, Self::Error> {
        // 1. Hash_to_try_and_increment --> H(m) as point in G1 (only if it exists)
        let hash_point = self.hash_to_try_and_increment(&message)?;

        // 2. Multiply hash_point times secret_key --> Signature in G1
        let sk = Fr::from_slice(&secret_key)?;
        let signature = hash_point * sk;

        // 3. Return signature as compressed bytes
        self.to_compressed_g1(signature)
    }

    /// Function to verify a signature (point in G1) given a public key (point in G2).
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
    fn verify(
        &mut self,
        signature: &[u8],
        message: &[u8],
        public_key: &[u8],
    ) -> Result<(), Self::Error> {
        let mut vals = Vec::new();
        // First pairing input: e(H(m), PubKey)
        let hash_point = self.hash_to_try_and_increment(&message)?;
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
            Err(Error::VerificationFailed)
        }
    }

    /// Function to aggregate public keys (sum of points in G2).
    ///
    /// # Arguments
    ///
    /// * `public_keys`  - An array of public key bytes to be aggregated
    ///
    /// # Returns
    ///
    /// * If successful, a vector of bytes with the aggregated public key
    fn aggregate_public_keys(&mut self, public_keys: &[&[u8]]) -> Result<Vec<u8>, Self::Error> {
        let agg_public_key: Result<G2, Error> =
            public_keys.iter().try_fold(G2::zero(), |acc, &compressed| {
                let public_key = PublicKey::from_compressed(&compressed)?;

                Ok(acc + public_key.0)
            });

        PublicKey(agg_public_key?).to_compressed()
    }

    /// Function to aggregate signatures (sum of points in G1).
    ///
    /// # Arguments
    ///
    /// * `signatures`  - An array of signature bytes to be aggregated
    ///
    /// # Returns
    ///
    /// * If successful, a vector of bytes with the aggregated signature
    fn aggregate_signatures(&mut self, signatures: &[&[u8]]) -> Result<Vec<u8>, Self::Error> {
        let agg_signatures: Result<G1, Error> =
            signatures.iter().try_fold(G1::zero(), |acc, &compressed| {
                let signature = G1::from_compressed(&compressed)?;

                Ok(acc + signature)
            });

        self.to_compressed_g1(agg_signatures?)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // Test vectors taken from https://asecuritysite.com/encryption/go_bn256. The public keys in G2 are changed in order in the website, i.e., imaginary goes first.
    // In order to construct the test vectors we need to do the following
    // Get the modulus of Fq
    // Get the components (real, imaginary) of x and y
    // perform (imaginary*modulus) +  real
    // Compress with 0x0a or 0x0b depending on the value of y

    #[test]
    fn test_valid_private_key() {
        let compressed =
            hex::decode("023aed31b5a9e486366ea9988b05dba469c6206e58361d9c065bbea7d928204a")
                .unwrap();
        let private_key = PrivateKey::new(&compressed.as_slice());
        assert_eq!(private_key.is_err(), false);
        assert_eq!(private_key.unwrap().to_bytes().unwrap(), compressed);
    }

    #[test]
    fn test_invalid_private_key_1() {
        let compressed = hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
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
    fn test_to_public_key_1() {
        let secret_key =
            hex::decode("1ab1126ff2e37c6e6eddea943ccb3a48f83b380b856424ee552e113595525565")
                .unwrap();
        let expected = hex::decode(
            "28fe26becbdc0384aa67bf734d08ec78ecc2330f0aa02ad9da00f56c37907f78\
             2cd080d897822a95a0fb103c54f06e9bf445f82f10fe37efce69ecb59514abc8\
             237faeb0351a693a45d5d54aa9759f52a71d76edae2132616d6085a9b2228bf9\
             0f46bd1ef47552c3089604c65a3e7154e3976410be01149b60d5a41a6053e6c2",
        )
        .unwrap();
        let mut curve = Bn256 {};
        let public_key = curve.derive_public_key(&secret_key).unwrap();
        let g2 = G2::from_compressed(&public_key).unwrap();
        let expected_g2 = PublicKey::from_uncompressed(&expected).unwrap();

        let uncompressed_slice = expected_g2.to_uncompressed().unwrap();

        assert_eq!(uncompressed_slice, expected);
        assert_eq!(g2, expected_g2.0);
    }

    #[test]
    fn test_to_public_key_2() {
        let secret_key =
            hex::decode("2009da7287c158b126123c113d1c85241b6e3294dd75c643588630a8bc0f934c")
                .unwrap();
        let expected = hex::decode(
            "1cd5df38ed2f184b9830bfd3c2175d53c1455352307ead8cbd7c6201202f4aa8\
             02ce1c4241143cc61d82589c9439c6dd60f81fa6f029625d58bc0f2e25e4ce89\
             0ba19ae3b5a298b398b3b9d410c7e48c4c8c63a1d6b95b098289fbe1503d00fb\
             2ec596e93402de0abc73ce741f37ed4984a0b59c96e20df8c9ea1c4e6ec04556",
        )
        .unwrap();

        let mut curve = Bn256 {};
        let public_key = curve.derive_public_key(&secret_key).unwrap();
        let g2 = G2::from_compressed(&public_key).unwrap();
        let expected_g2 = PublicKey::from_uncompressed(&expected).unwrap();

        let uncompressed_slice = expected_g2.to_uncompressed().unwrap();

        assert_eq!(uncompressed_slice, expected);
        assert_eq!(g2, expected_g2.0);
    }

    #[test]
    fn test_to_public_key_3() {
        let secret_key =
            hex::decode("26fb4d661491b0a623637a2c611e34b6641cdea1743bee94c17b67e5ef14a550")
                .unwrap();
        let expected = hex::decode(
            "077dfcf14e940b69bf88fa1ad99b6c7e1a1d6d2cb8813ac53383bf505a17f8ff\
             2d1a9b04a2c5674373353b5a25591292e69c37c0b84d9ef1c780a57bb98638e6\
             2dc52f109b333c4125bccf55bc3a839ce57676514405656c79e577e231519273\
             2410eee842807d9325f22d087fa6bc79d9bbea07f5fa8c345e1e57b28ad54f84",
        )
        .unwrap();

        let public_key = Bn256.derive_public_key(&secret_key).unwrap();
        let g2 = G2::from_compressed(&public_key).unwrap();
        let expected_g2 = PublicKey::from_uncompressed(&expected).unwrap();

        let uncompressed_slice = expected_g2.to_uncompressed().unwrap();

        assert_eq!(uncompressed_slice, expected);
        assert_eq!(g2, expected_g2.0);
    }

    #[test]
    fn test_to_public_key_4() {
        let secret_key =
            hex::decode("0f6b8785374476a3b3e4bde2c64dfb12964c81c7930d32367c8e318609387872")
                .unwrap();
        let public_key = Bn256.derive_public_key(&secret_key).unwrap();
        let expected = hex::decode(
            "270567a05b56b02e813281d554f46ce0c1b742b622652ef5a41d69afb6eb8338\
             1bab5671c5107de67fe06007dde240a84674c8ff13eeac6d64bad0caf2cfe53e\
             0142f4e04fc1402e17ae7e624fd9bd15f1eae0a1d8eda4e26ab70fd4cd793338\
             02b54a5deaaf86dc7f03d080c8373d62f03b3be06dac42b2d9426a8ebd0caf4a",
        )
        .unwrap();

        let g2 = G2::from_compressed(&public_key).unwrap();
        let expected_g2 = PublicKey::from_uncompressed(&expected).unwrap();
        let uncompressed_slice = expected_g2.to_uncompressed().unwrap();

        assert_eq!(uncompressed_slice, expected);
        assert_eq!(g2, expected_g2.0);
    }

    /// Test for the `hash_to_try_and_increment` valid range
    #[test]
    fn test_hash_to_try_valid_range() {
        let modulus = Fq::modulus();
        let mut last_multiple = arith::U256([5, 0]);
        let mut overflow_multiple = arith::U256([6, 0]);
        let max_value = arith::U256([
            0xffffffffffffffffffffffffffffffff,
            0xffffffffffffffffffffffffffffffff,
        ]);
        last_multiple.mul(&modulus, &max_value, 1);
        assert_eq!(last_multiple, LAST_MULTIPLE_OF_FQ_MODULUS_LOWER_THAN_2_256);
        overflow_multiple.mul(&modulus, &max_value, 1);
        assert!(overflow_multiple < modulus)
    }

    /// Test for the `hash_to_try_and_increment` function with own test vector
    #[test]
    fn test_hash_to_try_and_increment_1() {
        // Data to be hashed with TAI (ASCII "sample")
        let data = hex::decode("73616d706c65").unwrap();
        let hash_point = Bn256.hash_to_try_and_increment(&data).unwrap();
        let hash_bytes = Bn256.to_compressed_g1(hash_point).unwrap();

        let expected_hash = "0211e028f08c500889891cc294fe758a60e84495ec1e2d0bce208c9fc67b6486fd";
        assert_eq!(hex::encode(hash_bytes), expected_hash);
    }

    /// Test for the `hash_to_try_and_increment` function with own test vector
    #[test]
    fn test_hash_to_try_and_increment_2() {
        // Data to be hashed with TAI (ASCII "hello")
        let data = hex::decode("68656c6c6f").unwrap();
        let hash_point = Bn256.hash_to_try_and_increment(&data).unwrap();
        let hash_bytes = Bn256.to_compressed_g1(hash_point).unwrap();

        let expected_hash = "0200b201235f522abbd3863b7496dfa213be0ed1f4c7a22196d8afddec7e64c8ec";
        assert_eq!(hex::encode(hash_bytes), expected_hash);
    }

    /// Test for the `sign`` function with own test vector
    #[test]
    fn test_sign_1() {
        // Inputs: secret key and message "sample" in ASCII
        let secret_key =
            hex::decode("2009da7287c158b126123c113d1c85241b6e3294dd75c643588630a8bc0f934c")
                .unwrap();
        let data = hex::decode("73616d706c65").unwrap();

        // Sign data with secret key
        let signature = Bn256.sign(&secret_key, &data).unwrap();

        let expected_signature =
            "020f047a153e94b5f109e4013d1bd078112817cf0d58cdf6ba8891f9849852ba5b";

        assert_eq!(hex::encode(signature), expected_signature);
    }

    /// Test `verify` function with own signed message
    #[test]
    fn test_verify_signed_msg() {
        // Public key
        let secret_key =
            hex::decode("2009da7287c158b126123c113d1c85241b6e3294dd75c643588630a8bc0f934c")
                .unwrap();
        let public_key = Bn256.derive_public_key(&secret_key).unwrap();

        // Signature
        let signature =
            hex::decode("020f047a153e94b5f109e4013d1bd078112817cf0d58cdf6ba8891f9849852ba5b")
                .unwrap();

        // Message signed
        let msg = hex::decode("73616d706c65").unwrap();

        // Verify signature
        assert!(
            Bn256.verify(&signature, &msg, &public_key).is_ok(),
            "Verification failed"
        );
    }

    /// Test `aggregate_public_keys`
    #[test]
    fn test_aggregate_public_keys_1() {
        // Public keys
        let public_key_1 = PublicKey(G2::one()).to_compressed().unwrap();
        let public_key_2 = PublicKey(G2::one()).to_compressed().unwrap();
        let public_keys = [&public_key_1[..], &public_key_2[..]];

        // Aggregation
        let agg_public_key = Bn256.aggregate_public_keys(&public_keys).unwrap();

        // Check
        let expected = hex::decode("0b061848379c6bccd9e821e63ff6932738835b78e1e10079a0866073eba5b8bb444afbb053d16542e2b839477434966e5a9099093b6b3351f84ac19fe28f096548").unwrap();
        assert_eq!(agg_public_key, expected);
    }

    /// Test `aggregate_signatures`
    #[test]
    fn test_aggregate_signatures_1() {
        // Signatures (as valid points on G1)
        let sign_1 = Bn256.to_compressed_g1(G1::one()).unwrap();
        let sign_2 = Bn256.to_compressed_g1(G1::one()).unwrap();
        let signatures = [&sign_1[..], &sign_2[..]];

        // Aggregation
        let agg_signature = Bn256
            .aggregate_signatures(&signatures)
            .expect("Signature aggregation should not fail if G1 points are valid.");

        // Check
        let expected =
            hex::decode("02030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd3")
                .unwrap();
        assert_eq!(agg_signature, expected);
    }

    /// Test aggregated signatures verification
    #[test]
    fn test_verify_aggregated_signatures_1() {
        // Message
        let msg = hex::decode("73616d706c65").unwrap();

        // Signature 1
        let secret_key1 =
            hex::decode("1ab1126ff2e37c6e6eddea943ccb3a48f83b380b856424ee552e113595525565")
                .unwrap();
        let public_key1 = Bn256.derive_public_key(&secret_key1).unwrap();
        let sign_1 = Bn256.sign(&secret_key1, &msg).unwrap();

        // Signature 2
        let secret_key2 =
            hex::decode("2009da7287c158b126123c113d1c85241b6e3294dd75c643588630a8bc0f934c")
                .unwrap();
        let public_key2 = Bn256.derive_public_key(&secret_key2).unwrap();
        let sign_2 = Bn256.sign(&secret_key2, &msg).unwrap();

        // Public Key and Signature aggregation
        let agg_public_key = Bn256
            .aggregate_public_keys(&[&public_key1, &public_key2])
            .unwrap();
        let agg_signature = Bn256.aggregate_signatures(&[&sign_1, &sign_2]).unwrap();

        // Verification single signatures
        assert!(
            Bn256.verify(&sign_1, &msg, &public_key1).is_ok(),
            "Signature 1 verification failed"
        );
        assert!(
            Bn256.verify(&sign_2, &msg, &public_key2).is_ok(),
            "Signature 2 signature verification failed"
        );

        // Aggregated signature verification
        assert!(
            Bn256.verify(&agg_signature, &msg, &agg_public_key).is_ok(),
            "Aggregated signature verification failed"
        );
    }
}
