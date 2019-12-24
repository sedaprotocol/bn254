use crate::BLS;

extern crate bn;
extern crate rustc_hex;

use bn::{arith, AffineG1, AffineG2, Fq, Fq2, Fr, Group, Gt, G1, G2};
use bn::{CurveError, FieldError, GroupError};
use byteorder::{BigEndian, ByteOrder};
use digest::Digest;
use failure::Fail;
use sha2;
use failure::_core::ptr::hash;

#[allow(non_camel_case_types)]
#[derive(Debug, Fail)]
pub enum Error {
    /// The `hash_to_point()` function could not find a valid point
    #[fail(display = "Hash to point function could not find a valid point")]
    HashToPointError,
    /// Unknown error
    #[fail(display = "Unknown error")]
    Unknown,
}

impl From<CurveError> for Error {
    fn from(_error: CurveError) -> Self {
        Error::Unknown {}
    }
}

impl From<FieldError> for Error {
    fn from(_error: FieldError) -> Self {
        Error::Unknown {}
    }
}

impl From<GroupError> for Error {
    fn from(_error: GroupError) -> Self {
        Error::Unknown {}
    }
}

impl From<bn::arith::Error> for Error {
    fn from(_error: bn::arith::Error) -> Self {
        Error::Unknown {}
    }
}

pub fn to_u512(myass: Fq2) -> arith::U512 {
    let c0: arith::U256 = (myass.real()).into_u256();
    let c1: arith::U256 = (myass.imaginary()).into_u256();

    arith::U512::new(&c1, &c0, &Fq::modulus())
}

struct Bn128 {}

impl Bn128 {
    /// Function to convert an arbitrary string to a point in the curve
    ///
    /// # Arguments
    ///
    /// * `data` - A slice representing the data to be converted to a point.
    ///
    /// # Returns
    ///
    /// * If successful, a `G1` representing the converted point.
    fn arbitrary_string_to_point(&self, data: &[u8]) -> Result<G1, Error> {
        let mut v = vec![0x02];
        v.extend(data);
        let point = G1::from_compressed(&v)?;

        Ok(point)
    }

    /// Function to convert a `Hash(PK|DATA)` to a point in the curve as stated in [VRF-draft-05](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05)
    /// (section 5.4.1.1).
    ///
    /// Point multiplication by the cofactor is not required for curve `bn128`.
    /// Since this curve is of prime order, every non-identity point is a generator, therefore the cofactor is 1.
    ///
    /// # Arguments
    ///
    /// * `public_key` - A slice of `[u8]` representing the public key in compressed form.
    /// * `msg` - A slice containing the input data.
    ///
    /// # Returns
    ///
    /// * If successful, a point in the `G1` group representing the hashed point.
    fn hash_to_try_and_increment(&self, public_key: &[u8], msg: &[u8]) -> Result<G1, Error> {
        let mut c = 0..255;

        // Add prefixes and counter suffix
        let cipher = [0xFF, 0x01];
        let mut v = [&cipher[..], &public_key[..], &msg[..], &[0x00]].concat();
        let position = v.len() - 1;

        // `Hash(cipher||PK||data)`
        let point = c.find_map(|ctr| {
            v[position] = ctr;
            let attempted_hash = self.calculate_sha256(&v);
            // Check validity of `H` (i.e. point exists in group G1)
            self.arbitrary_string_to_point(&attempted_hash).ok()
        });

        // Return error if no valid point was found
        point.ok_or(Error::HashToPointError)
    }

    /// Function to convert `G1` point into compressed form (`0x02` if Y is even and `0x03` if Y is odd)
    ///
    /// # Arguments
    ///
    /// * `point` - A `G1` point.
    ///
    /// # Returns
    ///
    /// * If successful, a `Vec<u8>` with the compressed `G1` point.
    pub fn to_compressed_g1(&self, point: G1) -> Result<Vec<u8>, Error> {
        // From Jacobian to Affine first!
        let affine_coords = AffineG1::from_jacobian(point).ok_or(Error::Unknown)?;
        // Get X coordinate
        let x = Fq::into_u256(affine_coords.x());
        // Get Y coordinate
        let y = Fq::into_u256(affine_coords.y());
        // Get parity of Y
        let parity = y.get_bit(0).ok_or(Error::Unknown)?;

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

    /// Calculate the SHA256 hash
    pub fn calculate_sha256(&self, bytes: &[u8]) -> [u8; 32] {
        let mut hasher = sha2::Sha256::new();
        hasher.input(&bytes);
        let mut hash = [0; 32];
        hash.copy_from_slice(&hasher.result());

        hash
    }
}

pub struct PrivateKey {
    sk: bn::Fr,
}

pub struct PublicKey {
    pk: bn::G2,
}

impl PrivateKey {
    pub fn from_sk(sk: &Fr) -> PrivateKey {
        PrivateKey { sk: *sk }
    }

    pub fn to_public(&self) -> Result<PublicKey, Error> {
        Ok(PublicKey {
            pk: G2::one() * self.sk,
        })
    }
}

impl PublicKey {
    pub fn from_compressed(bytes: &[u8]) -> Result<Self, Error> {
        let uncompressed = G2::from_compressed(&bytes)?;
        Ok(PublicKey { pk: uncompressed })
    }

    pub fn to_compressed(&self) -> Result<Vec<u8>, Error> {
        let modulus = Fq::modulus();
        // From Jacobian to Affine first!
        let affine_coords = AffineG2::from_jacobian(self.pk).ok_or(Error::Unknown)?;

        // Get X real coordinate
        let x_real = Fq::into_u256(affine_coords.x().real());

        // Get X imaginary coordinate
        let x_imaginary = Fq::into_u256(affine_coords.x().imaginary());

        // Get Y and get sign
        let y = affine_coords.y();
        let y_neg = -y;
        let sign: u8 = if to_u512(y) > to_u512(y_neg) {
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
}

fn read_fr(scalar: &[u8]) -> Result<bn::Fr, Error> {
    Ok(bn::Fr::from_slice(&scalar[0..32])?)
}

impl BLS<&[u8], &[u8], &[u8]> for Bn128 {
    type Error = Error;

    // TODO: Add documentation -> public key in G2
    fn derive_public_key(&mut self, secret_key: &[u8]) -> Result<Vec<u8>, Error> {
        let scalar = read_fr(&secret_key)?;
        let key = PrivateKey::from_sk(&scalar);
        let public = key.to_public()?;

        // Jacobian to Affine
        //  let affine = AffineG2::from_jacobian(public.pk).ok_or(Error::Unknown)?;

        public.to_compressed()
    }

    // TODO: Add documentation
    fn sign(&mut self, secret_key: &[u8], msg: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let public_key = self.derive_public_key(&secret_key)?;

        // 1. Hash_to_try_and_increment --> H(m) as point in G1 (only if it exists)
        let hash_point = self.hash_to_try_and_increment(&public_key, &msg)?;

        // 2. Multiply hash_point times secret_key --> Signature in G1
        let sk = Fr::from_slice(&secret_key)?;
        let signature = hash_point * sk;

        // 3. Return signature as compressed bytes
        self.to_compressed_g1(signature)
    }

    // e( H(m), PubKey ) = e( Signature, G2::one())
    fn verify(
        &mut self,
        public_key: &[u8],
        signature: &[u8],
        msg: &[u8],
    ) -> Result<bool, Self::Error> {
        unimplemented!()
    }

    fn aggregate_public_keys(&mut self, public_key: &[&[u8]]) -> Result<Vec<u8>, Self::Error> {
        unimplemented!()
    }

    fn aggregate_signatures(&mut self, public_key: &[&[u8]]) -> Result<Vec<u8>, Self::Error> {
        unimplemented!()
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
    fn test_compressed_public_key_1() {
        let compressed = hex::decode("0a023aed31b5a9e486366ea9988b05dba469c6206e58361d9c065bbea7d928204a761efc6e4fa08ed227650134b52c7f7dd0463963e8a4bf21f4899fe5da7f984a").unwrap();
        let public_key = PublicKey::from_compressed(&compressed).unwrap();
        let compressed_again = public_key.to_compressed().unwrap();
        assert_eq!(compressed, compressed_again);
    }

    #[test]
    fn test_to_public_key_1() {
        let secret_key = hex::decode("1ab1126ff2e37c6e6eddea943ccb3a48f83b380b856424ee552e113595525565").unwrap();
        let mut curve = Bn128 {};
        let public_key = curve.derive_public_key(&secret_key).unwrap();
        let g2 = G2::from_compressed(
            &public_key
        ).unwrap();

        assert_eq!(g2.x(),
                   Fq2::new(
                       Fq::from_slice(&hex::decode("28fe26becbdc0384aa67bf734d08ec78ecc2330f0aa02ad9da00f56c37907f78").unwrap()).unwrap(),
                       Fq::from_slice(&hex::decode("2cd080d897822a95a0fb103c54f06e9bf445f82f10fe37efce69ecb59514abc8").unwrap()).unwrap(),
                   )
        );
        assert_eq!(g2.y(),
                   Fq2::new(
                       Fq::from_slice(&hex::decode("237faeb0351a693a45d5d54aa9759f52a71d76edae2132616d6085a9b2228bf9").unwrap()).unwrap(),
                       Fq::from_slice(&hex::decode("0f46bd1ef47552c3089604c65a3e7154e3976410be01149b60d5a41a6053e6c2").unwrap()).unwrap(),
                   )
        );
    }

    #[test]
    fn test_to_public_key_2() {
        let secret_key = hex::decode("2009da7287c158b126123c113d1c85241b6e3294dd75c643588630a8bc0f934c").unwrap();
        let mut curve = Bn128 {};
        let public_key = curve.derive_public_key(&secret_key).unwrap();
        let g2 = G2::from_compressed(
            &public_key
        ).unwrap();
        assert_eq!(g2.x(),
                   Fq2::new(
                       Fq::from_slice(&hex::decode("1cd5df38ed2f184b9830bfd3c2175d53c1455352307ead8cbd7c6201202f4aa8").unwrap()).unwrap(),
                       Fq::from_slice(&hex::decode("02ce1c4241143cc61d82589c9439c6dd60f81fa6f029625d58bc0f2e25e4ce89").unwrap()).unwrap(),
                   )
        );
        assert_eq!(g2.y(),
                   Fq2::new(
                       Fq::from_slice(&hex::decode("0ba19ae3b5a298b398b3b9d410c7e48c4c8c63a1d6b95b098289fbe1503d00fb").unwrap()).unwrap(),
                       Fq::from_slice(&hex::decode("2ec596e93402de0abc73ce741f37ed4984a0b59c96e20df8c9ea1c4e6ec04556").unwrap()).unwrap(),
                   )
        );
    }

    #[test]
    fn test_to_public_key_3() {
        let secret_key = hex::decode("26fb4d661491b0a623637a2c611e34b6641cdea1743bee94c17b67e5ef14a550").unwrap();
        let mut curve = Bn128 {};
        let public_key = curve.derive_public_key(&secret_key).unwrap();
        let g2 = G2::from_compressed(
            &public_key
        ).unwrap();
        assert_eq!(g2.x(),
                   Fq2::new(
                       Fq::from_slice(&hex::decode("077dfcf14e940b69bf88fa1ad99b6c7e1a1d6d2cb8813ac53383bf505a17f8ff").unwrap()).unwrap(),
                       Fq::from_slice(&hex::decode("2d1a9b04a2c5674373353b5a25591292e69c37c0b84d9ef1c780a57bb98638e6").unwrap()).unwrap(),
                   )
        );
        assert_eq!(g2.y(),
                   Fq2::new(
                       Fq::from_slice(&hex::decode("2dc52f109b333c4125bccf55bc3a839ce57676514405656c79e577e231519273").unwrap()).unwrap(),
                       Fq::from_slice(&hex::decode("2410eee842807d9325f22d087fa6bc79d9bbea07f5fa8c345e1e57b28ad54f84").unwrap()).unwrap(),
                   )
        );
    }

    /// Regression Test for the hash_to_try function
    /// TODO: double-check test
    #[test]
    fn test_regression_hash_to_try_and_increment() {
        let mut curve = Bn128 {};

        // Public key
        let secret_key =
            hex::decode("2009da7287c158b126123c113d1c85241b6e3294dd75c643588630a8bc0f934c")
                .unwrap();
        let public_key = curve.derive_public_key(&secret_key).unwrap();

        // Data to be hashed with TAI (ASCII "sample")
        let data = hex::decode("73616d706c65").unwrap();
        let hash_point = curve.hash_to_try_and_increment(&public_key, &data).unwrap();
        let hash_bytes = curve.to_compressed_g1(hash_point).unwrap();

        let expected_hash =
            hex::decode("022aea970a30a6e7ac62400cf2bab15ab3b31305c6af6c8b5763573286072295f6")
                .unwrap();
        assert_eq!(hash_bytes, expected_hash);
    }

    /// Regression Test for the `sign` function
    /// TODO: double-check test
    #[test]
    fn test_regression_sign() {
        let mut bn128 = Bn128 {};

        // Inputs: secret key and message "sample" in ASCII
        let secret_key =
            hex::decode("2009da7287c158b126123c113d1c85241b6e3294dd75c643588630a8bc0f934c")
                .unwrap();
        let data = hex::decode("73616d706c65").unwrap();

        // Sign data with secret key
        let signature = bn128.sign(&secret_key, &data).unwrap();

        let expected_signature =
            hex::decode("0224942ea9eb2845931cdd69d437a9e9bfc64b603497f72ab34f2accc30bb26bd1")
                .unwrap();
        assert_eq!(signature, expected_signature);
    }

}
