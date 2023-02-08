use bn::{arith, Fq, G1};
use sha2::{Digest, Sha256};

use crate::{error::Bn254Error, utils};

/// This is 0xf1f5883e65f820d099915c908786b9d3f58714d70a38f4c22ca2bc723a70f263,
/// the last mulitple of the modulus before 2^256
const LAST_MULTIPLE_OF_FQ_MODULUS_LOWER_THAN_2_256: arith::U256 = arith::U256([
    0xf587_14d7_0a38_f4c2_2ca2_bc72_3a70_f263,
    0xf1f5_883e_65f8_20d0_9991_5c90_8786_b9d3,
]);

/// Function to get the digest given some input data using SHA256 algorithm.
///
/// # Arguments
///
/// * `data` - A slice containing the input data.
///
/// # Returns
///
/// * The SHA256 digest as a slice.
fn calculate_sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(&bytes).into()
}

/// Function to convert a `Hash(DATA|COUNTER)` to a point in the curve.
/// Similar to [VRF-draft-05](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05) (section 5.4.1.1).
///
/// Point multiplication by the cofactor is not required for curve `bn256` as it
/// has cofactor 1.
///
/// # Arguments
///
/// * `msg` - A slice containing the input data.
///
/// # Returns
///
/// * If successful, a point in the `G1` group representing the hashed point.
pub(crate) fn hash_to_try_and_increment(message: &[u8]) -> Result<G1, Bn254Error> {
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
        let hash = calculate_sha256(&v);
        // this should never fail as the length of sha256 is max 256
        let attempted_hash = arith::U256::from_slice(&hash).unwrap();

        // Reducing the hash modulo the field modulus biases point odds
        // As a prevention, we should discard hashes above the highest multiple of the
        // modulo
        if attempted_hash >= LAST_MULTIPLE_OF_FQ_MODULUS_LOWER_THAN_2_256 {
            return None;
        }

        let module_hash = utils::mod_u256(attempted_hash, Fq::modulus());
        let mut s = [0u8; 32];
        module_hash
            .to_big_endian(&mut s)
            .ok()
            .and_then(|_| utils::arbitrary_string_to_g1(&s).ok())
    });

    // Return Bn254Error if no valid point was found
    point.ok_or(Bn254Error::HashToPointError)
}

/// Test for the `hash_to_try_and_increment` function with own test vector
#[test]
fn test_hash_to_try_and_increment_1() {
    // Data to be hashed with TAI (ASCII "sample")
    let data = hex::decode("73616d706c65").unwrap();
    let hash_point = hash_to_try_and_increment(&data).unwrap();
    let hash_bytes = utils::to_compressed_g1(hash_point).unwrap();

    let expected_hash = "0211e028f08c500889891cc294fe758a60e84495ec1e2d0bce208c9fc67b6486fd";
    assert_eq!(hex::encode(hash_bytes), expected_hash);
}

/// Test for the `hash_to_try_and_increment` function with own test vector
#[test]
fn test_hash_to_try_and_increment_2() {
    // Data to be hashed with TAI (ASCII "hello")
    let data = hex::decode("68656c6c6f").unwrap();
    let hash_point = hash_to_try_and_increment(&data).unwrap();
    let hash_bytes = utils::to_compressed_g1(hash_point).unwrap();

    let expected_hash = "0200b201235f522abbd3863b7496dfa213be0ed1f4c7a22196d8afddec7e64c8ec";
    assert_eq!(hex::encode(hash_bytes), expected_hash);
}

/// Test for the `hash_to_try_and_increment` valid range
#[test]
fn test_hash_to_try_valid_range() {
    let modulus = Fq::modulus();
    let mut last_multiple = arith::U256([5, 0]);
    let mut overflow_multiple = arith::U256([6, 0]);
    let max_value = arith::U256([0xffffffffffffffffffffffffffffffff, 0xffffffffffffffffffffffffffffffff]);
    last_multiple.mul(&modulus, &max_value, 1);
    assert_eq!(last_multiple, LAST_MULTIPLE_OF_FQ_MODULUS_LOWER_THAN_2_256);
    overflow_multiple.mul(&modulus, &max_value, 1);
    assert!(overflow_multiple < modulus)
}
