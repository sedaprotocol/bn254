use bn::{arith, Fq, G1};
use sha2::{Digest, Sha256};

use crate::{
    error::{Error, Result},
    utils,
};

/// This is 0xf1f5883e65f820d099915c908786b9d3f58714d70a38f4c22ca2bc723a70f263,
/// the last mulitple of the modulus before 2^256
pub(crate) const LAST_MULTIPLE_OF_FQ_MODULUS_LOWER_THAN_2_256: arith::U256 = arith::U256([
    0xf587_14d7_0a38_f4c2_2ca2_bc72_3a70_f263,
    0xf1f5_883e_65f8_20d0_9991_5c90_8786_b9d3,
]);

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
/// * If successful, a point in the [G1] group representing the hashed point.
pub(crate) fn hash_to_try_and_increment<T: AsRef<[u8]>>(message: T) -> Result<G1> {
    // Add counter suffix
    // This message should be: ciphersuite || 0x01 || message || ctr
    // For the moment we work with message || ctr until a tag is decided
    let mut v = [message.as_ref(), &[0x00]].concat();
    let position = v.len() - 1;

    // `Hash(data||ctr)`
    // The modulus of bn256 is low enough to trigger several iterations of this loop
    // We instead compute attempted_hash = `Hash(data||ctr)` mod Fq::modulus
    // This should trigger less iterations of the loop
    let point = (0..255).find_map(|ctr| {
        v[position] = ctr;
        let hash = Sha256::digest(&v);
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

    // Return an error if no valid point was found
    point.ok_or(Error::HashToPointError)
}
