use self::{hash_to_field::hash_to_field, map_to_curve::map_to_curve};

mod element;
mod expand_msg_xmd;
mod hash_to_field;
mod map_to_curve;

use anyhow::Result;
use bn::{AffineG1, G1};
use digest::{crypto_common::BlockSizeUser, Digest, FixedOutput};

pub fn hash_to_curve_g1<Hasher, Msg, Dst>(message: Msg, dst: Dst) -> Result<AffineG1>
where
    Hasher: BlockSizeUser + Digest + FixedOutput,
    Msg: AsRef<[u8]>,
    Dst: AsRef<[u8]>,
{
    let u = hash_to_field::<Hasher>(message.as_ref(), dst.as_ref(), 2)?;

    let q0 = map_to_curve(u[0])?;
    let q1 = map_to_curve(u[1])?;

    let q0_jac: G1 = q0.into();
    let q1_jac: G1 = q1.into();

    Ok(AffineG1::from_jacobian(q0_jac + q1_jac).unwrap())
}

#[cfg(test)]
#[path = ""]
mod test {
    use super::*;
    use crate::test_utils::TestCase;
    mod expand_msg_xmd_test;
    mod hash_to_field_test;

    #[test]
    fn does_it_panic() {
        // it does :c
        // It should never fail though I believe?
        // I see tests just feeding in random values to map to curve
        // x for first map to curve should be [2570383990618758870
        // 16836523554894106449 16669291316902191077 2582760076117888206]
        // y for first map to curve should be [8255676397616104146 3471910408089579624
        // 15181191053719781553 2728335385036632800]
        hash_to_curve_g1::<sha2::Sha256, _, _>(b"", b"QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_RO_").unwrap();
    }
}
