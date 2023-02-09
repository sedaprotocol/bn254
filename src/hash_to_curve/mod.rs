use self::{expand_msg_xmd::expand_msg_xmd, hash_to_field::hash_to_field, map_to_curve::map_to_curve};

mod element;
mod expand_msg_xmd;
mod hash_to_field;
mod map_to_curve;

use anyhow::Result;
use bn::{AffineG1, G1};
use digest::{crypto_common::BlockSizeUser, Digest, FixedOutput};

#[cfg(test)]
#[path = ""]
mod test {
    use super::*;
    use crate::test_utils::TestCase;
    mod expand_msg_xmd_test;
}

pub fn hash_to_curve_g1<Hasher>(data: &[u8], dst: &[u8]) -> Result<AffineG1>
where
    Hasher: BlockSizeUser + Digest + FixedOutput,
{
    let u = hash_to_field::<Hasher>(data, dst, 2)?;

    let q0 = map_to_curve(u[0])?;
    let q1 = map_to_curve(u[1])?;

    let q0_jac: G1 = q0.into();
    let q1_jac: G1 = q1.into();

    Ok(AffineG1::from_jacobian(q0_jac + q1_jac).unwrap())
}
