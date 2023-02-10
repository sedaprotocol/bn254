use anyhow::Result;
use digest::{crypto_common::BlockSizeUser, Digest, FixedOutput};

use super::element::Element;
use crate::hash_to_curve::expand_msg_xmd::expand_msg_xmd;

// Hash data to count prime field elements.
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-11#section-5.3
pub(crate) fn hash_to_field<Hasher>(data: &[u8], dst: &[u8], count: usize) -> Result<Vec<Element>>
where
    Hasher: BlockSizeUser + Digest + FixedOutput,
{
    let bytes = 1 + (254 - 1) / 8;
    let l = 16 + bytes;
    let len_in_bytes = count * l;
    let random_bytes = expand_msg_xmd::<Hasher>(data, dst, len_in_bytes)?;

    Ok((0..count)
        .into_iter()
        .map(|i| {
            let field_bytes = &random_bytes[l * i..l * (i + 1)];
            let big_int = num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, field_bytes);
            Element::from_big_int(big_int)
        })
        .collect::<Vec<_>>())
}
