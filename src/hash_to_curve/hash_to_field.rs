use anyhow::Result;
use digest::{crypto_common::BlockSizeUser, Digest, FixedOutput};

use super::element::Element;
use crate::hash_to_curve::expand_msg_xmd::expand_msg_xmd;

// Hash data to count prime field elements.
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-11#section-5.3
pub(crate) fn hash_to_field<Hasher>(data: &[u8], dst: &[u8], count: usize, l: usize) -> Result<Vec<Element>>
where
    Hasher: BlockSizeUser + Digest + FixedOutput,
{
    let len_in_bytes = count * l;
    dbg!(l);
    dbg!(len_in_bytes);
    let random_bytes = expand_msg_xmd::<Hasher>(data, dst, len_in_bytes)?;
    dbg!(random_bytes.len());

    (0..count)
        .into_iter()
        .map(|i| Element::from_slice(&random_bytes[l * i..l * (i + 1)]))
        .collect::<Result<Vec<_>>>()
}
