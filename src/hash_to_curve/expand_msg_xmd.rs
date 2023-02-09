use anyhow::{bail, Result};
use digest::{crypto_common::BlockSizeUser, generic_array::GenericArray, typenum::Unsigned, Digest, FixedOutputReset};

// ExpandMsgXmd expands msg to a slice of len_in_bytes bytes.
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-06#section-5
// https://tools.ietf.org/html/rfc8017#section-4.1 (I2OSP/O2ISP)
pub(crate) fn expand_msg_xmd<Hasher>(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Result<Vec<u8>>
where
    Hasher: Digest + BlockSizeUser + FixedOutputReset,
{
    let b_in_bytes = Hasher::OutputSize::to_usize();
    let ell = (len_in_bytes + b_in_bytes - 1) / b_in_bytes;
    if ell > 255 {
        bail!("invalid len_in_bytes")
    }
    if dst.len() > 255 {
        bail!("invalid domain size (>255 bytes)")
    }
    let domain_size = [dst.len() as u8];

    let b0 = Hasher::new()
        .chain_update(GenericArray::<u8, Hasher::BlockSize>::default())
        .chain_update(msg)
        .chain_update([(len_in_bytes >> 8) as u8, len_in_bytes as u8, 0u8])
        .chain_update(dst)
        .chain_update(domain_size)
        .finalize_reset();

    let mut b1 = Hasher::new()
        .chain_update(&b0)
        .chain_update([1u8])
        .chain_update(dst)
        .chain_update(domain_size)
        .finalize_reset();

    let mut result = vec![0u8; len_in_bytes];
    result[..Hasher::OutputSize::to_usize()].copy_from_slice(&b1);
    // let mut offset = 0;
    for i in 2..=ell {
        // TODO is there a better way to do this?
        let mut stxor = GenericArray::<u8, Hasher::OutputSize>::default();
        b0.iter()
            .zip(&b1)
            .enumerate()
            .for_each(|(j, (b0, bi))| stxor[j] = b0 ^ bi);

        b1 = Hasher::new()
            .chain_update(stxor)
            .chain_update([i as u8])
            .chain_update(dst)
            .chain_update(domain_size)
            .finalize_reset();

        let r_len = result.len();
        result[Hasher::OutputSize::to_usize() * (i - 1)..std::cmp::min(Hasher::OutputSize::to_usize() * i, r_len)]
            .copy_from_slice(&b1);
    }

    Ok(result)
}

mod test {
    use super::*;

    #[test]
    fn simple() {
        let dst = b"QUUX-V01-CS02-with-expander-SHA256-128";
        let hex = "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235";
        let uniform = expand_msg_xmd::<sha2::Sha256>(b"", dst, sha2::Sha256::output_size()).unwrap();

        let uniform_og_hex = hex::decode(hex.as_bytes()).unwrap();

        assert_eq!(uniform.len(), uniform_og_hex.len());
        let uniform_hex = hex::encode(&uniform);
        assert_eq!(uniform_hex, hex);
        assert_eq!(uniform, uniform_og_hex);
    }
}
