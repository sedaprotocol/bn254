use anyhow::{bail, Result};
use digest::{crypto_common::BlockSizeUser, generic_array::GenericArray, typenum::Unsigned, Digest, FixedOutput};

struct Expander<'a, Hasher>
where
    Hasher: BlockSizeUser + FixedOutput,
{
    b0:     GenericArray<u8, Hasher::OutputSize>,
    b1:     GenericArray<u8, Hasher::OutputSize>,
    domain: &'a [u8],
    index:  u8,
    offset: usize,
    ell:    u8,
}
impl<'a, Hasher> Expander<'a, Hasher>
where
    Hasher: BlockSizeUser + Digest + FixedOutput,
{
    fn next(&mut self) -> bool {
        if self.index < self.ell {
            self.index += 1;
            self.offset = 0;
            // b_0 XOR b_(idx - 1)
            let mut tmp = GenericArray::<u8, Hasher::OutputSize>::default();
            self.b0
                .iter()
                .zip(&self.b1[..])
                .enumerate()
                .for_each(|(j, (b0val, bi1val))| tmp[j] = b0val ^ bi1val);
            self.b1 = Hasher::new()
                .chain_update(&tmp)
                .chain_update([self.index])
                .chain_update(self.domain)
                .chain_update([self.domain.len() as u8])
                .finalize_fixed();
            true
        } else {
            false
        }
    }
}

// ExpandMsgXmd expands msg to a slice of len_in_bytes bytes.
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-06#section-5
// https://tools.ietf.org/html/rfc8017#section-4.1 (I2OSP/O2ISP)
pub(crate) fn expand_msg_xmd<Hasher>(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Result<Vec<u8>>
where
    Hasher: BlockSizeUser + Digest + FixedOutput,
{
    if len_in_bytes == 0 {
        bail!("le in bytes cannot be 0");
    }
    let len_in_bytes_u16 = u16::try_from(len_in_bytes)?;
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
        .chain_update(len_in_bytes_u16.to_be_bytes())
        .chain_update([0])
        .chain_update(dst)
        .chain_update(domain_size)
        .finalize_fixed();

    let b1 = Hasher::new()
        .chain_update(&b0)
        .chain_update([1u8])
        .chain_update(dst)
        .chain_update(domain_size)
        .finalize_fixed();

    let mut expander = Expander::<'_, Hasher> {
        b0,
        b1,
        domain: dst,
        index: 1,
        offset: 0,
        ell: ell as u8,
    };
    let mut result = vec![0u8; len_in_bytes];

    for index in 0..result.len() {
        if expander.offset == expander.b1.len() && !expander.next() {
            return Ok(result);
        }
        result[index] = expander.b1[expander.offset];
        expander.offset += 1;
    }

    Ok(result)
}
