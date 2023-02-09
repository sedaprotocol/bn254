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
            let big_int = dbg!(num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, field_bytes));

            let e = Element::from_big_int(big_int);
            // panic!("help");
            e
        })
        .collect::<Vec<_>>())
}

mod test {
    use std::str::FromStr;

    use num_bigint::BigInt;

    use super::hash_to_field;
    use crate::hash_to_curve::element::Element;

    #[test]
    fn simple() {
        let data = b"".as_slice();
        // let dst = b"QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_NU_".as_slice();
        let dst = b"QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_RO_".as_slice();
        let mut foo = vec![0u8; 32];
        bn::Fq::zero().to_big_endian(&mut foo).unwrap();

        let u0_big_int =
            BigInt::from_str("21498498956904532351723378912032873852253513037650692457560050969314502748597").unwrap();
        let e = Element::from_big_int(u0_big_int);
        dbg!(e);
        let elements = hash_to_field::<sha2::Sha256>(data, dst, 2).unwrap();
        // dbg!(elements);
        assert_eq!(e, elements[0]);
    }
}
