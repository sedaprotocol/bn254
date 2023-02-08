use anyhow::Result;

pub trait ToElement {
    fn to_element(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized;
}

// Hash data to count prime field elements.
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-11#section-5.3
pub(crate) fn hash_to_field<E, T>(data: &[u8], domain: &[u8], count: usize, l: usize) -> Result<Vec<T>>
where
    T: ToElement,
    E: super::expand_msg_xmd::ExpandMsg,
{
    let len_in_bytes = count * l;
    let random_bytes = E::expand_msg(data, domain, len_in_bytes)?;

    (0..count)
        .into_iter()
        .map(|i| T::to_element(&random_bytes[(l * i)..l * (i + 1)]))
        .collect::<Result<Vec<_>>>()
}
