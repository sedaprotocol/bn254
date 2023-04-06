use bn::{
    arith::{U256, U512},
    G1,
    G2,
    *,
};
use borsh::BorshSerialize;
use byteorder::ByteOrder;

use crate::{
    error::{Error, Result},
    hash::hash_to_try_and_increment,
    PublicKey,
    Signature,
};

/// Function to calculate the modulus of a [U256].
///
/// # Arguments
///
/// * `num` - the number we want to reduce.
/// * `modulus` - the modulus we want to apply.
///
/// # Returns
///
/// * If successful, a [U256] representing num % modulus.
pub(crate) fn mod_u256(num: U256, modulus: U256) -> U256 {
    let mut reduced = num;
    // the library does not provide a function to do a modulo reduction
    // we use the provided add function adding a 0
    // we also need to iterate here as the library does the modulus only once
    while reduced > modulus {
        reduced.add(&U256::zero(), &modulus);
    }

    reduced
}

/// Function to convert a complex coordinate ([Fq2]) to [U512].
pub(crate) fn to_u512(coord: Fq2) -> U512 {
    let c0: U256 = (coord.real()).into_u256();
    let c1: U256 = (coord.imaginary()).into_u256();

    U512::new(&c1, &c0, &Fq::modulus())
}

/// Function to convert an arbitrary string to a point in the curve [G1].
///
/// # Arguments
///
/// * `data` - A slice representing the data to be converted to a [G1] point.
///
/// # Returns
///
/// * If successful, a [G1] representing the converted point.
pub(crate) fn arbitrary_string_to_g1(data: &[u8; 32]) -> Result<G1> {
    let mut v = vec![0x02];
    v.extend(data);

    let point = G1::from_compressed(&v)?;

    Ok(point)
}

/// Function to obtain a private key in bytes.
pub(crate) fn fr_to_bytes(fr: bn::Fr) -> Result<Vec<u8>> {
    let mut result: [u8; 32] = [0; 32];
    // to_big_endian from Fr does not work here.
    fr.into_u256().to_big_endian(&mut result)?;

    Ok(result.to_vec())
}

/// Function to convert [G1] point into compressed form (`0x02` if Y is even and
/// `0x03` if Y is odd).
///
/// # Arguments
///
/// * `point` - A [G1] point.
///
/// # Returns
///
/// * If successful, a `Vec<u8>` with the compressed [G1] point.
pub(crate) fn g1_to_compressed(point: G1) -> Result<Vec<u8>> {
    // From Jacobian to Affine first!
    let affine_coords = AffineG1::from_jacobian(point).ok_or(Error::PointInJacobian)?;
    // Get X coordinate
    let x = Fq::into_u256(affine_coords.x());
    // Get Y coordinate
    let y = Fq::into_u256(affine_coords.y());
    // Get parity of Y
    let parity = y.get_bit(0).ok_or(Error::IndexOutOfBounds)?;

    // Take x as big endian into slice
    let mut s = [0u8; 32];
    x.to_big_endian(&mut s)?;
    let mut result: Vec<u8> = Vec::new();
    // Push 0x02 or 0x03 depending on parity
    result.push(if parity { 3 } else { 2 });
    // Append x
    result.append(&mut s.to_vec());

    Ok(result)
}

/// Function to create a [G2] from bytes in uncompressed format.
pub(crate) fn from_uncompressed_to_g2(bytes: &[u8]) -> Result<G2> {
    if bytes.len() != 128 {
        return Err(Error::InvalidLength {});
    }
    let x = Fq2::new(Fq::from_slice(&bytes[0..32])?, Fq::from_slice(&bytes[32..64])?);
    let y = Fq2::new(Fq::from_slice(&bytes[64..96])?, Fq::from_slice(&bytes[96..128])?);
    let g2_point = AffineG2::new(x, y)?;

    Ok(g2_point.into())
}

/// Function to create a [G1] from bytes in uncompressed format.
pub(crate) fn from_uncompressed_to_g1(bytes: &[u8]) -> Result<G1> {
    if bytes.len() != 64 {
        return Err(Error::InvalidLength {});
    }
    let x = Fq::from_slice(&bytes[0..32])?;
    let y = Fq::from_slice(&bytes[32..64])?;
    let g1_point = AffineG1::new(x, y)?;
    Ok(g1_point.into())
}

/// Function to serialize the [G2] to vector of bytes in compressed format.
pub(crate) fn g2_to_compressed(g2: G2) -> Result<Vec<u8>> {
    let modulus = Fq::modulus();
    // From Jacobian to Affine first!
    let affine_coords = AffineG2::from_jacobian(g2).ok_or(Error::PointInJacobian)?;

    // Get X real coordinate
    let x_real = Fq::into_u256(affine_coords.x().real());
    // Get X imaginary coordinate
    let x_imaginary = Fq::into_u256(affine_coords.x().imaginary());
    // Get Y and get sign
    let y = affine_coords.y();
    let y_neg = -y;
    let sign: u8 = if to_u512(y) > to_u512(y_neg) { 0x0b } else { 0x0a };

    // To U512 and its compressed representation
    let compressed = U512::new(&x_imaginary, &x_real, &modulus);
    // To slice
    let mut buf: [u8; 64] = [0; (4 * 16)];
    for (l, i) in (0..4).rev().zip((0..4).map(|i| i * 16)) {
        byteorder::BigEndian::write_u128(&mut buf[i..], compressed.0[l]);
    }

    // Result = sign || compressed
    let mut result: Vec<u8> = Vec::new();
    result.push(sign);
    result.append(&mut buf.to_vec());

    Ok(result)
}

/// Function to serialize the [G2] to vector of bytes in uncompressed format.
pub(crate) fn g2_to_uncompressed(g2: G2) -> Result<Vec<u8>> {
    // From Jacobian to Affine first!
    let affine_coords = AffineG2::from_jacobian(g2).ok_or(Error::PointInJacobian)?;
    let mut result: [u8; 32 * 4] = [0; (4 * 32)];

    // Get X real coordinate
    Fq::into_u256(affine_coords.x().real()).to_big_endian(&mut result[0..32])?;

    // Get X imaginary coordinate
    Fq::into_u256(affine_coords.x().imaginary()).to_big_endian(&mut result[32..64])?;

    // Get Y real coordinate
    Fq::into_u256(affine_coords.y().real()).to_big_endian(&mut result[64..96])?;

    // Get Y imaginary coordinate
    Fq::into_u256(affine_coords.y().imaginary()).to_big_endian(&mut result[96..128])?;

    Ok(result.to_vec())
}

/// Function to serialize the [G1] to vector of bytes in uncompressed format.
pub(crate) fn g1_to_uncompressed(g1: G1) -> Result<Vec<u8>> {
    // From Jacobian to Affine first!
    let affine_coords = AffineG1::from_jacobian(g1).ok_or(Error::PointInJacobian)?;
    let mut result: [u8; 32 * 2] = [0; (2 * 32)];

    // Get X coordinate
    Fq::into_u256(affine_coords.x()).to_big_endian(&mut result[0..32])?;

    // Get Y coordinate
    Fq::into_u256(affine_coords.y()).to_big_endian(&mut result[32..64])?;

    Ok(result.to_vec())
}

/// Function to format the inputs using Borsh for a pairing check
pub fn format_pairing_check_values(
    message: Vec<u8>,
    signature: Vec<u8>,
    public_key: Vec<u8>,
) -> Result<[([u8; 64], [u8; 128]); 2]> {
    // First pairing input: e(Uncompressed H(m) on G1, Uncompressed PubKey on G2)
    let msg_hash_point = hash_to_try_and_increment(message)?;
    let msg_hash_arr: [u8; 64] = msg_hash_point.try_to_vec()?.try_into()?;
    let pk_point = PublicKey::from_compressed(public_key)?;
    let pk_arr: [u8; 128] = pk_point.0.try_to_vec()?.try_into()?;

    // Second pairing input:  e(Uncompressed Signature on G1,-G2::one())
    let sig_point = Signature::from_compressed(signature)?;
    let sig_arr: [u8; 64] = sig_point.0.try_to_vec()?.try_into()?;
    let n_g2: [u8; 128] = (-G2::one()).try_to_vec()?.try_into()?;

    Ok([(msg_hash_arr, pk_arr), (sig_arr, n_g2)])
}

pub fn format_pairing_check_uncompressed_values(
    message: Vec<u8>,
    mut signature: Vec<u8>,
    mut public_key: Vec<u8>,
) -> Result<[([u8; 64], [u8; 128]); 2]> {
    // convert to little endian
    for i in (0..=32).step_by(32) {
        signature[i..i + 32].reverse()
    }
    for i in (0..=96).step_by(32) {
        public_key[i..i + 32].reverse()
    }

    // First pairing input: e(Uncompressed H(m) on G1, Uncompressed PubKey on G2)
    let msg_hash_point = hash_to_try_and_increment(message)?;
    let msg_hash_arr: [u8; 64] = msg_hash_point.try_to_vec()?.try_into()?;
    let pk_arr: [u8; 128] = public_key.try_into()?;

    // Second pairing input:  e(Uncompressed Signature on G1,-G2::one())
    let sig_arr: [u8; 64] = signature.try_into()?;
    let n_g2: [u8; 128] = (-G2::one()).try_to_vec()?.try_into()?;

    Ok([(msg_hash_arr, pk_arr), (sig_arr, n_g2)])
}
