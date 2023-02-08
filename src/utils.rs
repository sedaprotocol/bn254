use bn::{arith, AffineG1, Fq, Fq2, G1};
use byteorder::ByteOrder;

use crate::error::Bn254Error;

/// Function to calculate the modulus of a U256.
///
/// # Arguments
///
/// * `num` - the number we want to reduce.
/// * `modulus` - the modulus we want to apply.
///
/// # Returns
///
/// * If successful, a `U256` representing num % modulus.
pub(crate) fn mod_u256(num: arith::U256, modulus: arith::U256) -> arith::U256 {
    let mut reduced = num;
    // the library does not provide a function to do a modulo reduction
    // we use the provided add function adding a 0
    // we also need to iterate here as the library does the modulus only once
    while reduced > modulus {
        reduced.add(&arith::U256::zero(), &modulus);
    }

    reduced
}

/// Function to convert a complex coordinate (`Fq2`) to `U512`.
pub(crate) fn to_u512(coord: Fq2) -> arith::U512 {
    let c0: arith::U256 = (coord.real()).into_u256();
    let c1: arith::U256 = (coord.imaginary()).into_u256();

    arith::U512::new(&c1, &c0, &Fq::modulus())
}

/// Function to convert an arbitrary string to a point in the curve G1.
///
/// # Arguments
///
/// * `data` - A slice representing the data to be converted to a G1 point.
///
/// # Returns
///
/// * If successful, a `G1` representing the converted point.
pub(crate) fn arbitrary_string_to_g1(data: &[u8; 32]) -> Result<G1, Bn254Error> {
    let mut v = vec![0x02];
    v.extend(data);

    let point = G1::from_compressed(&v)?;

    Ok(point)
}

/// Function to obtain a private key in bytes.
pub(crate) fn fr_to_bytes(fr: bn::Fr) -> Result<Vec<u8>, Bn254Error> {
    let mut result: [u8; 32] = [0; 32];
    // to_big_endian from bn::Fr does not work here.
    fr.into_u256().to_big_endian(&mut result)?;

    Ok(result.to_vec())
}

/// Function to convert `G1` point into compressed form (`0x02` if Y is even and
/// `0x03` if Y is odd).
///
/// # Arguments
///
/// * `point` - A `G1` point.
///
/// # Returns
///
/// * If successful, a `Vec<u8>` with the compressed `G1` point.
pub(crate) fn g1_to_compressed(point: G1) -> Result<Vec<u8>, Bn254Error> {
    // From Jacobian to Affine first!
    let affine_coords = AffineG1::from_jacobian(point).ok_or(Bn254Error::PointInJacobian)?;
    // Get X coordinate
    let x = Fq::into_u256(affine_coords.x());
    // Get Y coordinate
    let y = Fq::into_u256(affine_coords.y());
    // Get parity of Y
    let parity = y.get_bit(0).ok_or(Bn254Error::IndexOutOfBounds)?;

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

/// Function to create a `PublicKey` from bytes representing a G2 point in
/// uncompressed format.
pub(crate) fn from_uncompressed_to_g2(bytes: &[u8]) -> Result<bn::G2, Bn254Error> {
    if bytes.len() != 128 {
        return Err(Bn254Error::InvalidLength {});
    }
    let x = Fq2::new(Fq::from_slice(&bytes[0..32])?, Fq::from_slice(&bytes[32..64])?);
    let y = Fq2::new(Fq::from_slice(&bytes[64..96])?, Fq::from_slice(&bytes[96..128])?);
    let g2_point = bn::AffineG2::new(x, y)?;

    Ok(g2_point.into())
}

/// Function to serialize the `PublicKey` to vector of bytes in compressed
/// format.
pub(crate) fn g2_to_compressed(g2: bn::G2) -> Result<Vec<u8>, Bn254Error> {
    let modulus = Fq::modulus();
    // From Jacobian to Affine first!
    let affine_coords = bn::AffineG2::from_jacobian(g2).ok_or(Bn254Error::PointInJacobian)?;

    // Get X real coordinate
    let x_real = Fq::into_u256(affine_coords.x().real());
    // Get X imaginary coordinate
    let x_imaginary = Fq::into_u256(affine_coords.x().imaginary());
    // Get Y and get sign
    let y = affine_coords.y();
    let y_neg = -y;
    let sign: u8 = if to_u512(y) > to_u512(y_neg) { 0x0b } else { 0x0a };

    // To U512 and its compressed representation
    let compressed = arith::U512::new(&x_imaginary, &x_real, &modulus);
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

/// Function to serialize the `PublicKey` to vector of bytes in uncompressed
/// format.
pub(crate) fn g2_to_uncompressed(g2: bn::G2) -> Result<Vec<u8>, Bn254Error> {
    // From Jacobian to Affine first!
    let affine_coords = bn::AffineG2::from_jacobian(g2).ok_or(Bn254Error::PointInJacobian)?;
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
