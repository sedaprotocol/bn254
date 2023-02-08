use bn::{arith, AffineG1, Fq, Fq2, G1};

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

/// Function to convert an arbitrary string to a point in the curve G1.
///
/// # Arguments
///
/// * `data` - A slice representing the data to be converted to a G1 point.
///
/// # Returns
///
/// * If successful, a `G1` representing the converted point.
pub(crate) fn arbitrary_string_to_g1(data: &[u8]) -> Result<G1, Bn254Error> {
    let mut v = vec![0x02];
    v.extend(data);

    let point = G1::from_compressed(&v)?;

    Ok(point)
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
pub(crate) fn to_compressed_g1(point: G1) -> Result<Vec<u8>, Bn254Error> {
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

/// Function to convert a complex coordinate (`Fq2`) to `U512`.
pub(crate) fn to_u512(coord: Fq2) -> arith::U512 {
    let c0: arith::U256 = (coord.real()).into_u256();
    let c1: arith::U256 = (coord.imaginary()).into_u256();

    arith::U512::new(&c1, &c0, &Fq::modulus())
}
