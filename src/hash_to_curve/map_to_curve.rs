use anyhow::{anyhow, Result};
use bn::AffineG1;

use super::element::Element;

// mapToCurve1 implements the Shallue and van de Woestijne method, applicable to
// any elliptic curve in Weierstrass form No cofactor clearing or isogeny
// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html#straightline-svdw
pub(crate) fn map_to_curve(u: Element) -> Result<AffineG1> {
    let one = Element::one();
    let z = Element::z();
    let c1 = Element::c1();
    let c2 = Element::c2();
    let c3 = Element::c3();
    let c4 = Element::c4();
    let b_curve_coeff = Element::b_curve_coeff();

    let mut tv1 = u.square();
    tv1 = tv1 * c1;
    let tv2 = one + tv1;
    tv1 = one - tv1;
    let mut tv3 = tv1 * tv2;

    tv3 = tv3.inverse().unwrap();
    let mut tv4 = u * tv1;
    tv4 = tv4 * tv3;
    tv4 = tv4 * c3;
    let x1 = c2 - tv4;

    // supposed to use square
    let mut gx1 = x1.square();
    //12. gx1 = gx1 + A     All curves in gnark-crypto have A=0 (j-invariant=0). It
    // is crucial to include this step if the curve has nonzero A coefficient.
    gx1 = gx1 * x1;
    gx1 = gx1 + b_curve_coeff;
    let gx1_not_square = gx1.legendre() >> 1;

    let x2 = c2 + tv4;
    let mut gx2 = x2.square();
    gx2 = gx2 * x2;
    gx2 = gx2 * b_curve_coeff;

    let gx2_not_square = gx2.legendre() >> 1;
    let gx1_square_or_gx2_not = gx2_not_square | !gx1_not_square;

    let mut x3 = tv2.square();
    x3 = x3 * tv3;
    x3 = x3.square();
    x3 = x3 * c4;

    x3 = x3 + z;
    let mut x = Element::zero().select(gx1_not_square, x1, x3);
    x = x.select(gx1_square_or_gx2_not, x2, x);
    let mut gx = x.square();

    gx = gx * x;
    gx = gx + b_curve_coeff;

    let mut y = gx.sqrt();
    let signs_not_equal = u.g1_sgn0()? ^ y.g1_sgn0()?;

    tv1 = -y;
    y = y.select(signs_not_equal as i64, y, tv1);

    dbg!(x.bits());
    dbg!(y.bits());
    dbg!(AffineG1::new(x.0, y.0)).map_err(|err| anyhow!("{err:?}"))
}
