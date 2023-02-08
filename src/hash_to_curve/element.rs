use std::ops::{Add, Mul, Sub};

use anyhow::{anyhow, Result};
use bn::{arith::U256, AffineG1, Fq};

use super::{hash_to_field::ToElement, map_to_curve::MapToCurve};

#[derive(Debug, Clone, Copy)]
pub struct Element(Fq);

impl Element {
    #[inline]
    fn one() -> Self {
        Self(Fq::one())
    }

    #[inline]
    fn z() -> Self {
        Self(
            Fq::from_u256(U256::from([
                15230403791020821917,
                754611498739239741,
                7381016538464732716,
                1011752739694698287,
            ]))
            .unwrap(),
        )
    }

    #[inline]
    fn c1() -> Self {
        Self(
            Fq::from_u256(U256::from([
                1248766071674976557,
                10548065924188627562,
                16242874202584236114,
                560012691975822483,
            ]))
            .unwrap(),
        )
    }

    #[inline]
    fn c2() -> Self {
        Self(
            Fq::from_u256(U256::from([
                12997850613838968789,
                14304628359724097447,
                2950087706404981016,
                1237622763554136189,
            ]))
            .unwrap(),
        )
    }

    #[inline]
    fn c3() -> Self {
        Self(
            Fq::from_u256(U256::from([
                8972444824031832946,
                5898165201680709844,
                10690697896010808308,
                824354360198587078,
            ]))
            .unwrap(),
        )
    }

    #[inline]
    fn c4() -> Self {
        Self(
            Fq::from_u256(U256::from([
                12077013577332951089,
                1872782865047492001,
                13514471836495169457,
                415649166299893576,
            ]))
            .unwrap(),
        )
    }

    fn legendre(self) -> i64 {
        let l = Self::one();
        todo!()
    }
}

pub trait Square {
    fn square(self) -> Self;
}

impl Square for Element {
    // TODO: This seems to have an optimized algo that we should use at some point
    fn square(self) -> Self {
        self * self
    }
}

pub trait Inverse {
    fn inverse(self) -> Option<Self>
    where
        Self: Sized;
}

pub trait Select {
    fn select(self, c: i64, x0: Self, x1: Self) -> Self;
}

impl Select for Element {
    fn select(self, c: i64, x0: Self, x1: Self) -> Self {
        let cc = (c | -c) >> 63;

        todo!()
    }
}

impl Inverse for Element {
    fn inverse(self) -> Option<Self>
    where
        Self: Sized,
    {
        self.0.inverse().map(Self)
    }
}

impl Add for Element {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl Sub for Element {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl Mul for Element {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl ToElement for Element {
    fn to_element(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(Self(Fq::from_slice(bytes).map_err(|err| anyhow!("{err:?}"))?))
    }
}

// mapToCurve1 implements the Shallue and van de Woestijne method, applicable to
// any elliptic curve in Weierstrass form No cofactor clearing or isogeny
// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html#straightline-svdw
impl MapToCurve for Element {
    type Output = AffineG1;

    fn map_to_curve(self) -> Result<Self::Output> {
        let one = Self::one();
        let z = Self::z();
        let c1 = Self::c1();
        let c2 = Self::c2();
        let c3 = Self::c3();
        let c4 = Self::c4();

        let mut tv1 = self.square();
        tv1 = tv1 * c1;
        let tv2 = one + tv1;
        tv1 = one - tv1;
        let mut tv3 = tv1 * tv2;

        tv3 = tv3.inverse().unwrap();
        let mut tv4 = self * tv1;
        tv4 = tv4 * tv3;
        tv4 = tv4 * c3;
        let x1 = c2 - tv4;

        // supposed to use square
        let mut gx1 = x1.square();
        //12. gx1 = gx1 + A     All curves in gnark-crypto have A=0 (j-invariant=0). It
        // is crucial to include this step if the curve has nonzero A coefficient.
        gx1 = gx1 * x1;
        gx1 = gx1 + todo!("bcurve coeff");
        let gx1_not_square = gx1.legendre() >> 1;

        let x2 = c2 + tv4;
        let mut gx2 = x2.square();
        gx2 = gx2 * x2;
        gx2 = gx2 * todo!("bcurve coeff");

        let gx2_not_square = gx2.legendre() >> 1;
        let gx1_square_or_gx2_not = gx2_not_square | !gx1_not_square;

        let mut x3 = tv2.square();
        x3 = x3 * tv3;
        x3 = x3.square();
        x3 = x3 * c4;

        x3 = x3 + z;
        let mut x = one.select(gx1_not_square, x1, x3);
        x = x.select(gx1_square_or_gx2_not, x2, x);
        let mut gx = x.square();

        gx = gx * x;
        gx = gx + todo!("bcurve coeff");

        let y: Self = todo!("sqrt gx");
        let signs_not_equal = todo!("g1Sgn0(u) ^ g1Sgn0(&y)");

        tv1 = todo!("-y");
        y = y.select(signs_not_equal, y, tv1);

        AffineG1::new(x.0, y.0).map_err(|err| anyhow!("{err:?}"))
    }
}
