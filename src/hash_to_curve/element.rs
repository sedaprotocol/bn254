use std::ops::{Add, Mul, Neg, Sub};

use anyhow::{anyhow, Result};
use bn::{arith::U256, Fq};

#[derive(Debug, Clone, Copy)]
pub(crate) struct Element(pub(crate) Fq);

impl Element {
    #[inline]
    pub(crate) fn zero() -> Self {
        Self(Fq::zero())
    }

    #[inline]
    pub(crate) fn one() -> Self {
        Self(Fq::one())
    }

    #[inline]
    pub(crate) fn z() -> Self {
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
    pub(crate) fn c1() -> Self {
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
    pub(crate) fn c2() -> Self {
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
    pub(crate) fn c3() -> Self {
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
    pub(crate) fn c4() -> Self {
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

    fn exp_by_legendre_exp(self, other: Self) -> Self {
        let mut t8 = other.square();
        let z = other * t8;
        let mut t2 = t8 * z;
        let mut t1 = other * t2;
        let mut t3 = t8 * t1;
        let mut t9 = t2 * t3;
        let mut t6 = t2 * t9;
        let mut t18 = other * t6;
        let mut t0 = other * t18;
        let mut t19 = z * t0;
        t2 = t2 * t19;
        let mut t16 = t9 * t18;
        let mut t4 = z * t16;
        let mut t14 = t3 * t4;
        let mut t12 = t18 * t2;
        let mut t15 = t6 * t12;
        let mut t17 = t6 * t15;
        t3 = t3 * t17;
        let mut t5 = t1 * t3;
        t0 = t0 * t5;
        let mut t10 = t2 * t0;
        let mut t7 = t16 * t0;
        let mut t11 = t16 * t7;
        let mut t13 = t1 * t11;
        let mut t20 = t1 * t13;
        t2 = t8 * t20;
        t6 = t6 * t20;
        t16 = t16 * t20;
        t8 = t8 * t16;
        t1 = t1 * t16;

        (0..8).into_iter().for_each(|_| t20 = t20.square());
        t20 = t10 * t20;

        (0..10).into_iter().for_each(|_| t20 = t20.square());
        t20 = t1 * t20;

        (0..7).into_iter().for_each(|_| t20 = t20.square());
        t19 = t19 * t20;

        (0..9).into_iter().for_each(|_| t19 = t19.square());
        t18 = t18 * t19;

        (0..7).into_iter().for_each(|_| t18 = t18.square());
        t18 = t9 * t18;

        (0..14).into_iter().for_each(|_| t18 = t18.square());
        t17 = t17 * t18;

        (0..9).into_iter().for_each(|_| t17 = t17.square());
        t16 = t16 * t17;

        (0..8).into_iter().for_each(|_| t16 = t16.square());
        t15 = t15 * t16;

        (0..10).into_iter().for_each(|_| t15 = t15.square());
        t15 = t3 * t15;

        (0..5).into_iter().for_each(|_| t15 = t15.square());
        t15 = t9 * t15;

        (0..8).into_iter().for_each(|_| t15 = t15.square());
        t15 = z * t15;

        (0..12).into_iter().for_each(|_| t15 = t15.square());
        t14 = t14 * t15;

        (0..12).into_iter().for_each(|_| t14 = t14.square());
        t13 = t13 * t14;

        (0..8).into_iter().for_each(|_| t13 = t13.square());
        t12 = t12 * t13;

        (0..14).into_iter().for_each(|_| t12 = t12.square());
        t11 = t11 * t12;

        (0..9).into_iter().for_each(|_| t11 = t11.square());
        t10 = t10 * t11;

        (0..5).into_iter().for_each(|_| t10 = t10.square());
        t9 = t9 * t10;

        (0..12).into_iter().for_each(|_| t9 = t9.square());
        t8 = t8 * t9;

        (0..8).into_iter().for_each(|_| t8 = t8.square());
        t7 = t7 * t8;

        (0..11).into_iter().for_each(|_| t7 = t7.square());
        t6 = t6 * t7;

        (0..7).into_iter().for_each(|_| t6 = t6.square());
        t5 = t5 * t6;

        (0..11).into_iter().for_each(|_| t5 = t5.square());
        t4 = t4 * t5;

        (0..12).into_iter().for_each(|_| t4 = t4.square());
        t3 = t3 * t4;

        (0..9).into_iter().for_each(|_| t3 = t3.square());
        t2 = t2 * t3;

        (0..8).into_iter().for_each(|_| t2 = t2.square());
        t1 = t1 * t2;

        (0..7).into_iter().for_each(|_| t1 = t1.square());
        t0 = t0 * t1;

        (0..5).into_iter().for_each(|_| t0 = t0.square());

        z * t0
    }

    pub(crate) fn legendre(self) -> i64 {
        let l = Self::zero().exp_by_legendre_exp(self);

        if l.0.is_zero() {
            return 0;
        }

        if l.0.into_u256() == U256::from(1) {
            return 1;
        }

        -1
    }

    fn bits(self) -> Result<[u64; 4]> {
        // pain they don't have a method to get these in little endian.
        let mut bytes = Vec::new();
        self.0
            .into_u256()
            .to_big_endian(&mut bytes)
            .map_err(|err| anyhow!("{err:?}"))?;
        let mut result = bytes
            .chunks_exact(8)
            .into_iter()
            .map(|bytes| Ok(u64::from_be_bytes(bytes.try_into()?)))
            .collect::<Result<Vec<u64>>>()?;
        result.reverse();
        // Can safely unwrap here
        Ok(result.try_into().unwrap())
    }

    pub(crate) fn from_slice(bytes: &[u8]) -> Result<Self> {
        // dbg!(bytes.len());
        // dbg!(U256::from_slice(bytes));
        Ok(Self(Fq::from_slice(bytes).map_err(|err| anyhow!("{err:?}"))?))
    }

    pub(crate) fn inverse(self) -> Option<Self> {
        self.0.inverse().map(Self)
    }

    // g1Sgn0 is an algebraic substitute for the notion of sign in ordered fields
    // Namely, every non-zero quadratic residue in a finite field of characteristic
    // =/= 2 has exactly two square roots, one of each sign https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html#name-the-sgn0-function
    // The sign of an element is not obviously related to that of its Montgomery
    // form
    pub(crate) fn g1_sgn0(self) -> Result<u64> {
        let non_mont = self.bits()?;

        Ok(non_mont[0] % 2)
    }

    pub(crate) fn select(self, c: i64, x0: Self, x1: Self) -> Self {
        let cc = (c | -c) >> 63;

        todo!()
    }

    pub(crate) fn sqrt(self) -> Option<Self> {
        self.0.sqrt().map(Self)
    }

    // TODO: This seems to have an optimized algo that we should use at some point
    pub(crate) fn square(self) -> Self {
        self * self
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

impl Neg for Element {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(-self.0)
    }
}

impl Mul for Element {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}
