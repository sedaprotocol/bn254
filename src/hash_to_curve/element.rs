use std::{
    ops::{Add, Mul, Neg, Sub},
    str::FromStr,
};

use anyhow::{anyhow, Result};
use bn::{arith::U256, Fq};
use num_bigint::BigInt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    #[inline]
    pub(crate) fn b_curve_coeff() -> Self {
        let res = Self(Fq::from_u256(U256::from([3, 0, 0, 0])).unwrap());
        res * Self::r_square()
    }

    #[inline]
    pub(crate) fn r_square() -> Self {
        Self(
            Fq::from_u256(U256::from([
                17522657719365597833,
                13107472804851548667,
                5164255478447964150,
                493319470278259999,
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

    pub(crate) fn bits(self) -> Result<[u64; 4]> {
        // pain they don't have a method to get these in little endian.
        let mut bytes = vec![0u8; 32];
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

    /// assumes 0 ⩽ v < q
    fn from_big_int_helper(int: BigInt) -> Self {
        let mut parts = [0u64; 4];
        if cfg!(target_pointer_width = "64") {
            int.iter_u64_digits()
                .enumerate()
                .for_each(|(index, u64)| parts[index] = u64);
        } else {
            todo!()
        }

        let e = Self(Fq::from_u256(U256::from(parts)).unwrap());
        e * Self::r_square()
    }

    pub(crate) fn from_big_int(int: BigInt) -> Self {
        let res = Self::zero();
        let zero_big = BigInt::from(0);
        // TODO: how to not parse this every time >.<
        let modulus =
            BigInt::parse_bytes(b"30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47", 16).unwrap();

        if int == modulus {
            res
        } else if int > zero_big && int < modulus {
            // checks 0 ⩽ v < q
            Self::from_big_int_helper(int)
        } else {
            let vv = int % modulus;
            Self::from_big_int(vv)
        }
    }

    pub(crate) fn from_slice<T: AsRef<[u8]>>(bytes: T) -> Result<Self> {
        Ok(Self(Fq::from_slice(bytes.as_ref()).map_err(|err| anyhow!("{err:?}"))?))
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

    // If c = 0, x0 else x1
    pub(crate) fn select(self, c: i64, x0: Self, x1: Self) -> Self {
        if c == 0 { x0 } else { x1 }

        // This is how I saw it implemented  but... seems overly complex
        // let mut parts = [0u64; 4];
        // let cc = ((c | -c) >> 63) as u64;
        // let x0 = x0.bits().unwrap();
        // let x1 = x1.bits().unwrap();

        // parts[0] = x0[0] & cc & (x0[0] & x1[0]);
        // parts[1] = x0[1] & cc & (x0[1] & x1[1]);
        // parts[2] = x0[2] & cc & (x0[2] & x1[2]);
        // parts[3] = x0[3] & cc & (x0[3] & x1[3]);
        // Self(Fq::from_u256(U256::from(parts)).unwrap())
    }

    // Sqrt z = √x (mod q)
    // if the square root doesn't exist (x is not a square mod q)
    // returns self
    pub(crate) fn sqrt(self) -> Self {
        if let Some(sqrt) = self.0.sqrt() {
            Self(sqrt)
        } else {
            self
        }
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
