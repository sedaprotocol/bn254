// Copyright 2015-2018 Parity Technologies (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

extern crate bn;
extern crate rustc_hex;

use std::io::{self, Read};
use bn::Group;

#[derive(Debug)]
pub struct Error(pub &'static str);

impl From<&'static str> for Error {
    fn from(val: &'static str) -> Self {
        Error(val)
    }
}

fn read_fr(scalar: &[u8]) -> Result<::bn::Fr, Error> {
    ::bn::Fr::from_slice(&scalar[0..32]).map_err(|_| Error::from("Invalid field element"))
}

fn read_point(xCord: &[u8], yCord: &[u8]) -> Result<::bn::G1, Error> {
    use bn::{AffineG1, Fq, Group, G1};
    let px = Fq::from_slice(xCord).map_err(|_| Error::from("Invalid point x coordinate"))?;
    let py = Fq::from_slice(yCord).map_err(|_| Error::from("Invalid point x coordinate"))?;
    Ok(if px == Fq::zero() && py == Fq::zero() {
        G1::zero()
    } else {
        AffineG1::new(px, py)
            .map_err(|_| Error::from("Invalid curve point"))?
            .into()
    })
}

// TODO: doc
pub fn bn128_derive_pk(sk: &[u8],  output: &mut [u8; 128]) -> Result<(), Error> {
    use bn::AffineG1;

//    let p = read_point(xCord, yCord)?;
    let fr = read_fr(&sk)?;
//    let pk = bn::G2::one() * fr;

//    let affine_coords = bn::AffineG2::from_jacobian(pk).ok_or(Error::from("Error while converting to affine"))?;

    let mut write_buf = [0u8; 128];
    if let Some(mul) = bn::AffineG2::from_jacobian(bn::G2::one() * fr) {
        // point not at infinity
        mul.x().imaginary()
            .to_big_endian(&mut write_buf[0..32])
            .expect("Cannot fail since 0..32 is 32-byte length");
        mul.x().real()
            .to_big_endian(&mut write_buf[32..64])
            .expect("Cannot fail since 32..64 is 32-byte length");
        mul.y().imaginary()
            .to_big_endian(&mut write_buf[64..96])
            .expect("Cannot fail since 0..32 is 32-byte length");
        mul.y().real()
            .to_big_endian(&mut write_buf[96..128])
            .expect("Cannot fail since 32..64 is 32-byte length");
    }
    *output = write_buf;

    Ok(())
}

// Can fail if any of the 2 points does not belong the bn128 curve
pub fn bn128_add(xCord1: &[u8], yCord1: &[u8], xCord2: &[u8], yCord2: &[u8],  output: &mut [u8; 64]) -> Result<(), Error> {
    use bn::AffineG1;

    let p1 = read_point(xCord1,yCord1)?;
    let p2 = read_point(xCord2, yCord2)?;

    let mut write_buf = [0u8; 64];
    if let Some(sum) = AffineG1::from_jacobian(p1 + p2) {
        // point not at infinity
        sum.x()
            .to_big_endian(&mut write_buf[0..32])
            .expect("Cannot fail since 0..32 is 32-byte length");
        sum.y()
            .to_big_endian(&mut write_buf[32..64])
            .expect("Cannot fail since 32..64 is 32-byte length");
    }
    *output = write_buf;

    Ok(())
}

// Can fail if first paramter (bn128 curve point) does not actually belong to the curve
pub fn bn128_mul(xCord: &[u8], yCord: &[u8], scalar: &[u8],  output: &mut [u8; 64]) -> Result<(), Error> {
    use bn::AffineG1;

    let p = read_point(xCord, yCord)?;
    let fr = read_fr(&scalar)?;

    let mut write_buf = [0u8; 64];
    if let Some(sum) = AffineG1::from_jacobian(p * fr) {
        // point not at infinity
        sum.x()
            .to_big_endian(&mut write_buf[0..32])
            .expect("Cannot fail since 0..32 is 32-byte length");
        sum.y()
            .to_big_endian(&mut write_buf[32..64])
            .expect("Cannot fail since 32..64 is 32-byte length");
    }
    *output = write_buf;

    Ok(())
}

/// Can fail if:
///     - input length is not a multiple of 192
///     - any of odd points does not belong to bn128 curve
///     - any of even points does not belong to the twisted bn128 curve over the field F_p^2 = F_p[i] / (i^2 + 1)
pub fn bn128_pairing(input: &[u8], output: &mut [u8; 32]) -> Result<(), Error> {

    println!("----------------------------------------------");
    println!("input length: {:?} bytes", input.len());
    println!("input data: {:?}", hex::encode(input));


    use bn::{pairing_batch, AffineG1, AffineG2, Fq, Fq2, Group, Gt, G1, G2};

    if input.len() % 192 != 0 {
        return Err("Invalid input length, must be multiple of 192 (3 * (32*2))".into());
    }

    let elements = input.len() / 192; // (a, b_a, b_b - each 64-byte affine coordinates)
    println!("no. elements: {:?}", elements);

    let ret_val = if input.len() == 0 {
        bn::arith::U256::one()
    } else {
        let mut vals = Vec::new();
        for idx in 0..elements {
            println!("\n Tuple #{:?}", idx);

            println!("\t a_x:   {:?}", hex::encode(&input[idx * 192..idx * 192 + 32]));
            let a_x = Fq::from_slice(&input[idx * 192..idx * 192 + 32])
                .map_err(|_| Error::from("Invalid a argument x coordinate"))?;

            println!("\t a_y:   {:?}", hex::encode(&input[idx * 192 + 32..idx * 192 + 64]));
            let a_y = Fq::from_slice(&input[idx * 192 + 32..idx * 192 + 64])
                .map_err(|_| Error::from("Invalid a argument y coordinate"))?;

            println!("\t b_a_y: {:?}", hex::encode(&input[idx * 192 + 64..idx * 192 + 96]));
            let b_a_y = Fq::from_slice(&input[idx * 192 + 64..idx * 192 + 96])
                .map_err(|_| Error::from("Invalid b argument imaginary coeff x coordinate"))?;

            println!("\t b_a_x: {:?}", hex::encode(&input[idx * 192 + 96..idx * 192 + 128]));
            let b_a_x = Fq::from_slice(&input[idx * 192 + 96..idx * 192 + 128])
                .map_err(|_| Error::from("Invalid b argument imaginary coeff y coordinate"))?;

            println!("\t b_b_y: {:?}", hex::encode(&input[idx * 192 + 128..idx * 192 + 160]));
            let b_b_y = Fq::from_slice(&input[idx * 192 + 128..idx * 192 + 160])
                .map_err(|_| Error::from("Invalid b argument real coeff x coordinate"))?;

            println!("\t b_b_x: {:?}", hex::encode(&input[idx * 192 + 160..idx * 192 + 192]));
            let b_b_x = Fq::from_slice(&input[idx * 192 + 160..idx * 192 + 192])
                .map_err(|_| Error::from("Invalid b argument real coeff y coordinate"))?;

            let b_a = Fq2::new(b_a_x, b_a_y);
            let b_b = Fq2::new(b_b_x, b_b_y);
            let b = if b_a.is_zero() && b_b.is_zero() {
                println!("---------------------------------- B in G2 is ZERO -----------------");
                G2::zero()
            } else {
                G2::from(
                    AffineG2::new(b_a, b_b)
                        .map_err(|_| Error::from("Invalid b argument - not on curve"))?,
                )
            };
            let a = if a_x.is_zero() && a_y.is_zero() {
                println!("---------------------------------- A in G1 is ZERO -----------------");
                G1::zero()
            } else {
                G1::from(
                    AffineG1::new(a_x, a_y)
                        .map_err(|_| Error::from("Invalid a argument - not on curve"))?,
                )
            };
            vals.push((a, b));
        }

        let mul = pairing_batch(&vals);

        if mul == Gt::one() {
            bn::arith::U256::one()
        } else {
            bn::arith::U256::zero()
        }
    };

    ret_val
        .to_big_endian(output)
        .expect("Cannot fail since 0..32 is 32-byte length");

    println!("----------------------------------------------");


    Ok(())
}

#[cfg(test)]
mod tests {
    use rustc_hex::FromHex;
    use std::fs::File;
    use serde_json::{json, Value};
    use super::{bn128_add, bn128_mul, bn128_pairing};
    use crate::bn128::bn128_eth::{bn128_derive_pk, read_fr};
    use bn::{Group, pairing_batch, Gt};

    fn bytes(s: &'static str) -> Vec<u8> {
        FromHex::from_hex(s).expect("static str should contain valid hex bytes")
    }

    fn pairing_empty_test(expected: Vec<u8>) {
        let empty_input = [0u8; 0];
        let mut output = [0u8; 32];

        bn128_pairing(&empty_input[..], &mut output).expect("Builtin should not fail");
        assert_eq!(output.to_vec(), expected);
    }

    fn pairing_error_test(input: &[u8], msg_contains: Option<&str>) {
        let mut output = [0u8; 32];
        let res = bn128_pairing(input, &mut output);
        if let Some(msg) = msg_contains {
            if let Err(e) = res {
                if !e.0.contains(msg) {
                    panic!(
                        "There should be error containing '{}' here, but got: '{}'",
                        msg, e.0
                    );
                }
            }
        } else {
            assert!(res.is_err(), "There should be built-in error here");
        }
    }

    #[test]
    fn test_bn128_add() {
        // zero-points additions
        {
            let x1 = FromHex::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000000"
            ).unwrap();
            let y1 = FromHex::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000000"
            ).unwrap();
            let x2 = FromHex::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000000"
            ).unwrap();
            let y2 = FromHex::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000000"
            ).unwrap();
                 
                

            let mut output = [0u8; 64];
            let expected = FromHex::from_hex(
                "\
                 0000000000000000000000000000000000000000000000000000000000000000\
                 0000000000000000000000000000000000000000000000000000000000000000",
            )
                .unwrap();

            bn128_add(&x1, &y1, &x2, &y2, &mut output).expect("Builtin should not fail");
            assert_eq!(output.to_vec(), expected);
        }
        // should fail - point not on curve
        {
            let x1 = FromHex::from_hex(
                "1111111111111111111111111111111111111111111111111111111111111111"
            ).unwrap();
            let y1 = FromHex::from_hex(
                "1111111111111111111111111111111111111111111111111111111111111111"
            ).unwrap();
            let x2 = FromHex::from_hex(
                "1111111111111111111111111111111111111111111111111111111111111111"
            ).unwrap();
            let y2 = FromHex::from_hex(
                "1111111111111111111111111111111111111111111111111111111111111111"
            ).unwrap();

            let mut output = [0u8; 64];

            let res = bn128_add(&x1, &y1, &x2, &y2, &mut output);
            assert!(res.is_err(), "There should be built-in error here");
        }
    }

    #[test]
    fn test_bn128_mul() {
        // zero-point multiplication
        {
            let x = FromHex::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000000"
            ).unwrap();
            let y = FromHex::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000000"
            ).unwrap();
            let scalar = FromHex::from_hex(
                "0200000000000000000000000000000000000000000000000000000000000000"
            ).unwrap();

            let mut output = [0u8; 64];
            let expected = FromHex::from_hex(
                "\
                 0000000000000000000000000000000000000000000000000000000000000000\
                 0000000000000000000000000000000000000000000000000000000000000000",
            )
                .unwrap();

            bn128_mul(&x, &y, &scalar, &mut output).expect("Builtin should not fail");
            assert_eq!(output.to_vec(), expected);
        }

        // should fail - point not on curve
        {
            let x = FromHex::from_hex(
                "1111111111111111111111111111111111111111111111111111111111111111"
            ).unwrap();
            let y = FromHex::from_hex(
                "1111111111111111111111111111111111111111111111111111111111111111"
            ).unwrap();
            let scalar = FromHex::from_hex(
                "0f00000000000000000000000000000000000000000000000000000000000000"
            ).unwrap();

            let mut output = [0u8; 64];

            let res = bn128_mul(&x, &y, &scalar, &mut output);
            assert!(res.is_err(), "There should be built-in error here");
        }
    }

    #[test]
    // should pass (multi-point example taken from ethereum test case 'pairingTest')
    fn bn128_pairing_multi_point() {
        let pairing_input = FromHex::from_hex("\
            2eca0c7238bf16e83e7a1e6c5d49540685ff51380f309842a98561558019fc02\
            03d3260361bb8451de5ff5ecd17f010ff22f5c31cdf184e9020b06fa5997db84\
            1213d2149b006137fcfb23036606f848d638d576a120ca981b5b1a5f9300b3ee\
            2276cf730cf493cd95d64677bbb75fc42db72513a4c1e387b476d056f80aa75f\
            21ee6226d31426322afcda621464d0611d226783262e21bb3bc86b537e986237\
            096df1f82dff337dd5972e32a8ad43e28a78a96a823ef1cd4debe12b6552ea5f\
            06967a1237ebfeca9aaae0d6d0bab8e28c198c5a339ef8a2407e31cdac516db9\
            22160fa257a5fd5b280642ff47b65eca77e626cb685c84fa6d3b6882a283ddd1\
            198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2\
            1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed\
            090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b\
            12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa").unwrap();
        let mut output = [0u8; 32];
        let mut output_expected = [0u8; 32];
        output_expected[31] = 1u8;
        bn128_pairing(&pairing_input, &mut output).expect("pairing check failed");
        assert!(
            output_expected == output,
            "pairing check did not evaluate to 1"
        );
    }

    #[test]
    fn bn128_pairing_empty() {
        // should not fail, because empty input is a valid input of 0 elements
        pairing_empty_test(bytes(
            "0000000000000000000000000000000000000000000000000000000000000001",
        ));
    }

    #[test]
    fn bn128_pairing_notcurve() {
        // should fail - point not on curve
        pairing_error_test(
            &bytes(
                "\
                 1111111111111111111111111111111111111111111111111111111111111111\
                 1111111111111111111111111111111111111111111111111111111111111111\
                 1111111111111111111111111111111111111111111111111111111111111111\
                 1111111111111111111111111111111111111111111111111111111111111111\
                 1111111111111111111111111111111111111111111111111111111111111111\
                 1111111111111111111111111111111111111111111111111111111111111111",
            ),
            Some("not on curve"),
        );
    }

    #[test]
    fn bn128_pairing_fragmented() {
        // should fail - input length is invalid
        pairing_error_test(
            &bytes(
                "\
                 1111111111111111111111111111111111111111111111111111111111111111\
                 1111111111111111111111111111111111111111111111111111111111111111\
                 111111111111111111111111111111",
            ),
            Some("Invalid input length"),
        );
    }

    #[test]
    fn test_bn128_add_ethereum_json() {
      let file = File::open("./src/bn256.json").expect("File should open read only");
      let json: Value = serde_json::from_reader(file).expect("File should be proper JSON");
      let adds = json["add"].as_array().expect("File should have priv key");
      for (i, elem) in adds.iter().enumerate() {
        println!("Test number {}:", i);
        let mut output = [0u8; 64];
        let x1 = FromHex::from_hex(elem.get("x1").unwrap().as_str().unwrap()).unwrap();
        let y1 = FromHex::from_hex(elem.get("y1").unwrap().as_str().unwrap()).unwrap();
        let x2 = FromHex::from_hex(elem.get("x2").unwrap().as_str().unwrap()).unwrap();
        let y2 = FromHex::from_hex(elem.get("y2").unwrap().as_str().unwrap()).unwrap();
        let expected = FromHex::from_hex(elem.get("result").unwrap().as_str().unwrap()).unwrap();
        bn128_add(&x1, &y1, &x2, &y2, &mut output).expect("Builtin should not fail");
        assert_eq!(output.to_vec(), expected);
      };
    }

    #[test]
    fn test_bn128_mul_ethereum_json() {
      let file = File::open("./src/bn256.json").expect("File should open read only");
      let json: Value = serde_json::from_reader(file).expect("File should be proper JSON");
      let adds = json["mul"].as_array().expect("File should have priv key");
      for (i, elem) in adds.iter().enumerate() {
        println!("Test number {}:", i);
        let mut output = [0u8; 64];
        let x = FromHex::from_hex(elem.get("x").unwrap().as_str().unwrap()).unwrap();
        let y = FromHex::from_hex(elem.get("y").unwrap().as_str().unwrap()).unwrap();
        let scalar = FromHex::from_hex(elem.get("scalar").unwrap().as_str().unwrap()).unwrap();
        let expected = FromHex::from_hex(elem.get("result").unwrap().as_str().unwrap()).unwrap();
        bn128_mul(&x, &y, &scalar, &mut output).expect("Builtin should not fail");
        assert_eq!(output.to_vec(), expected);
      };
    }   

    #[test]
    fn test_bn128_mul_ethereum() {
        let x = FromHex::from_hex(
                "2bd3e6d0f3b142924f5ca7b49ce5b9d54c4703d7ae5648e61d02268b1a0a9fb7"
            ).unwrap();
            let y = FromHex::from_hex(
                "21611ce0a6af85915e2f1d70300909ce2e49dfad4a4619c8390cae66cefdb204"
            ).unwrap();
            let scalar = FromHex::from_hex(
                "00000000000000000000000000000000000000000000000011138ce750fa15c2"
            ).unwrap();

        let mut output = [0u8; 64];
        let expected = FromHex::from_hex(
            "\
             070a8d6a982153cae4be29d434e8faef8a47b274a053f5a4ee2a6c9c13c31e5c\
             031b8ce914eba3a9ffb989f9cdd5b0f01943074bf4f0f315690ec3cec6981afc",
        )
            .unwrap();

        bn128_mul(&x, &y, &scalar, &mut output).expect("Builtin should not fail");
        assert_eq!(output.to_vec(), expected);
    }

    // Test extracted from https://asecuritysite.com/encryption/go_bn256
    #[test]
    fn test_bn128_derive_pk() {
        let sk = FromHex::from_hex(
            "0f6b8785374476a3b3e4bde2c64dfb12964c81c7930d32367c8e318609387872"
        ).unwrap();

        let mut output = [0u8; 128];
        let expected = FromHex::from_hex(
            "\
             1bab5671c5107de67fe06007dde240a84674c8ff13eeac6d64bad0caf2cfe53e\
             270567a05b56b02e813281d554f46ce0c1b742b622652ef5a41d69afb6eb8338\
             02b54a5deaaf86dc7f03d080c8373d62f03b3be06dac42b2d9426a8ebd0caf4a\
             0142f4e04fc1402e17ae7e624fd9bd15f1eae0a1d8eda4e26ab70fd4cd793338",
        ).unwrap();

        bn128_derive_pk(&sk, &mut output).expect("Builtin should not fail");
        assert_eq!(output.to_vec(), expected);
    }

    // Test extracted from https://asecuritysite.com/encryption/go_bn256
    #[test]
    fn test_bn128_sign_g1_one() {
        let sk = FromHex::from_hex(
            "0f6b8785374476a3b3e4bde2c64dfb12964c81c7930d32367c8e318609387872"
        ).unwrap();

        let mut public_key = [0u8; 128];
        let expected = FromHex::from_hex(
            "\
             1bab5671c5107de67fe06007dde240a84674c8ff13eeac6d64bad0caf2cfe53e\
             270567a05b56b02e813281d554f46ce0c1b742b622652ef5a41d69afb6eb8338\
             02b54a5deaaf86dc7f03d080c8373d62f03b3be06dac42b2d9426a8ebd0caf4a\
             0142f4e04fc1402e17ae7e624fd9bd15f1eae0a1d8eda4e26ab70fd4cd793338",
        ).unwrap();

        bn128_derive_pk(&sk, &mut public_key).expect("Builtin should not fail");
        assert_eq!(public_key.to_vec(), expected);

        // If H(m) = G1 then...
        // e(H(m), PublicKey) = e(Signature, G2)
        // e(G1, PublicKey) = e(sign(G1), G2)
        // e(G1, SecretKey * G2) = e(SecretKey * G1, G2) holds!!!

        // Signature (multiplication)
        let fr = read_fr(&sk).unwrap();
        let mut sign_bytes = [0u8; 64];
        if let Some(mul) = bn::AffineG1::from_jacobian(bn::G1::one() * fr) {
            // point not at infinity
            mul.x()
                .to_big_endian(&mut sign_bytes[0..32])
                .expect("Cannot fail since 0..32 is 32-byte length");
            mul.y()
                .to_big_endian(&mut sign_bytes[32..64])
                .expect("Cannot fail since 32..64 is 32-byte length");
        }

        // G1 into bytes
        let mut g1_bytes = [0u8; 64];
        if let Some(g1) = bn::AffineG1::from_jacobian(bn::G1::one()) {
            // point not at infinity
            g1.x()
                .to_big_endian(&mut g1_bytes[0..32])
                .expect("Cannot fail since 0..32 is 32-byte length");
            g1.y()
                .to_big_endian(&mut g1_bytes[32..64])
                .expect("Cannot fail since 32..64 is 32-byte length");
        }

        // G2 into bytes
        let mut g2_bytes = [0u8; 128];
        if let Some(g2) = bn::AffineG2::from_jacobian(bn::G2::one()) {
            // point not at infinity
            g2.x().imaginary()
                .to_big_endian(&mut g2_bytes[0..32])
                .expect("Cannot fail since 0..32 is 32-byte length");
            g2.x().real()
                .to_big_endian(&mut g2_bytes[32..64])
                .expect("Cannot fail since 32..64 is 32-byte length");
            g2.y().imaginary()
                .to_big_endian(&mut g2_bytes[64..96])
                .expect("Cannot fail since 0..32 is 32-byte length");
            g2.y().real()
                .to_big_endian(&mut g2_bytes[96..128])
                .expect("Cannot fail since 32..64 is 32-byte length");
        }

        // Verify BLS concatenating BLS pairing inputs
        // e(H(m), PublicKey) = e(Signature, G2)
        let mut pairing_input = vec![];
        pairing_input.extend_from_slice(&g1_bytes);
        pairing_input.extend_from_slice(&public_key);
        assert_eq!(pairing_input.len(), 192);
        pairing_input.extend_from_slice(&sign_bytes);
        pairing_input.extend_from_slice(&g2_bytes);
        assert_eq!(pairing_input.len(), 192*2);

        let mut output = [0u8; 32];
        let mut output_expected = [0u8; 32];
        output_expected[31] = 1u8;
        bn128_pairing(&pairing_input, &mut output).expect("pairing check failed");
//        assert_eq!(
//            output_expected,
//            output,
//            "pairing check did not evaluate to 1"
//        );

        let secret_key_scalar = read_fr(&sk).unwrap();

        let public_key_point = bn::G2::one() * secret_key_scalar;
        let pairing1 = bn::pairing(bn::G1::one(), public_key_point);

        let signature_point = bn::G1::one() * secret_key_scalar;
        let pairing2 = bn::pairing(signature_point, bn::G2::one());

        println!("------------ verification 1: {:?}", pairing1 == pairing2);
        assert!(pairing1 == pairing2);

        let batch = pairing_batch(&[
            (bn::G1::one(), public_key_point),
            (-signature_point, bn::G2::one())
        ]);

        println!("------------ verification 2: {:?}", batch == bn::Gt::one());
        // TODO: uncomment
        assert!(batch == bn::Gt::one());

//        assert!(false);
    }

    #[test]
    // Working pairing function with previous example of G1
    fn bn128_pairing_multi_point_generator_g1() {
//        let pairing_input = FromHex::from_hex("000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000021bab5671c5107de67fe06007dde240a84674c8ff13eeac6d64bad0caf2cfe53e270567a05b56b02e813281d554f46ce0c1b742b622652ef5a41d69afb6eb833802b54a5deaaf86dc7f03d080c8373d62f03b3be06dac42b2d9426a8ebd0caf4a0142f4e04fc1402e17ae7e624fd9bd15f1eae0a1d8eda4e26ab70fd4cd793338224ba482819606b6196afd4317ffde4fa955780c78f1cea19f66358c37bafb2127705440408e330a2f7185f5e4b88f69e651dd888e27c34f78978163f088ec79198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa").unwrap();

        println!("-------------- PAIRING 1 --------------");

        let g1 = bn::AffineG1::from_jacobian(bn::G1::one()).unwrap();
        let mut g1_bytes_x = [0; 32];
        g1.x().to_big_endian(&mut g1_bytes_x);
        println!("g1_x:\t\t {:?}", hex::encode(g1_bytes_x));
        let mut g1_bytes_y = [0; 32];
        g1.y().to_big_endian(&mut g1_bytes_y);
        println!("g1_y:\t\t {:?}", hex::encode(g1_bytes_y));

        let priv_key = FromHex::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ).unwrap();
        let fr = read_fr(&priv_key).unwrap();
        let public_key = bn::AffineG2::from_jacobian(bn::G2::one() * fr).unwrap();
        let mut pk_bytes_x_im = [0; 32];
        public_key.x().imaginary().to_big_endian(&mut pk_bytes_x_im);
        println!("pk_x_im:\t {:?}", hex::encode(pk_bytes_x_im));
        let mut pk_bytes_x_real = [0; 32];
        public_key.x().real().to_big_endian(&mut pk_bytes_x_real);
        println!("pk_x_real:\t {:?}", hex::encode(pk_bytes_x_real));
        let mut pk_bytes_y_im = [0; 32];
        public_key.y().imaginary().to_big_endian(&mut pk_bytes_y_im);
        println!("pk_y_im:\t {:?}", hex::encode(pk_bytes_y_im));
        let mut pk_bytes_y_real = [0; 32];
        public_key.y().real().to_big_endian(&mut pk_bytes_y_real);
        println!("pk_y_real:\t {:?}", hex::encode(pk_bytes_y_real));

        println!("-------------- PAIRING 2 --------------");

        // TODO: AQQQQQUIII ESTA EL MEOLLO DEL ASUNTO!... NEGAR el pairing 2!!!!
        let sign = bn::AffineG1::from_jacobian(-(bn::G1::one() * fr)).unwrap();
        let mut sign_bytes_x = [0; 32];
        sign.x().to_big_endian(&mut sign_bytes_x);
        println!("sign_x:\t\t {:?}", hex::encode(sign_bytes_x));
        let mut sign_bytes_y = [0; 32];
        sign.y().to_big_endian(&mut sign_bytes_y);
        println!("sign_y:\t\t {:?}", hex::encode(sign_bytes_y));

        let g2 = bn::AffineG2::from_jacobian(bn::G2::one()).unwrap();
        let mut g2_bytes_x_im = [0; 32];
        let g2_x_im = g2.x().imaginary().to_big_endian(&mut g2_bytes_x_im);
        println!("g2_x_im:\t {:?}", hex::encode(g2_bytes_x_im));
        let mut g2_bytes_x_real = [0; 32];
        let g2_x_real = g2.x().real().to_big_endian(&mut g2_bytes_x_real);
        println!("g2_x_real:\t {:?}", hex::encode(g2_bytes_x_real));
        let mut g2_bytes_y_im = [0; 32];
        g2.y().imaginary().to_big_endian(&mut g2_bytes_y_im);
        println!("pk_y_im:\t {:?}", hex::encode(g2_bytes_y_im));
        let mut g2_bytes_y_real = [0; 32];
        g2.y().real().to_big_endian(&mut g2_bytes_y_real);
        println!("pk_y_real:\t {:?}", hex::encode(g2_bytes_y_real));

        println!("---------------- INPUT ----------------");
        let mut pairing_input = vec![];
        pairing_input.extend_from_slice(&g1_bytes_x);
        pairing_input.extend_from_slice(&g1_bytes_y);
        pairing_input.extend_from_slice(&pk_bytes_x_im);
        pairing_input.extend_from_slice(&pk_bytes_x_real);
        pairing_input.extend_from_slice(&pk_bytes_y_im);
        pairing_input.extend_from_slice(&pk_bytes_y_real);
        pairing_input.extend_from_slice(&sign_bytes_x);
        pairing_input.extend_from_slice(&sign_bytes_y);
        pairing_input.extend_from_slice(&g2_bytes_x_im);
        pairing_input.extend_from_slice(&g2_bytes_x_real);
        pairing_input.extend_from_slice(&g2_bytes_y_im);
        pairing_input.extend_from_slice(&g2_bytes_y_real);

        println!("data: {:?}", hex::encode(&pairing_input));
        println!("length: {:?}", pairing_input.len());

        println!("----------------------------------------");

        let mut output = [0u8; 32];
        let mut output_expected = [0u8; 32];
        output_expected[31] = 1u8;
        bn128_pairing(&pairing_input, &mut output).expect("pairing check failed");
        assert!(
            output_expected == output,
            "pairing check did not evaluate to 1"
        );
    }

    #[test]
    // Source: https://github.com/ethereum/go-ethereum/blob/7b189d6f1f7eedf46c6607901af291855b81112b/core/vm/contracts_test.go
    fn bn128_pairing_multi_point_geth_1() {
        let pairing_input = FromHex::from_hex("\
            0000000000000000000000000000000000000000000000000000000000000001\
            0000000000000000000000000000000000000000000000000000000000000002\
            198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2\
            1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed\
            090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b\
            12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa\
            0000000000000000000000000000000000000000000000000000000000000001\
            0000000000000000000000000000000000000000000000000000000000000002\
            198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2\
            1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed\
            275dc4a288d1afb3cbb1ac09187524c7db36395df7be3b99e673b13a075a65ec\
            1d9befcd05a5323e6da4d435f3b617cdb3af83285c2df711ef39c01571827f9d").unwrap();
        let mut output = [0u8; 32];
        let mut output_expected = [0u8; 32];
        output_expected[31] = 1u8;
        bn128_pairing(&pairing_input, &mut output).expect("pairing check failed");
        assert!(
            output_expected == output,
            "pairing check did not evaluate to 1"
        );
    }

}
