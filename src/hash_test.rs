use bn::{arith, Fq};

use crate::{
    hash::{hash_to_try_and_increment, LAST_MULTIPLE_OF_FQ_MODULUS_LOWER_THAN_2_256},
    utils,
};

/// Test for the `hash_to_try_and_increment` function with own test vector
#[test]
fn test_hash_to_try_and_increment_1() {
    // Data to be hashed with TAI (ASCII "sample")
    let data = hex::decode("73616d706c65").unwrap();
    let hash_point = hash_to_try_and_increment(&data).unwrap();
    let hash_bytes = utils::g1_to_compressed(hash_point).unwrap();

    let expected_hash = "0211e028f08c500889891cc294fe758a60e84495ec1e2d0bce208c9fc67b6486fd";
    assert_eq!(hex::encode(hash_bytes), expected_hash);
}

/// Test for the `hash_to_try_and_increment` function with own test vector
#[test]
fn test_hash_to_try_and_increment_2() {
    // Data to be hashed with TAI (ASCII "hello")
    let data = hex::decode("68656c6c6f").unwrap();
    let hash_point = hash_to_try_and_increment(&data).unwrap();
    let hash_bytes = utils::g1_to_compressed(hash_point).unwrap();

    let expected_hash = "0200b201235f522abbd3863b7496dfa213be0ed1f4c7a22196d8afddec7e64c8ec";
    assert_eq!(hex::encode(hash_bytes), expected_hash);
}

/// Test for the `hash_to_try_and_increment` valid range
#[test]
fn test_hash_to_try_valid_range() {
    let modulus = Fq::modulus();
    let mut last_multiple = arith::U256([5, 0]);
    let mut overflow_multiple = arith::U256([6, 0]);
    let max_value = arith::U256([0xffffffffffffffffffffffffffffffff, 0xffffffffffffffffffffffffffffffff]);
    last_multiple.mul(&modulus, &max_value, 1);
    assert_eq!(last_multiple, LAST_MULTIPLE_OF_FQ_MODULUS_LOWER_THAN_2_256);
    overflow_multiple.mul(&modulus, &max_value, 1);
    assert!(overflow_multiple < modulus)
}
