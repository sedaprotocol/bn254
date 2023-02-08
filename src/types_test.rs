/// Test vectors taken from https://asecuritysite.com/encryption/go_bn256.
/// The public keys in G2 are changed in order in the website, i.e., imaginary
/// goes first.
///
/// In order to construct the test vectors we need to do the following:
/// - Get the modulus of Fq
/// - Get the components (real, imaginary) of x and y
/// - Perform (imaginary*modulus) + real
/// - Compress with 0x0a or 0x0b depending on the value of y
use super::*;

#[test]
fn test_valid_private_key() {
    let compressed = hex::decode("023aed31b5a9e486366ea9988b05dba469c6206e58361d9c065bbea7d928204a").unwrap();
    let private_key = PrivateKey::new(&compressed.as_slice());
    assert_eq!(private_key.is_err(), false);
    assert_eq!(private_key.unwrap().to_bytes().unwrap(), compressed);
}

#[test]
fn test_invalid_private_key_1() {
    let compressed = hex::decode(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .unwrap();
    let private_key = PrivateKey::new(&compressed.as_slice());
    assert_eq!(private_key.is_err(), true);
}

#[test]
fn test_invalid_private_key_2() {
    let compressed = hex::decode("aaaa").unwrap();
    let private_key = PrivateKey::new(&compressed.as_slice());
    assert_eq!(private_key.is_err(), true);
}

#[test]
fn test_compressed_public_key_1() {
    let compressed = hex::decode("0a023aed31b5a9e486366ea9988b05dba469c6206e58361d9c065bbea7d928204a761efc6e4fa08ed227650134b52c7f7dd0463963e8a4bf21f4899fe5da7f984a").unwrap();
    let public_key = PublicKey::from_compressed(&compressed).unwrap();
    let compressed_again = public_key.to_compressed().unwrap();
    assert_eq!(compressed, compressed_again);
}

#[test]
fn test_uncompressed_public_key() {
    let uncompressed = hex::decode(
        "28fe26becbdc0384aa67bf734d08ec78ecc2330f0aa02ad9da00f56c37907f78\
             2cd080d897822a95a0fb103c54f06e9bf445f82f10fe37efce69ecb59514abc8\
             237faeb0351a693a45d5d54aa9759f52a71d76edae2132616d6085a9b2228bf9\
             0f46bd1ef47552c3089604c65a3e7154e3976410be01149b60d5a41a6053e6c2",
    )
    .unwrap();
    let public_key = PublicKey::from_uncompressed(&uncompressed).unwrap();

    let uncompressed_again = public_key.to_uncompressed().unwrap();
    assert_eq!(uncompressed_again, uncompressed);
}

#[test]
fn test_to_public_key_1() {
    let private_key = hex::decode("1ab1126ff2e37c6e6eddea943ccb3a48f83b380b856424ee552e113595525565").unwrap();
    let expected = hex::decode(
        "28fe26becbdc0384aa67bf734d08ec78ecc2330f0aa02ad9da00f56c37907f78\
             2cd080d897822a95a0fb103c54f06e9bf445f82f10fe37efce69ecb59514abc8\
             237faeb0351a693a45d5d54aa9759f52a71d76edae2132616d6085a9b2228bf9\
             0f46bd1ef47552c3089604c65a3e7154e3976410be01149b60d5a41a6053e6c2",
    )
    .unwrap();
    let expected_public_key = PublicKey::from_uncompressed(&expected).unwrap();
    let private_key = PrivateKey::try_from(private_key.as_ref()).unwrap();
    let public_key = PublicKey::from_private_key(&private_key);
    assert_eq!(public_key.0, expected_public_key.0);
}

#[test]
fn test_to_public_key_2() {
    let private_key = hex::decode("2009da7287c158b126123c113d1c85241b6e3294dd75c643588630a8bc0f934c").unwrap();
    let expected = hex::decode(
        "1cd5df38ed2f184b9830bfd3c2175d53c1455352307ead8cbd7c6201202f4aa8\
             02ce1c4241143cc61d82589c9439c6dd60f81fa6f029625d58bc0f2e25e4ce89\
             0ba19ae3b5a298b398b3b9d410c7e48c4c8c63a1d6b95b098289fbe1503d00fb\
             2ec596e93402de0abc73ce741f37ed4984a0b59c96e20df8c9ea1c4e6ec04556",
    )
    .unwrap();
    let expected_public_key = PublicKey::from_uncompressed(&expected).unwrap();
    let private_key = PrivateKey::try_from(private_key.as_ref()).unwrap();
    let public_key = PublicKey::from_private_key(&private_key);
    assert_eq!(public_key.0, expected_public_key.0);
}

#[test]
fn test_to_public_key_3() {
    let private_key = hex::decode("26fb4d661491b0a623637a2c611e34b6641cdea1743bee94c17b67e5ef14a550").unwrap();
    let expected = hex::decode(
        "077dfcf14e940b69bf88fa1ad99b6c7e1a1d6d2cb8813ac53383bf505a17f8ff\
             2d1a9b04a2c5674373353b5a25591292e69c37c0b84d9ef1c780a57bb98638e6\
             2dc52f109b333c4125bccf55bc3a839ce57676514405656c79e577e231519273\
             2410eee842807d9325f22d087fa6bc79d9bbea07f5fa8c345e1e57b28ad54f84",
    )
    .unwrap();
    let expected_public_key = PublicKey::from_uncompressed(&expected).unwrap();
    let private_key = PrivateKey::try_from(private_key.as_ref()).unwrap();
    let public_key = PublicKey::from_private_key(&private_key);
    assert_eq!(public_key.0, expected_public_key.0);
}

#[test]
fn test_to_public_key_4() {
    let private_key = hex::decode("0f6b8785374476a3b3e4bde2c64dfb12964c81c7930d32367c8e318609387872").unwrap();
    let expected = hex::decode(
        "270567a05b56b02e813281d554f46ce0c1b742b622652ef5a41d69afb6eb8338\
             1bab5671c5107de67fe06007dde240a84674c8ff13eeac6d64bad0caf2cfe53e\
             0142f4e04fc1402e17ae7e624fd9bd15f1eae0a1d8eda4e26ab70fd4cd793338\
             02b54a5deaaf86dc7f03d080c8373d62f03b3be06dac42b2d9426a8ebd0caf4a",
    )
    .unwrap();
    let expected_public_key = PublicKey::from_uncompressed(&expected).unwrap();
    let private_key = PrivateKey::try_from(private_key.as_ref()).unwrap();
    let public_key = PublicKey::from_private_key(&private_key);
    assert_eq!(public_key.0, expected_public_key.0);
}

/// Test `aggregate_public_keys`
#[test]
fn test_aggregate_public_keys_1() {
    // Public keys
    let public_key_1 = PublicKey(G2::one());
    let public_key_2 = PublicKey(G2::one());

    // Aggregation
    let agg_public_key = public_key_1 + public_key_2;

    // Check
    let expected = hex::decode("0b061848379c6bccd9e821e63ff6932738835b78e1e10079a0866073eba5b8bb444afbb053d16542e2b839477434966e5a9099093b6b3351f84ac19fe28f096548").unwrap();
    assert_eq!(agg_public_key.to_compressed().unwrap(), expected);
}

// /// Test `aggregate_signatures`
// #[test]
// fn test_aggregate_signatures_1() {
//     // Signatures (as valid points on G1)
//     let sign_1 = utils::to_compressed_g1(G1::one()).unwrap();
//     let sign_2 = utils::to_compressed_g1(G1::one()).unwrap();
//     let signatures = [&sign_1[..], &sign_2[..]];

//     // Aggregation
//     let agg_signature = Bn256
//         .aggregate_signatures(&signatures)
//         .expect("Signature aggregation should not fail if G1 points are
// valid.");

//     // Check
//     let expected =
// hex::decode("
// 02030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd3").
// unwrap();     assert_eq!(agg_signature, expected);
// }

// /// Test aggregated signatures verification
// #[test]
// fn test_verify_aggregated_signatures_1() {
//     // Message
//     let msg = hex::decode("73616d706c65").unwrap();

//     // Signature 1
//     let secret_key1 =
// hex::decode("
// 1ab1126ff2e37c6e6eddea943ccb3a48f83b380b856424ee552e113595525565").unwrap();

//     let private_key1 = PrivateKey::try_from(secret_key1.as_ref()).unwrap();
//     let public_key1 = PublicKey::from_private_key(private_key1);
//     let sign_1 = Bn256.sign(&secret_key1, &msg).unwrap();

//     // Signature 2
//     let secret_key2 =
// hex::decode("
// 2009da7287c158b126123c113d1c85241b6e3294dd75c643588630a8bc0f934c").unwrap();
//     let private_key2 = PrivateKey::try_from(secret_key2.as_ref()).unwrap();
//     let public_key2 = PublicKey::from_private_key(private_key2);
//     let sign_2 = Bn256.sign(&secret_key2, &msg).unwrap();

//     // Public Key and Signature aggregation
//     let agg_public_key = public_key1 + public_key2;
//     let agg_signature = Bn256.aggregate_signatures(&[&sign_1,
// &sign_2]).unwrap();

//     // Verification single signatures
//     assert!(
//         Bn256
//             .verify(&sign_1, &msg, &public_key1.to_compressed().unwrap())
//             .is_ok(),
//         "Signature 1 verification failed"
//     );
//     assert!(
//         Bn256
//             .verify(&sign_2, &msg, &public_key2.to_compressed().unwrap())
//             .is_ok(),
//         "Signature 2 signature verification failed"
//     );

//     // Aggregated signature verification
//     assert!(
//         Bn256
//             .verify(&agg_signature, &msg,
// &agg_public_key.to_compressed().unwrap())             .is_ok(),
//         "Aggregated signature verification failed"
//     );
// }

// /// Test PubKey in G1 -> PubKey in G2
// /// e(G1, P2) = e(P1, G2)
// #[test]
// fn test_verify_pk1_pk2() {
//     let secret_key =
//         hex::decode("
// 1ab1126ff2e37c6e6eddea943ccb3a48f83b380b856424ee552e113595525565")
//             .unwrap();
//     let scalar2 = Fr::from_slice(&secret_key[0..32]).unwrap();
//     let key2 = PrivateKey(scalar2);
//     let public_g2 = key2.derive_public_key_g2().unwrap();

//     let scalar1 = Fr::from_slice(&secret_key[0..32]).unwrap();
//     let key1 = PrivateKey(scalar1);
//     let public_g1 = key1.derive_public_key_g1().unwrap();

//     let mut vals = Vec::new();
//     // First pairing input: e(G1::one(), PubKey_G2)
//     // let hash_point = self.hash_to_try_and_increment(&message)?;
//     // let public_key_point = G2::from_compressed(&public_key)?;
//     vals.push((G1::one(), public_g2));
//     // Second pairing input:  e(PubKey_G1, G2::one())
//     // let signature_point = G1::from_compressed(&signature)?;
//     vals.push((public_g1, -G2::one()));
//     // Pairing batch with one negated point
//     let mul = pairing_batch(&vals);

//     assert!(
//         mul == Gt::one(),
//         "Publikey Key in G1 DOES NOT correspondond to PubKey in G2"
//     )
// }

// /// Test PubKey in G1 -> PubKey in G2
// /// e(G1, P2) = e(P1, G2)
// #[test]
// fn test_verify_invalid_pk1_pk2() {
//     let secret_key1 =
//         hex::decode("
// 1ab1126ff2e37c6e6eddea943ccb3a48f83b380b856424ee552e113595525565")
//             .unwrap();
//     let scalar2 = Fr::from_slice(&secret_key1[0..32]).unwrap();
//     let key2 = PrivateKey(scalar2);
//     let public_g2 = key2.derive_public_key_g2().unwrap();

//     let secret_key2 =
//         hex::decode("
// 1ab1126ff2e37c6e6eddea943ccb3a48f83b380b856424ee552e113595525566")
//             .unwrap();
//     let scalar1 = Fr::from_slice(&secret_key2[0..32]).unwrap();
//     let key1 = PrivateKey(scalar1);
//     let public_g1 = key1.derive_public_key_g1().unwrap();

//     let mut vals = Vec::new();
//     // First pairing input: e(G1::one(), PubKey_G2)
//     // let hash_point = self.hash_to_try_and_increment(&message)?;
//     // let public_key_point = G2::from_compressed(&public_key)?;
//     vals.push((G1::one(), public_g2));
//     // Second pairing input:  e(PubKey_G1, G2::one())
//     // let signature_point = G1::from_compressed(&signature)?;
//     vals.push((public_g1, -G2::one()));
//     // Pairing batch with one negated point
//     let mul = pairing_batch(&vals);

//     assert!(
//         mul != Gt::one(),
//         "Publikey Key in G1 DOES correspondond to PubKey in G2"
//     )
// }
