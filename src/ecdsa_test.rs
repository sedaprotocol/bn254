use super::*;
use crate::ecdsa::check_public_keys;

/// Test for the `ECDSA::sign` function with own test vector
#[test]
fn test_sign_1() {
    // Inputs: private key and message "sample" in ASCII
    let data = hex::decode("73616d706c65").unwrap();

    let private_key = PrivateKey::try_from("2009da7287c158b126123c113d1c85241b6e3294dd75c643588630a8bc0f934c").unwrap();

    // Sign data with private key
    let signature = ECDSA::sign(data, &private_key).unwrap();

    let expected_signature = "020f047a153e94b5f109e4013d1bd078112817cf0d58cdf6ba8891f9849852ba5b";
    assert_eq!(hex::encode(signature.to_compressed().unwrap()), expected_signature);
}

/// Test `ECDSA::verify` function with own signed message
#[test]
fn test_verify_signed_msg() {
    // Public key
    let private_key = PrivateKey::try_from("2009da7287c158b126123c113d1c85241b6e3294dd75c643588630a8bc0f934c").unwrap();
    let public_key = PublicKey::from_private_key(&private_key);

    // Signature
    let signature_vec = hex::decode("020f047a153e94b5f109e4013d1bd078112817cf0d58cdf6ba8891f9849852ba5b").unwrap();
    let signature = Signature::from_compressed(signature_vec).unwrap();

    // Message signed
    let msg = hex::decode("73616d706c65").unwrap();

    // Verify signature
    assert!(
        ECDSA::verify(msg, &signature, &public_key).is_ok(),
        "Verification failed"
    );
}

/// Test aggregate signature verification
#[test]
fn test_verify_aggregate_signatures() {
    // Message
    let msg = hex::decode("73616d706c65").unwrap();

    // Signature 1
    let private_key_1 =
        PrivateKey::try_from("1ab1126ff2e37c6e6eddea943ccb3a48f83b380b856424ee552e113595525565").unwrap();
    let sign_1 = ECDSA::sign(&msg, &private_key_1).unwrap();

    let public_key_1 = PublicKey::from_private_key(&private_key_1);

    // Signature 2
    let private_key_2 =
        PrivateKey::try_from("2009da7287c158b126123c113d1c85241b6e3294dd75c643588630a8bc0f934c").unwrap();
    let sign_2 = ECDSA::sign(&msg, &private_key_2).unwrap();

    let public_key_2 = PublicKey::from_private_key(&private_key_2);

    // Public Key and Signature aggregation
    let agg_public_key = public_key_1 + public_key_2;
    let agg_signature = sign_1 + sign_2;

    // Verification single signatures
    assert!(
        ECDSA::verify(&msg, &sign_1, &public_key_1).is_ok(),
        "Signature 1 verification failed"
    );
    assert!(
        ECDSA::verify(&msg, &sign_2, &public_key_2).is_ok(),
        "Signature 2 signature verification failed"
    );

    // Aggregate signature verification
    assert!(
        ECDSA::verify(&msg, &agg_signature, &agg_public_key).is_ok(),
        "Aggregated signature verification failed"
    );
}

/// Test if PubKey in G1 -> PubKey in G2: e(G1, P2) = e(P1, G2)
#[test]
fn test_verify_valid_public_keys_in_g1_g2() {
    let private_key = PrivateKey::try_from("1ab1126ff2e37c6e6eddea943ccb3a48f83b380b856424ee552e113595525565").unwrap();

    // Get public keys in G1 and G2
    let public_g2 = PublicKey::from_private_key(&private_key);
    let public_g1 = PublicKeyG1::from_private_key(&private_key);

    // Check if valid
    assert!(
        check_public_keys(&public_g2, &public_g1).is_ok(),
        "Public Key in G1 DOES NOT correspond to Public Key in G2"
    );
}

/// Test (false-positive) if PubKey in G1 -> PubKey in G2: e(G1, P2) = e(P1, G2)
#[test]
fn test_verify_invalid_public_keys_in_g1_g2() {
    // Get public keys in G1 and G2 (from different private keys)
    let private_key_1 =
        PrivateKey::try_from("1ab1126ff2e37c6e6eddea943ccb3a48f83b380b856424ee552e113595525565").unwrap();
    let public_g2 = PublicKey::from_private_key(&private_key_1);

    let private_key_2 =
        PrivateKey::try_from("2009da7287c158b126123c113d1c85241b6e3294dd75c643588630a8bc0f934c").unwrap();
    let public_g1 = PublicKeyG1::from_private_key(&private_key_2);

    // Check if valid
    let result = check_public_keys(&public_g2, &public_g1);
    assert!(matches!(result, Err(Error::VerificationFailed)));
}

/// Test 'PublicKeyG1::from_uncompressed' and 'PublicKeyG1::to_uncompressed'
#[test]
fn test_public_key_g1_from_uncompressed() {
    let private_key = PrivateKey::try_from("1ab1126ff2e37c6e6eddea943ccb3a48f83b380b856424ee552e113595525565").unwrap();

    // Get public keys in G1 and G2
    let public_g2 = PublicKey::from_private_key(&private_key);
    let public_g1 = PublicKeyG1::from_private_key(&private_key);

    let pk_g1_uncompressed = public_g1.to_uncompressed().unwrap();
    let public_g1_again = PublicKeyG1::from_uncompressed(pk_g1_uncompressed).unwrap();

    // Check if valid
    assert!(
        check_public_keys(&public_g2, &public_g1_again).is_ok(),
        "Public Key in G1 DOES NOT correspond to Public Key in G2"
    );
}

/// Test `Signature::from_uncompressed()` and `Signature::to_uncompressed()`
#[test]
fn test_sig_from_uncompressed() {
    // Public key
    let private_key = PrivateKey::try_from("2009da7287c158b126123c113d1c85241b6e3294dd75c643588630a8bc0f934c").unwrap();
    let public_key = PublicKey::from_private_key(&private_key);

    // Signature
    let signature_vec = hex::decode("020f047a153e94b5f109e4013d1bd078112817cf0d58cdf6ba8891f9849852ba5b").unwrap();
    let signature = Signature::from_compressed(signature_vec).unwrap();
    let uncompressed_sig = signature.to_uncompressed().unwrap();
    let signature_again = Signature::from_uncompressed(uncompressed_sig).unwrap();

    // Message signed
    let msg = hex::decode("73616d706c65").unwrap();

    // Verify signature
    assert!(
        ECDSA::verify(msg, &signature_again, &public_key).is_ok(),
        "Verification failed"
    );
}
