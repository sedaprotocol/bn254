use super::*;

/// Test for the `sign`` function with own test vector
#[test]
fn test_sign_1() {
    // Inputs: private key and message "sample" in ASCII
    let private_key = hex::decode("2009da7287c158b126123c113d1c85241b6e3294dd75c643588630a8bc0f934c").unwrap();
    let data = hex::decode("73616d706c65").unwrap();

    let private_key = PrivateKey::try_from(private_key.as_ref()).unwrap();

    // Sign data with private key
    let signature = ECDSA::sign(&data, &private_key).unwrap();

    let expected_signature = "020f047a153e94b5f109e4013d1bd078112817cf0d58cdf6ba8891f9849852ba5b";
    assert_eq!(hex::encode(signature.to_compressed().unwrap()), expected_signature);
}

/// Test `verify` function with own signed message
#[test]
fn test_verify_signed_msg() {
    // Public key
    let private_key = hex::decode("2009da7287c158b126123c113d1c85241b6e3294dd75c643588630a8bc0f934c").unwrap();
    let private_key = PrivateKey::try_from(private_key.as_ref()).unwrap();
    let public_key = PublicKey::from_private_key(&private_key);

    // Signature
    let signature_vec = hex::decode("020f047a153e94b5f109e4013d1bd078112817cf0d58cdf6ba8891f9849852ba5b").unwrap();
    let signature = Signature::from_compressed(&signature_vec).unwrap();

    // Message signed
    let msg = hex::decode("73616d706c65").unwrap();

    // Verify signature
    assert!(
        ECDSA::verify(&msg, &signature, &public_key).is_ok(),
        "Verification failed"
    );
}

/// Test aggregate signature verification
#[test]
fn test_verify_aggregate_signatures() {
    // Message
    let msg = hex::decode("73616d706c65").unwrap();

    // Signature 1
    let private_key_1_bytes = hex::decode("1ab1126ff2e37c6e6eddea943ccb3a48f83b380b856424ee552e113595525565").unwrap();
    let private_key_1 = PrivateKey::try_from(private_key_1_bytes.as_ref()).unwrap();
    let sign_1 = ECDSA::sign(&msg, &private_key_1).unwrap();

    let public_key_1 = PublicKey::from_private_key(&private_key_1);

    // Signature 2
    let secret_key_2_bytes = hex::decode("2009da7287c158b126123c113d1c85241b6e3294dd75c643588630a8bc0f934c").unwrap();
    let private_key_2 = PrivateKey::try_from(secret_key_2_bytes.as_ref()).unwrap();
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
