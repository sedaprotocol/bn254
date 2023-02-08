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
