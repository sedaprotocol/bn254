use bn254::{PrivateKey, PublicKey, ECDSA};

fn main() {
    // Inputs: Secret Key, Public Key (derived) & Message

    // Secret key one
    let private_key_1_bytes = hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();
    let private_key_1 = PrivateKey::try_from(private_key_1_bytes.as_ref()).unwrap();

    // Secret key two
    let private_key_2_bytes = hex::decode("a55e93edb1350916bf5beea1b13d8f198ef410033445bcb645b65be5432722f1").unwrap();
    let private_key_2 = PrivateKey::try_from(private_key_2_bytes.as_ref()).unwrap();

    // Derive public keys from secret key
    let public_key_1 = PublicKey::from_private_key(&private_key_1);
    let public_key_2 = PublicKey::from_private_key(&private_key_2);

    let message: &[u8] = b"sample";

    // Sign identical message with two different secret keys
    let signature_1 = ECDSA::sign(&private_key_1, &message).unwrap();
    let signature_2 = ECDSA::sign(&private_key_2, &message).unwrap();

    // Aggregate public keys
    let aggregate_pub_key = public_key_1 + public_key_2;

    // Aggregate signatures
    let aggregate_sig = signature_1 + signature_2;

    // Check whether the aggregate signature corresponds to the aggregated
    // public_key
    ECDSA::verify(&aggregate_sig, &message, &aggregate_pub_key).unwrap();
    println!("Successful aggregate signature verification");
}
