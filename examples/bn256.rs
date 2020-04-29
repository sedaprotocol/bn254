use bls_signatures_rs::bn256::Bn256;
use bls_signatures_rs::MultiSignature;

fn main() {
    // Inputs: Secret Key, Public Key (derived) & Message

    // Secret key one
    let secret_key_1 =
        hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();

    // Secret key two
    let secret_key_2 =
        hex::decode("a55e93edb1350916bf5beea1b13d8f198ef410033445bcb645b65be5432722f1").unwrap();

    // Derive public keys from secret key
    let public_key_1 = Bn256.derive_public_key(&secret_key_1).unwrap();
    let public_key_2 = Bn256.derive_public_key(&secret_key_2).unwrap();

    let message: &[u8] = b"sample";

    // Sign identical message with two different secret keys
    let sig_1 = Bn256.sign(&secret_key_1, &message).unwrap();
    let sig_2 = Bn256.sign(&secret_key_2, &message).unwrap();

    // Aggregate public keys
    let agg_pub_key = Bn256
        .aggregate_public_keys(&[&public_key_1, &public_key_2])
        .unwrap();

    // Aggregate signatures
    let agg_sig = Bn256.aggregate_signatures(&[&sig_1, &sig_2]).unwrap();

    // Check whether the aggregated signature corresponds to the aggregated public key
    Bn256.verify(&agg_sig, &message, &agg_pub_key).unwrap();
    println!("Successful verification");
}
