use super::*;

#[test]
pub fn test_serde_private_key() {
    let pk = PrivateKey::random(&mut rand::rngs::OsRng);
    let json = serde_json::to_value(&pk).unwrap();
    let pk_from_json: PrivateKey = serde_json::from_value(json).unwrap();
    assert_eq!(pk_from_json, pk);
}

#[test]
pub fn test_serde_public_key() {
    let pk = PrivateKey::random(&mut rand::rngs::OsRng);
    let pubk = PublicKey::from_private_key(&pk);
    let json = serde_json::to_value(pubk).unwrap();
    let pubk_from_json: PublicKey = serde_json::from_value(json).unwrap();
    assert_eq!(pubk_from_json, pubk);
}
