
use crate::BLS;

extern crate bn;
extern crate rustc_hex;
use failure::Fail;
use bn::{pairing_batch, AffineG1, AffineG2, Fq, Fr, Fq2, Group, Gt, G1, G2};
use self::bn::{CurveError, FieldError, GroupError};

#[allow(non_camel_case_types)]
#[derive(Debug, Fail)]

pub enum Error {
    /// Unknown error
    #[fail(display = "Unknown error")]
    Unknown,
}

impl From<CurveError> for Error {
    /// Transforms error from `openssl::error::ErrorStack` to `Error::CodedError` or `Error::Unknown`
    fn from(_error: CurveError) -> Self {
        Error::Unknown {}
    }
}

impl From<FieldError> for Error {
    /// Transforms error from `openssl::error::ErrorStack` to `Error::CodedError` or `Error::Unknown`
    fn from(_error: FieldError) -> Self {
        Error::Unknown {}
    }
}

impl From<GroupError> for Error {
    /// Transforms error from `openssl::error::ErrorStack` to `Error::CodedError` or `Error::Unknown`
    fn from(_error: GroupError) -> Self {
        Error::Unknown {}
    }
}

impl From<bn::arith::Error> for Error {
    /// Transforms error from `openssl::error::ErrorStack` to `Error::CodedError` or `Error::Unknown`
    fn from(_error: bn::arith::Error) -> Self {
        Error::Unknown {}
    }
}


struct Bn128 {}

pub struct PrivateKey {
    sk: bn::Fr,
}

pub struct PublicKey {
    pk: bn::G1,
}

impl PrivateKey {

    pub fn from_sk(sk: &Fr) -> PrivateKey {
        PrivateKey { sk: *sk }
    }
    
    pub fn to_public(&self) ->  Result<PublicKey, Error> {
      Ok(PublicKey { pk: G1::one() * self.sk })
    }
}

impl PublicKey {

    pub fn from_compressed(bytes: &[u8]) -> Result<Self, Error> {
        let compressed = G1::from_compressed(&bytes)?;

        Ok(PublicKey { pk: compressed})
    }

    pub fn to_compressed(&self) ->  Result<Vec<u8>, Error> {
        // From Jacobian to Affine first!
        let affine_coords = AffineG1::from_jacobian(self.pk).ok_or(Error::Unknown)?;
        // Get X coordinate
        let x = Fq::into_u256(affine_coords.x());
        // Get Y coordinate
        let y = Fq::into_u256(affine_coords.y());
        // Get parity of Y
        let parity = y.get_bit(0).ok_or(Error::Unknown)?;

        // Take x as big endian into slice
        let mut s = [0u8; 32];
        x.to_big_endian( &mut s)?;
        let mut result: Vec<u8> = Vec::new();
        // Push 0x02 or 0x03 depending on parity
        result.push(if parity {3} else {2});
        // Append x
        result.append(&mut s.to_vec());

        Ok(result)
    }
}


fn read_fr(scalar: &[u8]) -> Result<bn::Fr, Error> {
  Ok(bn::Fr::from_slice(&scalar[0..32])?)
}

fn read_point(x_cord: &[u8], y_cord: &[u8]) -> Result<::bn::G1, Error> {
    let px = Fq::from_slice(x_cord)?;
    let py = Fq::from_slice(y_cord)?;
    Ok(if px == Fq::zero() && py == Fq::zero() {
        G1::zero()
    } else {
        // from Afine into G1
        AffineG1::new(px, py)?
            .into()
    })
}

impl BLS<&[u8], &[u8], &[u8]> for Bn128 {
  type Error = Error;

  fn derive_public_key(&mut self, secret_key: &[u8]) -> Result<Vec<u8>, Error>{

    let scalar = read_fr(&secret_key)?;
    let key = PrivateKey::from_sk(&scalar);
    let public = key.to_public()?;

    public.to_compressed()
  }

    fn sign(&mut self, secret_key: &[u8], msg: &[u8]) -> Result<Vec<u8>, Self::Error> {
        unimplemented!()
    }

    fn verify(&mut self, public_key: &[u8], signature: &[u8], msg: &[u8]) -> Result<bool, Self::Error> {
        unimplemented!()
    }

    fn aggregate_public_keys(&mut self, public_key: &[&[u8]]) -> Result<Vec<u8>, Self::Error> {
        unimplemented!()
    }

    fn aggregate_signatures(&mut self, public_key: &[&[u8]]) -> Result<Vec<u8>, Self::Error> {
        unimplemented!()
    }
}
#[cfg(test)]
mod test {
    use super::*;
    // Test vectors taken from https://asecuritysite.com/encryption/go_bn256
    #[test]
    fn test_derive_public_key_1() {
        let secret_key = hex::decode("27f147a74c59d741623144885af95d03d1a11b424fe03576c3de8c95116f3e90").unwrap();
        let expected = hex::decode("020ec528f12a7477e921ef1caf4d07e3f1c5397dfd29c8d754940373ccf2af1053").unwrap();
        let mut curve = Bn128{};
        let public_key = curve.derive_public_key(&secret_key).unwrap();
    }

    #[test]
    fn test_derive_public_key_2() {
        let secret_key = hex::decode("19540c18454c629bb6b8ff84a79254dac85ab06ea890c3982ac65aa34f56f4b9").unwrap();
        let expected = hex::decode("030ab5e0f229e5020eab9217e4810a55c6dc8cc8a9693cc6305e88a7adb0e13f87").unwrap();
        let mut curve = Bn128{};
        let public_key = curve.derive_public_key(&secret_key).unwrap();
        assert_eq!(public_key, expected);
    }

    #[test]
    fn test_derive_public_key_3() {
        let secret_key = hex::decode("0ea240c8c842993ae46cc67cf51ee3708a8df958f15ca712564b0cf7bc8d6587").unwrap();
        let expected = hex::decode("032760546fce84e889e12b3a8d5c90f38aae71b12af77a78323960f763daaa5ad6").unwrap();
        let mut curve = Bn128{};
        let public_key = curve.derive_public_key(&secret_key).unwrap();
        assert_eq!(public_key, expected);
    }
    #[test]
    fn test_derive_public_key_4() {
        let secret_key = hex::decode("00f3f6209b6405a6c7c15806cc2c3d16c4e21ea5e4a06d9a16b98e73eaa7cc1e").unwrap();
        let expected = hex::decode("020fa46f48321476666693b1c0256ba41c97dc6a90611b23a2dc7bfc3aa5e58e80").unwrap();
        let mut curve = Bn128{};
        let public_key = curve.derive_public_key(&secret_key).unwrap();
        assert_eq!(public_key, expected);
    }
    #[test]
    fn test_derive_public_key_5() {
        let secret_key = hex::decode("1dcdce57344ac624a0796cbe53c57818564e825dfa9be214d7a72fe8590d738b").unwrap();
        let expected = hex::decode("030779a0700b9e594e76becf454b4d2b4865651337af87c8c80e88379f8bc838b8").unwrap();
        let mut curve = Bn128{};
        let public_key = curve.derive_public_key(&secret_key).unwrap();
        assert_eq!(public_key, expected);
    }
    #[test]
    fn test_derive_public_key_6() {
        let secret_key = hex::decode("10c753c09b292541f281ec63444ff75d7d9fdefde897c5e6e6a06b22ce0cce86").unwrap();
        let expected = hex::decode("0312eb2e90752c26d2a65381680eba893da7a762c9bb8edc22862ae580e47f5b97").unwrap();
        let mut curve = Bn128{};
        let public_key = curve.derive_public_key(&secret_key).unwrap();
        assert_eq!(public_key, expected);
    }
    #[test]
    fn test_derive_public_key_7() {
        let secret_key = hex::decode("11734d50bfae98dbecf206e5d885aacc82e47872f813fcc127fd0688ec5d6241").unwrap();
        let expected = hex::decode("030f318e059e13b62fe7c4133e59a9e55c9ef4870d1cd59d8fcfc4799f5d3a8f81").unwrap();
        let mut curve = Bn128{};
        let public_key = curve.derive_public_key(&secret_key).unwrap();
        assert_eq!(public_key, expected);
    }
    #[test]
    fn test_derive_public_key_8() {
        let secret_key = hex::decode("0553fa0ab032684b792626856adba0eb3ee0a80737e1a51e553f0aef0d85c0b2").unwrap();
        let expected = hex::decode("032865b2db0874dcca131d9455c5cc47841bf92a524c1c25bd490267acda372c55").unwrap();
        let mut curve = Bn128{};
        let public_key = curve.derive_public_key(&secret_key).unwrap();
        assert_eq!(public_key, expected);
    }
    #[test]
    fn test_derive_public_key_9() {
        let secret_key = hex::decode("211037dc8667dd39b2e809707978fddeb44ab67246923f720e27c1db021bfe8a").unwrap();
        let expected = hex::decode("030cf60ef373667e3407d0728390a523cff560f8f9ef0f795a397cc243f74672e4").unwrap();
        let mut curve = Bn128{};
        let public_key = curve.derive_public_key(&secret_key).unwrap();
        assert_eq!(public_key, expected);
    }
    #[test]
    fn test_from_compressed() {
        let compressed = hex::decode("0312eb2e90752c26d2a65381680eba893da7a762c9bb8edc22862ae580e47f5b97").unwrap();
        let pub_key = PublicKey::from_compressed(&compressed).unwrap();
        let to_compressed = pub_key.to_compressed().unwrap();
        assert_eq!(compressed, to_compressed);
    }
}
