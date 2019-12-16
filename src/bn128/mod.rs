
use crate::BLS;

extern crate bn;
extern crate rustc_hex;
use bn::{pairing_batch, AffineG1, AffineG2, Fq, Fr, Fq2, Group, Gt, G1, G2};

#[allow(non_camel_case_types)]
#[derive(Debug)]

pub struct Error(pub &'static str);

impl From<&'static str> for Error {
    fn from(val: &'static str) -> Self {
        Error(val)
    }
}

struct bn128 {}

pub struct PrivateKey {
    sk: ::bn::Fr,
}

pub struct PublicKey {
    pk: ::bn::G1,
}

impl PrivateKey {

    pub fn from_sk(sk: &Fr) -> PrivateKey {
        PrivateKey { sk: sk.clone() }
    }
    
    pub fn to_public(&self) ->  Result<PublicKey, Error> {
      Ok(PublicKey { pk: G1::one() * self.sk })
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

impl BLS<PublicKey, &[u8], &[u8]> for bn128 {
  type Error = Error;

  fn derive_public_key(&mut self, secret_key: &[u8]) -> Result<PublicKey, Error>{

    let scalar = read_fr(&secret_key)?;
    let key = PrivateKey::from_sk(&scalar);
    key.to_public()
  }

}