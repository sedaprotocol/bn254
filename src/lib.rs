//! Elliptic Curve Digital Signature Algorithm (ECDSA) using the `bn254` curve,
//! also known as `bn128` or `bn256`.
//!
//! This module has been designed with the goal of being compatible with the
//! bn256Add(G1), bn256ScalarMul(G1) and bn256Pairing provided by precompiled
//! contracts on the Ethereum Virtual Machine (EVM).
//!
//! <b>Signature verification</b>: <em>e(H(m), PubKey) = e(Signature,
//! G2::one)</em>
//!
//! This module handles public keys in G2 in order to avoid performing the
//! hashing to G2, which involves a costly multiplication with the cofactor.
//!
//!<b>Test vectors</b>: the following resources have been used for testing
//! BN256 functionalities
//! - test vectors from <a href="https://github.com/ethereum/go-ethereum/blob/7b189d6f1f7eedf46c6607901af291855b81112b/core/vm/contracts_test.go">Ethereum</a>
//! - test vectors from <a href="https://asecuritysite.com/encryption/bn">Asecurity</a>
//!
//! <b>Hashing to G1</b>: In order to hash a specific message to G1 this module
//! uses the try and increment algorithm. The running time of this algorithm is
//! dependant on the input message, so it should be used only with public
//! inputs. Alternatively different hashing methods can be implemented as
//! specified in:
//! - <a href="https://tools.ietf.org/html/draft-irtf-cfrg-hash-to--04#page-37">hash_to_ algorithms</a>
//!
//!<b>Resources</b>: The following resources have been used as a reference
//! to implement aggregate signatures:
//!
//! - <a href="https://github.com/cfrg/draft-irtf-cfrg-bls-signature/blob/master/draft-irtf-cfrg-bls-signature-00.txt">BLS IRTF draft</a>
//! - <a href="https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html">
//!   BLSmultisig</a>
//! - <a href="https://medium.com/cryptoadvance/bls-signatures-better-than-schnorr-5a7fe30ea716">bls-signatures-better-than-schnorr</a>
//!
//! # Disclaimer
//!
//! This module does not implement a defense against Rogue-key attacks, which
//! means it should be used in protocols where the possession of the private key
//! of each individual has been proven (i.e., by signing a message).

mod ecdsa;
mod error;
mod hash;
mod types;
mod utils;

#[cfg(test)]
mod ecdsa_test;
#[cfg(test)]
mod hash_test;
#[cfg(test)]
mod types_test;

pub use ecdsa::ECDSA;
pub use error::Bn254Error;
pub use types::{PrivateKey, PublicKey, Signature};
