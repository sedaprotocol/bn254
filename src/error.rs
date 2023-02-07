//! Errors returned by the bn256 library
use bn::{CurveError, FieldError, GroupError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Bn254Error {
    #[error("errored to find a valid point while converting hash to point")]
    HashToPointError,
    #[error("errored to get data from an index out of bounds")]
    IndexOutOfBounds,
    #[error("errored to create group or field due to invalid input encoding")]
    InvalidEncoding,
    #[error("errored to map point to a curve")]
    InvalidGroupPoint,
    #[error("errored to create group or field due to invalid input length")]
    InvalidLength,
    #[error("errored to create a field element")]
    NotMemberError,
    #[error("errored to convert to affine coordinates")]
    ToAffineConversion,
    #[error("Point was already in affine coordinates (division-by-zero)")]
    PointInJacobian,
    #[error("Bn254 verification failed")]
    VerificationFailed,
}

impl From<CurveError> for Bn254Error {
    fn from(error: CurveError) -> Self {
        match error {
            CurveError::InvalidEncoding => Bn254Error::InvalidEncoding,
            CurveError::NotMember => Bn254Error::NotMemberError,
            CurveError::Field(field_error) => field_error.into(),
            CurveError::ToAffineConversion => Bn254Error::ToAffineConversion,
        }
    }
}

impl From<FieldError> for Bn254Error {
    fn from(error: FieldError) -> Self {
        match error {
            FieldError::NotMember => Bn254Error::NotMemberError,
            FieldError::InvalidSliceLength => Bn254Error::InvalidLength,
            FieldError::InvalidU512Encoding => Bn254Error::InvalidEncoding,
        }
    }
}

impl From<GroupError> for Bn254Error {
    fn from(_error: GroupError) -> Self {
        Bn254Error::InvalidGroupPoint
    }
}

impl From<bn::arith::Error> for Bn254Error {
    fn from(_error: bn::arith::Error) -> Self {
        Bn254Error::InvalidLength
    }
}
