//! Errors returned by the bn256 library
use bn::{CurveError, FieldError, GroupError};
use thiserror::Error as ThisError;

#[derive(ThisError, Debug)]
pub enum Error {
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
    #[error("Serialization failed")]
    SerializationError,
}

impl From<CurveError> for Error {
    fn from(error: CurveError) -> Self {
        match error {
            CurveError::InvalidEncoding => Error::InvalidEncoding,
            CurveError::NotMember => Error::NotMemberError,
            CurveError::Field(field_error) => field_error.into(),
            CurveError::ToAffineConversion => Error::ToAffineConversion,
        }
    }
}

impl From<FieldError> for Error {
    fn from(error: FieldError) -> Self {
        match error {
            FieldError::NotMember => Error::NotMemberError,
            FieldError::InvalidSliceLength => Error::InvalidLength,
            FieldError::InvalidU512Encoding => Error::InvalidEncoding,
        }
    }
}

impl From<GroupError> for Error {
    fn from(_error: GroupError) -> Self {
        Error::InvalidGroupPoint
    }
}

impl From<bn::arith::Error> for Error {
    fn from(_error: bn::arith::Error) -> Self {
        Error::InvalidLength
    }
}

impl From<std::vec::Vec<u8>> for Error {
    fn from(_error: std::vec::Vec<u8>) -> Self {
        Error::SerializationError
    }
}

impl From<std::io::Error> for Error {
    fn from(_error: std::io::Error) -> Self {
        Error::SerializationError
    }
}

pub type Result<T, E = Error> = core::result::Result<T, E>;
