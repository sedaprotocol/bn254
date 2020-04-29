//! Errors returned by the bn256 library
use bn::{CurveError, FieldError, GroupError};
use failure::Fail;

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "Failed to find a valid point while converting hash to point")]
    HashToPointError,
    #[fail(display = "Failed to get data from an index out of bounds")]
    IndexOutOfBounds,
    #[fail(display = "Failed to create group or field due to invalid input encoding")]
    InvalidEncoding,
    #[fail(display = "Failed to map point to a curve")]
    InvalidGroupPoint,
    #[fail(display = "Failed to create group or field due to invalid input length")]
    InvalidLength,
    #[fail(display = "Failed to create a field element")]
    NotMemberError,
    #[fail(display = "Point was already in affine coordinates (division-by-zero)")]
    PointInJacobian,
    #[fail(display = "BLS verification failed")]
    VerificationFailed,
}

impl From<CurveError> for Error {
    fn from(error: CurveError) -> Self {
        match error {
            CurveError::InvalidEncoding => Error::InvalidEncoding,
            CurveError::NotMember => Error::NotMemberError,
            CurveError::Field(field_error) => field_error.into(),
            // ToAffineConversion happens when using miller_loop_batch, we do not use that
            CurveError::ToAffineConversion => unimplemented!(),
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
