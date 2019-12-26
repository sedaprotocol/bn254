use bn::{CurveError, FieldError, GroupError};
use failure::Fail;

#[derive(Debug, Fail)]
pub enum Error {
    /// The `hash_to_point()` function could not find a valid point
    #[fail(display = "Hash to point function could not find a valid point")]
    HashToPointError,
    /// Unknown error
    #[fail(display = "Unknown error")]
    Unknown,
    /// BLS verification error
    #[fail(display = "BLS verification failed")]
    VerificationFailed,
}

impl From<CurveError> for Error {
    fn from(_error: CurveError) -> Self {
        Error::Unknown {}
    }
}

impl From<FieldError> for Error {
    fn from(_error: FieldError) -> Self {
        Error::Unknown {}
    }
}

impl From<GroupError> for Error {
    fn from(_error: GroupError) -> Self {
        Error::Unknown {}
    }
}

impl From<bn::arith::Error> for Error {
    fn from(_error: bn::arith::Error) -> Self {
        Error::Unknown {}
    }
}