use std::error::Error;
use std::fmt;

#[derive(Debug)] // Required for the `Error` trait
pub enum MyError {
    ArgumentError(String),
    CredentialsError(String),
    TransferError(String),
    PelicanError(String),
    GenericError(String),
}

impl Error for MyError {}

impl fmt::Display for MyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MyError::ArgumentError(details) => write!(f, "ArgumentError: {details}"),
            MyError::CredentialsError(details) => write!(f, "CredenialsError: {details}"),
            MyError::TransferError(details) => write!(f, "TransferError: {details}"),
            MyError::PelicanError(details) => write!(f, "PelicanError: {details}"),
            MyError::GenericError(details) => write!(f, "GenericError: {details}"),
        }
    }
}
