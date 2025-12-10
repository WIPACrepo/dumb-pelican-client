use std::error::Error;
use std::fmt;

#[derive(Debug)] // Required for the `Error` trait
pub enum MyError {
    Credentials(String),
    Transfer(String),
    Pelican(String),
    #[allow(dead_code)]
    Generic(String),
}

impl Error for MyError {}

impl fmt::Display for MyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MyError::Credentials(details) => write!(f, "CredenialsError: {details}"),
            MyError::Transfer(details) => write!(f, "TransferError: {details}"),
            MyError::Pelican(details) => write!(f, "PelicanError: {details}"),
            MyError::Generic(details) => write!(f, "GenericError: {details}"),
        }
    }
}
