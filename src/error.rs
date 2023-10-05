//! Errors.
use substrate_parser::error::SignableError;

use crate::std::string::String;

#[cfg(feature = "std")]
use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
};

#[cfg(not(feature = "std"))]
use core::fmt::{Display, Formatter, Result as FmtResult};

use substrate_parser::traits::ExternalMemory;

/// Error in generating shortened metadata.
#[derive(Debug, Eq, PartialEq)]
pub enum MetaCutError<E: ExternalMemory> {
    IndexTwice { id: u32 },
    NoEntryLargerRegistry,
    Signable(SignableError<E>),
    TreeCalculateProof,
    TreeCalculateRoot,
}

impl<E: ExternalMemory> MetaCutError<E> {
    fn error_text(&self) -> String {
        match &self {
            MetaCutError::IndexTwice{id} => format!("While forming shortened metadata types registry, tried to enter type with already existing index {id} and different description. This is code bug, please report it."),
            MetaCutError::NoEntryLargerRegistry => String::from("While forming metadata types registry with excluded types, found type that should exist in larger registry, but does not. This is code bug, please report it."),
            MetaCutError::Signable(signable_error) => format!("Unable to decode properly the signable transaction used for metadata shortening. {signable_error}"),
            MetaCutError::TreeCalculateProof => String::from("Unable to calculate proof for merkle tree"),
            MetaCutError::TreeCalculateRoot => String::from("Unable to calculate root hash"),
        }
    }
}

/// Implement [`Display`] for errors in both `std` and `no_std` cases.
/// Implement `Error` for `std` case.
macro_rules! impl_display_and_error_traited {
    ($($ty: ty), *) => {
        $(
            impl <E: ExternalMemory> Display for $ty {
                fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
                    write!(f, "{}", self.error_text())
                }
            }

            #[cfg(feature = "std")]
            impl <E: ExternalMemory> Error for $ty {
                fn source(&self) -> Option<&(dyn Error + 'static)> {
                    None
                }
            }
        )*
    }
}

impl_display_and_error_traited!(MetaCutError<E>);
