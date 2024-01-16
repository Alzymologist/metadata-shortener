//! Errors.
#[cfg(any(feature = "merkle-lean", test))]
use merkle_cbt_lean::ErrorMT;
use substrate_parser::error::SignableError;

use crate::std::string::String;

#[cfg(feature = "std")]
use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
};

#[cfg(not(feature = "std"))]
use core::fmt::{Display, Formatter, Result as FmtResult};

use external_memory_tools::ExternalMemory;
use substrate_parser::traits::AsMetadata;

/// Error in generating shortened metadata.
#[derive(Debug, Eq, PartialEq)]
pub enum MetaCutError<E: ExternalMemory, M: AsMetadata<E>> {
    NoEntryLargerRegistry,
    Registry(RegistryCutError),
    Signable(SignableError<E, M>),
    #[cfg(any(feature = "merkle-lean", test))]
    TreeCalculateProof(ErrorMT<E>),
    #[cfg(any(feature = "merkle-lean", test))]
    TreeCalculateRoot(ErrorMT<E>),
    #[cfg(any(feature = "merkle-lean", test))]
    TreeConstructProof(ErrorMT<E>),
}

/// Error in generating shortened registry.
#[derive(Debug, Eq, PartialEq)]
pub enum RegistryCutError {
    IndexTwice { id: u32 },
}

impl<E: ExternalMemory, M: AsMetadata<E>> MetaCutError<E, M> {
    fn error_text(&self) -> String {
        match &self {
            MetaCutError::NoEntryLargerRegistry => String::from("While forming metadata types registry with excluded types, found type that should exist in larger registry, but does not. This is code bug, please report it."),
            MetaCutError::Registry(registry_cut_error) => format!("{registry_cut_error}"),
            MetaCutError::Signable(signable_error) => format!("{signable_error}"),
            #[cfg(any(feature = "merkle-lean", test))]
            MetaCutError::TreeCalculateProof(error_merkle_tree) => format!("Unable to calculate proof for merkle tree. {error_merkle_tree}"),
            #[cfg(any(feature = "merkle-lean", test))]
            MetaCutError::TreeCalculateRoot(error_merkle_tree) => format!("Unable to calculate root hash. {error_merkle_tree}"),
            #[cfg(any(feature = "merkle-lean", test))]
            MetaCutError::TreeConstructProof(error_merkle_tree) => format!("Unable to construct proof with provided data. {error_merkle_tree}"),
        }
    }
}

impl RegistryCutError {
    fn error_text(&self) -> String {
        match &self {
            RegistryCutError::IndexTwice{id} => format!("While forming shortened metadata types registry, tried to enter type with already existing index {id} and different description. This is code bug, please report it."),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum MetadataDescriptorError {
    DescriptorVersionIncompatible,
}

impl MetadataDescriptorError {
    fn error_text(&self) -> String {
        match &self {
            MetadataDescriptorError::DescriptorVersionIncompatible => {
                String::from("MetadataDescriptor version is incompatible.")
            }
        }
    }
}

/// Implement [`Display`] for errors in both `std` and `no_std` cases.
/// Implement `Error` for `std` case.
macro_rules! impl_display_and_error {
    ($($ty: ty), *) => {
        $(
            impl Display for $ty {
                fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
                    write!(f, "{}", self.error_text())
                }
            }

            #[cfg(feature = "std")]
            impl Error for $ty {
                fn source(&self) -> Option<&(dyn Error + 'static)> {
                    None
                }
            }
        )*
    }
}

impl_display_and_error!(MetadataDescriptorError, RegistryCutError);

/// Implement [`Display`] for errors in both `std` and `no_std` cases.
/// Implement `Error` for `std` case.
macro_rules! impl_display_and_error_traited {
    ($($ty: ty), *) => {
        $(
            impl <E: ExternalMemory, M: AsMetadata<E>> Display for $ty {
                fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
                    write!(f, "{}", self.error_text())
                }
            }

            #[cfg(feature = "std")]
            impl <E: ExternalMemory, M: AsMetadata<E>> Error for $ty {
                fn source(&self) -> Option<&(dyn Error + 'static)> {
                    None
                }
            }
        )*
    }
}

impl_display_and_error_traited!(MetaCutError<E, M>);
