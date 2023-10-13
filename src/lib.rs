//! This crate is a shortener and digest generation tool for Substrate chains
//! metadata.
//!
//! During chain data parsing, only small fraction of the chain metadata is
//! actually utilized.
//! Hardware signer devices with limited memory capability can encounter
//! difficulties receiving and processing whole metadata which size is
//! typically a few hundred kB.
//! Receiving and using only the part required for decoding of particular data
//! piece greatly simplifies the task, as the typical metadata part size
//! decreases down to few kB.
//!
//! The decoding of the chain data is beneficial from safety viewpoint only if
//! the metadata can be guaranteed to not be tampered with.
//! A possible solution to that would be produce a digest of the metadata and
//! concat it to the signable transaction prior to signing, so that the
//! signature would be valid only if the metadata used for decoding matches the
//! one on chain. This crate generates such digest.
#![no_std]
#![deny(unused_crate_dependencies)]

pub mod cut_metadata;
pub mod error;
#[cfg(test)]
mod tests;
pub mod traits;

#[cfg(any(feature = "std", test))]
#[macro_use]
extern crate std;

#[cfg(all(not(feature = "std"), not(test)))]
#[macro_use]
extern crate alloc as std;
