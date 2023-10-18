//! This crate is a shortener and digest generation tool for Substrate chains
//! metadata.
//!
//! # Shortened metadata
//!
//! During chain data parsing, only small fraction of the chain metadata is
//! actually utilized.
//!
//! Hardware signer devices with limited memory capability can encounter
//! difficulties receiving and processing whole metadata which size is
//! typically a few hundred kB.
//! Receiving and using only the part required for decoding of particular data
//! piece greatly simplifies the task, as the typical metadata part size
//! decreases down to few kB.
//!
//! Decoding of the signable transaction, or extrinsic, requires both
//! information on extrinsic structure and the description of corresponding
//! types. Signable transaction is built as a SCALE-encoded call and
//! SCALE-encoded extensions concatenated to it. Call may or may not be double
//! SCALE-encoded, i.e. preceded by [compact](parity_scale_codec::Compact) of
//! the call length.
//!
//! Type describing all calls available is the type of `Call` parameter of the
//! `ty` type in [`ExtrinsicMetadata`](frame_metadata::v14::ExtrinsicMetadata).
//! The extensions set is determined by `signed_extensions` in
//! `ExtrinsicMetadata`.
//!
//! [`ShortMetadata`] contains:
//!
//! - short types registry [`ShortRegistry`] with description of all types
//! needed for signable transaction decoding (both for
//! call and for extensions),
//! - data from missing types, sufficient for Merkle tree root hash calculation
//! (part of digest calculation, see below),
//! - [`MetadataDescriptor`] with other relatively short data necessary for
//! decoding and appropriate data representation
//!
//! Note: chain specs (except base58 prefix in some cases) are **not** in the
//! metadata, and should be fetched from chain and provided separately on
//! `ShortMetadata` generation step, as [`ShortSpecs`].
//!
//! `ShortRegistry` is generated on the hot side, as the the transaction is
//! preliminarily decoded and the types used are collected. Entries in
//! `ShortRegistry` are [`ShortRegistryEntry`] values with unique `id` (same as
//! in [`PortableRegistry`](scale_info::PortableRegistry)) for type resolving
//! and [`Type`](scale_info::Type) itself. For enums (except `Option<_>`) only
//! the variants used in actual decoding are retained, all enum variants remain
//! within a single entry. `Option<_>` is treated as a regular type, since there
//! is [`Option<bool>`](parity_scale_codec::OptionBool) requiring special
//! decoding approach.
//!
//! `ShortMetadata` is generated with
//! [`cut_metadata`](crate::cut_metadata::cut_metadata) for transactions with
//! double SCALE-encoded call part (length-prefixed), and with
//! [`cut_metadata_transaction_unmarked`] for single SCALE-encoded call part.
//!
//! `ShortMetadata` implements trait
//! [`AsMetadata`](substrate_parser::AsMetadata) and could be used for chain
//! data decoding using tools of [`substrate_parser`] crate.
//!
//! # Example
//! ```
//! # #[cfg(feature = "std")]
//! # {
//! use frame_metadata::v14::RuntimeMetadataV14;
//! use metadata_shortener::{cut_metadata, ShortMetadata, ShortSpecs};
//! use parity_scale_codec::{Decode, Encode};
//! use primitive_types::H256;
//! use std::str::FromStr;
//! use substrate_parser::{parse_transaction, AsMetadata};
//!
//! // SCALE-encoded metadata, read from file.
//! let meta_file = std::fs::read("for_tests/westend9430").unwrap();
//! let meta = Vec::<u8>::decode(&mut &meta_file[..]).unwrap();
//!
//! // Full metadata is quite bulky. Check SCALE-encoded size here, for simplicity:
//! assert_eq!(300431, meta.len());
//!
//! // Full `RuntimeMetadataV14`, ready to use.
//! let full_metadata = RuntimeMetadataV14::decode(&mut &meta[5..]).unwrap();
//!
//! let specs_westend = ShortSpecs {
//!     base58prefix: 42,
//!     decimals: 12,
//!     unit: "WND".to_string(),
//! };
//!
//! // Transaction for which the metadata is cut: utility batch call combining
//! // two staking calls.
//! let data = hex::decode("c901100208060007001b2c3ef70006050c0008264834504a64ace1373f0c8ed5d57381ddf54a2f67a318fa42b1352681606d00aebb0211dbb07b4d335a657257b8ac5e53794c901e4f616d4a254f2490c43934009ae581fef1fc06828723715731adcf810e42ce4dadad629b1b7fa5c3c144a81d55000800d624000007000000e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e5b1d91c89d3de85a4d6eee76ecf3a303cf38b59e7d81522eb7cd24b02eb161ff").unwrap();
//!
//! // Make short metadata here. It is sufficient to decode the transaction.
//! let short_metadata =
//!     cut_metadata(&data.as_ref(), &mut (), &full_metadata, &specs_westend).unwrap();
//!
//! // `ShortMetadata` is substantially shorter. SCALE-encoded size:
//! assert_eq!(4607, short_metadata.encode().len());
//!
//! // Genesis hash, required for decoding:
//! let westend_genesis_hash =
//!     H256::from_str("e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e").unwrap();
//!
//! // Now check that decoding result remains unchanged.
//!
//! // Transaction parsed with shortened metadata, carded:
//! let parsed_with_short_meta = parse_transaction(
//!     &data.as_ref(),
//!     &mut (),
//!     &short_metadata,
//!     westend_genesis_hash,
//! )
//! .unwrap()
//! .card(
//!     &short_metadata.to_specs(),
//!     &<ShortMetadata as AsMetadata<()>>::spec_name_version(&short_metadata)
//!         .unwrap()
//!         .spec_name,
//! );
//!
//! // Transaction parsed with full metadata, carded:
//! let parsed_with_full_meta = parse_transaction(
//!     &data.as_ref(),
//!     &mut (),
//!     &full_metadata,
//!     westend_genesis_hash,
//! )
//! .unwrap()
//! .card(
//!     &specs_westend,
//!     &<RuntimeMetadataV14 as AsMetadata<()>>::spec_name_version(&full_metadata)
//!         .unwrap()
//!         .spec_name,
//! );
//!
//! // Call parsing result for short metadata (printed cards, without documentation):
//! let call_printed_short_meta = parsed_with_short_meta
//!     .call_result
//!     .unwrap()
//!     .iter()
//!     .map(|card| card.show())
//!     .collect::<Vec<String>>()
//!     .join("\n");
//!
//! // Call parsing result for full metadata (printed cards, without documentation):
//! let call_printed_full_meta = parsed_with_full_meta
//!     .call_result
//!     .unwrap()
//!     .iter()
//!     .map(|card| card.show())
//!     .collect::<Vec<String>>()
//!     .join("\n");
//!
//! // Call parsing results did not change.
//! assert_eq!(call_printed_short_meta, call_printed_full_meta);
//!
//! // Extensions parsing result for short metadata (printed cards, without documentation):
//! let extensions_printed_short_meta = parsed_with_short_meta
//!     .extensions
//!     .iter()
//!     .map(|card| card.show())
//!     .collect::<Vec<String>>()
//!     .join("\n");
//!
//! // Extensions parsing result for short metadata (printed cards, without documentation):
//! let extensions_printed_full_meta = parsed_with_full_meta
//!     .extensions
//!     .iter()
//!     .map(|card| card.show())
//!     .collect::<Vec<String>>()
//!     .join("\n");
//!
//! // Extensions parsing results did not change.
//! assert_eq!(extensions_printed_short_meta, extensions_printed_full_meta);
//! # }
//! ```
//!
//! # Metadata digest
//!
//! The decoding of the chain data is beneficial from safety viewpoint only if
//! the metadata can be guaranteed to be authentic.
//! A possible solution to that would be to produce a digest of the metadata and
//! concat it to the signable transaction prior to signing, so that the
//! signature would be valid only if the metadata used for decoding matches the
//! one on chain. This crate generates such digest, both for complete and for
//! shortened metadata.
//!
//! Digest is generated by merging the root hash of the Merkle tree build over
//! metadata's [`PortableRegistry`](scale_info::PortableRegistry)) with the hash
//! of SCALE-encoded [`MetadataDescriptor`].
//!
//! ## Merkle tree for types data
//!
//! Merkle tree is generated and processed using tools of [`merkle_cbt`] crate.
//! Merkle leaves are blake3-hashed SCALE-encoded individual
//! [`ShortRegistryEntry`] values. In enums (except `Option<_>` enums) same `id`
//! is used for every retained variant, and every retained variant is placed as
//! an individual enum with a single variant.
//!
//! For full metadata `RuntimeMetadataV14`, all leaves are constructed,
//! deterministically sorted, and processed to build the Merkle tree, and then
//! the root hash.
//! In `ShortMetadata`, the available types data is transformed into leaves and
//! combined with `MerkleProof` to calculate the root hash.
//!
//! Trait [`HashableRegistry`](crate::traits::HashableRegistry) for producing
//! sorted set of Merkle tree leaves is implemented for
//! [`PortableRegistry`](scale_info::PortableRegistry) and for
//! [`ShortRegistry`].
//!
//! Trait [`HashableMetadata`](crate::traits::HashableMetadata) for producing
//! Merkle tree root hash is implemented for
//! [`RuntimeMetadataV14`](frame_metadata::v14::RuntimeMetadataV14) and for
//! [`ShortMetadata`]. Complete digest could be calculated for
//! `HashableMetadata` if `MetadataDescriptor` is provided.
//!
//! [`ShortMetadata`] also implements trait
//! [`ExtendedMetadata`](crate::traits::ExtendedMetadata) for digest calculation
//! without additional data.
//!
//! ## `MetadataDescriptor`
//!
//! `MetadataDescriptor` contains other relatively short data necessary for
//! decoding and appropriate data representation:
//!
//! - `ExtrinsicMetadata` cloned from full metadata,
//! - chain spec name and spec version (extracted from `Version` constant of the
//! `System` pallet)
//! - chain specs (base58 prefix for in-chain Ss58 address representation,
//! decimals and unit for balance values representation)
//!
//! `MetadataDescriptor` is versioned to simplify version compatibility check on
//! the hardware side.
//!
//! # Example
//! ```
//! # #[cfg(feature = "std")]
//! # {
//!     use frame_metadata::v14::RuntimeMetadataV14;
//! use metadata_shortener::{
//!     cut_metadata,
//!     traits::{ExtendedMetadata, HashableMetadata},
//!     MetadataDescriptor, ShortMetadata, ShortSpecs,
//! };
//! use parity_scale_codec::Decode;
//! use substrate_parser::AsMetadata;
//!
//! // SCALE-encoded metadata, read from file.
//! let meta_file = std::fs::read("for_tests/westend9430").unwrap();
//! let meta = Vec::<u8>::decode(&mut &meta_file[..]).unwrap();
//!
//! // Full `RuntimeMetadataV14`, ready to use.
//! let full_metadata = RuntimeMetadataV14::decode(&mut &meta[5..]).unwrap();
//!
//! let specs_westend = ShortSpecs {
//!     base58prefix: 42,
//!     decimals: 12,
//!     unit: "WND".to_string(),
//! };
//!
//! // Full metadata digest:
//! let digest_full_metadata =
//!     <RuntimeMetadataV14 as HashableMetadata<()>>::digest_with_short_specs(
//!         &full_metadata,
//!         &specs_westend,
//!     )
//!     .unwrap();
//!
//! // Same transaction as in above example.
//! let data = hex::decode("c901100208060007001b2c3ef70006050c0008264834504a64ace1373f0c8ed5d57381ddf54a2f67a318fa42b1352681606d00aebb0211dbb07b4d335a657257b8ac5e53794c901e4f616d4a254f2490c43934009ae581fef1fc06828723715731adcf810e42ce4dadad629b1b7fa5c3c144a81d55000800d624000007000000e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e5b1d91c89d3de85a4d6eee76ecf3a303cf38b59e7d81522eb7cd24b02eb161ff").unwrap();
//!
//! // Generate short metadata:
//! let short_metadata =
//!     cut_metadata(&data.as_ref(), &mut (), &full_metadata, &specs_westend).unwrap();
//!
//! // Short metadata digest:
//! let digest_short_metadata =
//!     <ShortMetadata as ExtendedMetadata<()>>::digest(&short_metadata).unwrap();
//!
//! // Check that digest values match:
//! assert_eq!(digest_short_metadata, digest_full_metadata);
//! # }
//! ```
//!
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

pub use crate::cut_metadata::{
    cut_metadata, cut_metadata_transaction_unmarked, MetadataDescriptor, ShortMetadata,
    ShortRegistry, ShortRegistryEntry,
};
pub use substrate_parser::ShortSpecs;
