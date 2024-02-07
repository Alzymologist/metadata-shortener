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
//! Type describing all calls available is `call_ty` field in
//! [`ExtrinsicMetadata`](https://docs.rs/frame-metadata/latest/frame_metadata/v15/struct.ExtrinsicMetadata.html).
//! The extensions set is determined by `signed_extensions` in
//! `ExtrinsicMetadata`.
//!
//! `ShortMetadata` contains:
//!
//! - short types registry [`ShortRegistry`] with description of all types
//! needed for signable transaction decoding (both for
//! call and for extensions),
//! - data from missing types, sufficient for Merkle tree root hash calculation
//! (part of digest calculation, see below),
//! - [`MetadataDescriptor`] with other relatively short data necessary for
//! decoding and appropriate data representation
//!
//! Note: chain specs (except base58 prefix in some cases) are a part of
//! `MetadataDescriptor`, but are **not** in the full metadata, and should be
//! fetched from chain and provided separately on `ShortMetadata` generation
//! step, as [`ShortSpecs`].
//!
//! `ShortRegistry` is generated on the hot side, as the the transaction is
//! preliminarily decoded and the types used are collected. Entries in
//! `ShortRegistry` are [`PortableType`](scale_info::PortableType) values with
//! unique `id` (same as in [`PortableRegistry`](scale_info::PortableRegistry))
//! for type resolving and [`Type`](scale_info::Type) itself. For enums only the
//! variants used in actual decoding are retained, all enum variants remain
//! within a single entry.
//!
//! `ShortMetadata` is generated with
//! `cut_metadata` function for transactions with
//! double SCALE-encoded call part (length-prefixed), and with
//! `cut_metadata_transaction_unmarked` function for single SCALE-encoded call
//! part.
//!
//! `ShortMetadata` implements trait
//! [`AsMetadata`](substrate_parser::AsMetadata) and could be used for chain
//! data decoding using tools of [`substrate_parser`] crate.
//!
//! SCALE-encoded `ShortMetadata` structure (as received by the cold side) is
//! following:
//!
//! - `ShortRegistry`:
//!   - [Compact](parity_scale_codec::Compact) of the number of types described
//! in `ShortRegistry`
//!   - For each of the given number of types:
//!     - compact type `id` (same number as in original full metadata, for type
//! resolving)
//!     - SCALE-encoded [`Type`](scale_info::Type), encoded size is not known
//! before decoding
//! - Indices for Merkle tree leaves derived from types in `ShortRegistry`:
//!   - Compact of the number of indices for Merkle tree leaves derived from
//! types in `ShortRegistry`
//!   - Given number of SCALE-encoded `u32` indices, 4 bytes each
//! - Merkle tree lemmas:
//!   - Compact of the number of lemmas for Merkle tree
//!   - Given number of lemmas, 32 bytes each
//! - SCALE-encoded [`MetadataDescriptor`]:
//!   - 1-byte version of [`MetadataDescriptor`] (currently the only functioning
//! variant is `1`). For version `1`:
//!     - `id` in types registry for the type describing all available calls
//!     - Signed extensions set:
//!         - Compact of the number of provided [`SignedExtensionMetadata`]
//! entries
//!         - Given number of SCALE-encoded `SignedExtensionMetadata`, encoded
//! size of each is not known before decoding
//!     - Compact length of the printed spec version followed by corresponding
//! number of utf8 bytes
//!     - Compact length of the chain spec name followed by corresponding number
//! of utf8 bytes
//!     - SCALE-encoded `u16` base58 prefix value for the chain, 2 bytes
//!     - SCALE-encoded `u8` decimals value for the chain, 1 byte
//!     - Compact length of the unit value for the chain followed by
//! corresponding number of utf8 bytes
//!
//! # Example
//! ```
//! # #[cfg(all(feature = "std", feature = "merkle-standard", feature = "proof-gen"))]
//! # {
//! use frame_metadata::v15::RuntimeMetadataV15;
//! use metadata_shortener::{
//!     traits::{Blake3Leaf, ExtendedMetadata},
//!     cut_metadata, ShortMetadata, ShortSpecs,
//! };
//! use parity_scale_codec::{Decode, Encode};
//! use primitive_types::H256;
//! use std::str::FromStr;
//! use substrate_parser::{parse_transaction, AsMetadata};
//!
//! // Hex metadata string, read from file.
//! let meta_hex = std::fs::read_to_string("for_tests/westend1006001").unwrap();
//! let meta = hex::decode(meta_hex.trim()).unwrap();
//!
//! // Full metadata is quite bulky. Check SCALE-encoded size here, for simplicity:
//! assert_eq!(291897, meta.len());
//!
//! // Full `RuntimeMetadataV15`, ready to use.
//! let full_metadata = RuntimeMetadataV15::decode(&mut &meta[5..]).unwrap();
//!
//! let specs_westend = ShortSpecs {
//!     base58prefix: 42,
//!     decimals: 12,
//!     unit: "WND".to_string(),
//! };
//!
//! // Transaction for which the metadata is cut: utility batch call combining
//! // two staking calls.
//! let data = hex::decode("c901100208060007001b2c3ef70006050c0008264834504a64ace1373f0c8ed5d57381ddf54a2f67a318fa42b1352681606d00aebb0211dbb07b4d335a657257b8ac5e53794c901e4f616d4a254f2490c43934009ae581fef1fc06828723715731adcf810e42ce4dadad629b1b7fa5c3c144a81d55000800b1590f0007000000e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e5b1d91c89d3de85a4d6eee76ecf3a303cf38b59e7d81522eb7cd24b02eb161ff").unwrap();
//!
//! // Make short metadata here. It is sufficient to decode the transaction.
//! let short_metadata =
//!     cut_metadata(&data.as_ref(), &mut (), &full_metadata, &specs_westend).unwrap();
//!
//! // `ShortMetadata` is substantially shorter. SCALE-encoded size:
//! assert_eq!(4486, short_metadata.encode().len());
//!
//! // Now check that decoding result remains unchanged.
//!
//! // Transaction parsed with shortened metadata, carded:
//! let parsed_with_short_meta = parse_transaction(
//!     &data.as_ref(),
//!     &mut (),
//!     &short_metadata,
//!     None,
//! )
//! .unwrap()
//! .card(
//!     &<ShortMetadata<Blake3Leaf, ()> as ExtendedMetadata<()>>::to_specs(&short_metadata)
//!         .unwrap(),
//!     &<ShortMetadata<Blake3Leaf, ()> as AsMetadata<()>>::spec_name_version(&short_metadata)
//!         .unwrap()
//!         .spec_name,
//! );
//!
//! // Transaction parsed with full metadata, carded:
//! let parsed_with_full_meta = parse_transaction(
//!     &data.as_ref(),
//!     &mut (),
//!     &full_metadata,
//!     None,
//! )
//! .unwrap()
//! .card(
//!     &specs_westend,
//!     &<RuntimeMetadataV15 as AsMetadata<()>>::spec_name_version(&full_metadata)
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
//! metadata's [`PortableRegistry`](scale_info::PortableRegistry) with the hash
//! of SCALE-encoded [`MetadataDescriptor`].
//!
//! ## Merkle tree for types data
//!
//! Merkle tree is generated and processed using tools of
//! [`merkle_cbt`](https://docs.rs/merkle-cbt/latest/merkle_cbt/) and
//! [`merkle_cbt_lean`](https://docs.rs/merkle-cbt-lean/latest/merkle_cbt_lean/)
//! crates. While providing the same outcome, `merkle_cbt_lean` is tailored for
//! `no_std` environments with low memory capacities.
//!
//! Merkle leaves are blake3-hashed SCALE-encoded individual
//! [`PortableType`](scale_info::PortableType) values. In enums the same `id` is
//! used for every retained variant, and every retained variant is placed as an
//! individual enum with a single variant.
//!
//! For full metadata
//! [`RuntimeMetadataV15`](https://docs.rs/frame-metadata/latest/frame_metadata/v15/struct.RuntimeMetadataV15.html),
//! all leaves are constructed, deterministically sorted, and processed to build
//! the Merkle tree, and then the root hash.
//! In `ShortMetadata`, the available types data is transformed into leaves
//! and combined with `MerkleProof` to calculate the root hash.
//!
//! Trait [`HashableRegistry`](crate::traits::HashableRegistry) for producing
//! sorted set of Merkle tree leaves is implemented for
//! [`PortableRegistry`](scale_info::PortableRegistry) and for
//! [`ShortRegistry`].
//!
//! Trait `HashableMetadata` for producing Merkle tree root hash is implemented
//! both for
//! [`RuntimeMetadataV15`](https://docs.rs/frame-metadata/latest/frame_metadata/v15/struct.RuntimeMetadataV15.html)
//! and for `ShortMetadata`. Complete digest could be calculated for
//! `HashableMetadata` if `ShortSpecs` are provided.
//!
//! `ShortMetadata` also implements trait `ExtendedMetadata` for digest
//! calculation and transaction parsing without providing additional data.
//!
//! ## Metadata descriptor
//!
//! `MetadataDescriptor` contains other relatively short data necessary for
//! decoding and appropriate data representation:
//!
//! - `id` in types registry for the type describing all available calls
//! - set of signed extension metadata entries [`SignedExtensionMetadata`]
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
//! # #[cfg(all(feature = "std", feature = "merkle-standard", feature = "proof-gen"))]
//! # {
//! use frame_metadata::v15::RuntimeMetadataV15;
//! use metadata_shortener::{
//!     cut_metadata,
//!     traits::{Blake3Leaf, ExtendedMetadata, HashableMetadata},
//!     MetadataDescriptor, ShortMetadata, ShortSpecs,
//! };
//! use parity_scale_codec::Decode;
//! use substrate_parser::AsMetadata;
//!
//! // Hex metadata string, read from file.
//! let meta_hex = std::fs::read_to_string("for_tests/westend1006001").unwrap();
//! let meta = hex::decode(meta_hex.trim()).unwrap();
//!
//! // Full `RuntimeMetadataV15`, ready to use.
//! let full_metadata = RuntimeMetadataV15::decode(&mut &meta[5..]).unwrap();
//!
//! let specs_westend = ShortSpecs {
//!     base58prefix: 42,
//!     decimals: 12,
//!     unit: "WND".to_string(),
//! };
//!
//! // Full metadata digest:
//! let digest_full_metadata =
//!     <RuntimeMetadataV15 as HashableMetadata<()>>::digest_with_short_specs(
//!         &full_metadata,
//!         &specs_westend,
//!         &mut (),
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
//!     <ShortMetadata<Blake3Leaf, ()> as ExtendedMetadata<()>>::digest(
//!         &short_metadata,
//!         &mut ()
//!     ).unwrap();
//!
//! // Check that digest values match:
//! assert_eq!(digest_short_metadata, digest_full_metadata);
//! # }
//! ```
//!
//! # RuntimeMetadata versions support
//!
//! [`RuntimeMetadataV14`](https://docs.rs/frame-metadata/latest/frame_metadata/v14/struct.RuntimeMetadataV14.html)
//! implements trait `AsMetadata` and could be used for transactions decoding.
//!
//! Trait `HashableMetadata` could be implemented for `RuntimeMetadataV14` (and,
//! in fact, was, in earlier editions of this crate), but intentionally is not.
//!
//! The types registry of `RuntimeMetadataV14` has structure similar to that of
//! `RuntimeMetadataV15`, however, the types in registries for same
//! `spec_version` are different in `V14` and `V15`, with `RuntimeMetadataV14`
//! having types not available in `RuntimeMetadataV15` and vise versa, thus
//! making it not feasible to support both simultaneously during the
//! transitioning phase.
//!
//! V15 and above are expected to be supported.
//!
//! # Available features
//!
//! - `merkle-standard`: for calculating `RuntimeMetadataV15` digest using tools
//! of [`merkle_cbt`](https://docs.rs/merkle-cbt/latest/merkle_cbt/)
//! crate. Intended for signature checking side. Digest is constant while
//! metadata `spec_version` remains the same.
//!
//! - `merkle-lean`: for calculating `ShortMetadata` digest on cold signer side
//! using tools of
//! [`merkle_cbt_lean`](https://docs.rs/merkle-cbt-lean/latest/merkle_cbt_lean/)
//! crate.
//!
//! - `proof-gen`: for generating `ShortMetadata` on wallet side, using tools of
//! [`merkle_cbt_lean`](https://docs.rs/merkle-cbt-lean/latest/merkle_cbt_lean/)
//! crate. `proof-gen` feature includes `merkle-lean`.
//!
//! - `std`
//!
//! By default, all features are made available.
//!
#![no_std]
#![deny(unused_crate_dependencies)]

pub mod cutter;
pub mod error;
#[cfg(test)]
#[cfg(any(feature = "merkle-standard", feature = "merkle-lean", test))]
mod tests;
pub mod traits;

#[cfg(any(feature = "std", test))]
#[macro_use]
extern crate std;

#[cfg(all(not(feature = "std"), not(test)))]
#[macro_use]
extern crate alloc as std;

#[cfg(feature = "merkle-lean")]
pub use crate::cutter::ShortMetadata;
#[cfg(feature = "proof-gen")]
pub use crate::cutter::{cut_metadata, cut_metadata_transaction_unmarked};
pub use crate::cutter::{MetadataDescriptor, ShortRegistry};

pub use substrate_parser::{
    traits::{SignedExtensionMetadata, SpecNameVersion},
    ShortSpecs,
};
