//! Traits for digest generation.
use crate::std::borrow::ToOwned;

#[cfg(all(any(feature = "merkle-lean", test), not(feature = "std")))]
use core::any::TypeId;
#[cfg(all(any(feature = "merkle-lean", test), feature = "std"))]
use std::any::TypeId;

#[cfg(any(feature = "merkle-standard", feature = "merkle-lean", test))]
use crate::std::vec::Vec;

#[cfg(any(feature = "merkle-lean", feature = "merkle-standard", test))]
use external_memory_tools::AddressableBuffer;
use external_memory_tools::ExternalMemory;

#[cfg(any(feature = "merkle-standard", test))]
use frame_metadata::v15::RuntimeMetadataV15;

#[cfg(any(feature = "merkle-standard", test))]
use merkle_cbt::{merkle_tree::Merge, CBMT};

#[cfg(any(feature = "merkle-lean", test))]
use merkle_cbt_lean::{Hasher, Leaf, MerkleProof};

use parity_scale_codec::{Decode, Encode};

#[cfg(any(feature = "merkle-lean", test))]
use scale_info::interner::UntrackedSymbol;
#[cfg(any(feature = "merkle-standard", test))]
use scale_info::PortableType;
use scale_info::{form::PortableForm, PortableRegistry, Type, TypeDef};

#[cfg(any(feature = "merkle-lean", test))]
use substrate_parser::traits::{SignedExtensionMetadata, SpecNameVersion};
#[cfg(any(feature = "merkle-lean", feature = "merkle-standard", test))]
use substrate_parser::{
    error::SignableError, parse_transaction, parse_transaction_unmarked, traits::AsMetadata,
    ShortSpecs, TransactionParsed, TransactionUnmarkedParsed,
};
use substrate_parser::{
    error::{RegistryError, RegistryInternalError},
    traits::ResolveType,
};

#[cfg(any(feature = "merkle-lean", feature = "merkle-standard", test))]
use crate::cutter::MetadataDescriptor;
#[cfg(any(feature = "merkle-lean", test))]
use crate::cutter::ShortMetadata;
use crate::cutter::{add_as_enum, add_ty_as_regular, DraftRegistry, LeavesRegistry, ShortRegistry};

#[cfg(any(feature = "merkle-lean", feature = "merkle-standard", test))]
use crate::error::MetaCutError;
#[cfg(any(feature = "merkle-lean", test))]
use crate::error::MetadataDescriptorError;
use crate::error::RegistryCutError;

/// Hash length used throughout this crate.
pub const LEN: usize = 32;

/// Hasher used throughout this crate. Specifies hash structure and merging.
#[derive(Debug)]
pub struct Blake3Hasher;

#[cfg(any(feature = "merkle-lean", test))]
impl Hasher<LEN> for Blake3Hasher {
    fn make(bytes: &[u8]) -> [u8; LEN] {
        blake3::hash(bytes).into()
    }
    fn merge(left: &[u8; LEN], right: &[u8; LEN]) -> [u8; LEN] {
        blake3::hash(&[left.as_slice(), right.as_slice()].concat()).into()
    }
}

/// [`MerkleProof`] for metadata.
///
/// Hash length is set to [`LEN`], [`Hasher`] is specified as [`Blake3Hasher`].
#[cfg(any(feature = "merkle-lean", test))]
pub type MerkleProofMetadata<L, E> = MerkleProof<LEN, L, E, Blake3Hasher>;

/// Example Merkle tree leaf. Length is set to [`LEN`], value is available
/// without external memory access.
#[derive(Copy, Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct Blake3Leaf([u8; LEN]);

#[cfg(any(feature = "proof-gen", test))]
impl<E: ExternalMemory> Leaf<LEN, E> for Blake3Leaf {
    fn read(&self, _ext_memory: &mut E) -> Result<[u8; LEN], E::ExternalMemoryError> {
        Ok(self.0)
    }
    fn write(value: [u8; LEN], _ext_memory: &mut E) -> Result<Self, E::ExternalMemoryError> {
        Ok(Self(value))
    }
}

#[cfg(any(feature = "merkle-standard", test))]
impl Merge for Blake3Hasher {
    type Item = [u8; LEN];
    fn merge(left: &Self::Item, right: &Self::Item) -> Self::Item {
        blake3::hash(&[*left, *right].concat()).into()
    }
}

/// Make blake3 hash for values implementing `Encode`.
///
/// Applied on individual [`PortableType`] in Merkle tree generation and on
/// [`MetadataDescriptor`] in digest calculation.
#[cfg(any(feature = "merkle-standard", test))]
pub fn blake3_leaf<T: Encode>(value: &T) -> [u8; LEN] {
    blake3::hash(value.encode().as_ref()).into()
}

/// [`AsMetadata`] with registry implementing [`HashableRegistry`].
#[cfg(any(feature = "merkle-lean", feature = "merkle-standard", test))]
pub trait HashableMetadata<E: ExternalMemory>: AsMetadata<E>
where
    <Self as AsMetadata<E>>::TypeRegistry: HashableRegistry<E>,
{
    /// Calculate Merkle tree root hash for original complete types data.
    ///
    /// This root hash must be identical both for shortened and full metadata.
    /// Note that for any shortened metadata in addition to known types data,
    /// serialized Merkle proof data would be required.
    fn types_merkle_root(&self, ext_memory: &mut E) -> Result<[u8; LEN], MetaCutError<E, Self>>;

    /// Calculate full digest with additionally provided chain [`ShortSpecs`].
    fn digest_with_short_specs(
        &self,
        short_specs: &ShortSpecs,
        ext_memory: &mut E,
    ) -> Result<[u8; LEN], MetaCutError<E, Self>> {
        let types_merkle_root = self.types_merkle_root(ext_memory)?;
        let metadata_descriptor = MetadataDescriptor::V1 {
            call_ty: self
                .call_ty()
                .map_err(|e| MetaCutError::Signable(SignableError::MetaStructure(e)))?,
            signed_extensions: self
                .signed_extensions()
                .map_err(|e| MetaCutError::Signable(SignableError::MetaStructure(e)))?,
            spec_name_version: self
                .spec_name_version()
                .map_err(|e| MetaCutError::Signable(SignableError::MetaStructure(e)))?,
            base58prefix: short_specs.base58prefix,
            decimals: short_specs.decimals,
            unit: short_specs.unit.to_owned(),
        };
        #[cfg(all(feature = "merkle-standard", not(test)))]
        {
            let metadata_descriptor_blake3 =
                blake3_leaf::<MetadataDescriptor>(&metadata_descriptor);
            Ok(<Blake3Hasher as Merge>::merge(
                &types_merkle_root,
                &metadata_descriptor_blake3,
            ))
        }
        #[cfg(any(not(feature = "merkle-standard"), test))]
        {
            let metadata_descriptor_blake3 = Blake3Hasher::make(&metadata_descriptor.encode());
            Ok(<Blake3Hasher as Hasher<LEN>>::merge(
                &types_merkle_root,
                &metadata_descriptor_blake3,
            ))
        }
    }
}

/// [`HashableMetadata`] with in-built [`ShortSpecs`].
#[cfg(any(feature = "merkle-lean", feature = "merkle-standard", test))]
pub trait ExtendedMetadata<E: ExternalMemory>: HashableMetadata<E> + Sized
where
    <Self as AsMetadata<E>>::TypeRegistry: HashableRegistry<E>,
{
    /// Extract [`ShortSpecs`].
    fn to_specs(&self) -> Result<ShortSpecs, <Self as AsMetadata<E>>::MetaStructureError>;

    /// Calculate full digest.
    fn digest(&self, ext_memory: &mut E) -> Result<[u8; LEN], MetaCutError<E, Self>> {
        self.digest_with_short_specs(
            &self
                .to_specs()
                .map_err(|e| MetaCutError::Signable(SignableError::MetaStructure(e)))?,
            ext_memory,
        )
    }

    /// Parse transaction (with call length compact prefix, standard form).
    ///
    /// Note that the chain genesis hash is not provided for
    /// [`substrate_parser::parse_transaction`] here and genesis hash from
    /// transaction is not checked to match that of the chain.
    ///
    /// Genesis hash is nonetheless a part of signed bytes (without the genesis
    /// hash the extensions set is considered invalid by [`substrate_parser`]).
    /// Metadata `spec_name` is contained in [`MetadataDescriptor`] and thus
    /// participates in digest calculation.
    fn parse_transaction<B>(
        &self,
        data: &B,
        ext_memory: &mut E,
    ) -> Result<TransactionParsed<E, Self>, SignableError<E, Self>>
    where
        B: AddressableBuffer<E>,
    {
        parse_transaction::<B, E, Self>(data, ext_memory, self, None)
    }

    /// Parse unmarked transaction (**no** call length compact prefix).
    ///
    /// Note that the chain genesis hash is not provided for
    /// [`substrate_parser::parse_transaction_unmarked`] here and genesis hash
    /// from transaction is not checked to match that of the chain.
    ///
    /// Genesis hash is nonetheless a part of signed bytes (without the genesis
    /// hash the extensions set is considered invalid by [`substrate_parser`]).
    /// Metadata `spec_name` is contained in [`MetadataDescriptor`] and thus
    /// participates in digest calculation.
    fn parse_transaction_unmarked<B>(
        &self,
        data: &B,
        ext_memory: &mut E,
    ) -> Result<TransactionUnmarkedParsed, SignableError<E, Self>>
    where
        B: AddressableBuffer<E>,
    {
        parse_transaction_unmarked::<B, E, Self>(data, ext_memory, self, None)
    }
}

/// Types registry that could be transformed into deterministically sorted set
/// of Merkle tree leaves.
pub trait HashableRegistry<E: ExternalMemory>: ResolveType<E> {
    /// Calculate Merkle tree leaves set.
    ///
    /// Each leave is calculated using a single type entry (for non-enums) or
    /// using an enum entry with a single enum variant (for enums).
    ///
    /// Sorting is done pre-hashing, by type id and by enum variant index within
    /// single id.
    fn merkle_leaves_source(&self) -> Result<LeavesRegistry, RegistryCutError>;
}

/// Implement [`HashableRegistry`].
macro_rules! impl_hashable_registry {
    ($($ty: ty), *) => {
        $(
            impl<E: ExternalMemory> HashableRegistry<E> for $ty {
                fn merkle_leaves_source(&self) -> Result<LeavesRegistry, RegistryCutError> {
                    let mut draft_registry = DraftRegistry::new();
                    for registry_entry in self.types.iter() {
                        match registry_entry.ty.type_def {
                                TypeDef::Variant(ref type_def_variant) => {
                                    if !type_def_variant.variants.is_empty() {
                                        for variant in type_def_variant.variants.iter() {
                                            add_as_enum(
                                                &mut draft_registry,
                                                &registry_entry.ty.path,
                                                variant.to_owned(),
                                                registry_entry.id,
                                            )?;
                                        }
                                    }
                                    else {
                                        add_ty_as_regular(
                                            &mut draft_registry,
                                            registry_entry.ty.to_owned(),
                                            registry_entry.id,
                                        )?;
                                    }
                                }
                                _ => {
                                    add_ty_as_regular(
                                        &mut draft_registry,
                                        registry_entry.ty.to_owned(),
                                        registry_entry.id,
                                    )?;
                                }
                        }
                    }
                    Ok(draft_registry.into_leaves())
                }
            }
        )*
    }
}

impl_hashable_registry!(PortableRegistry, ShortRegistry);

impl<E: ExternalMemory> ResolveType<E> for ShortRegistry {
    fn resolve_ty(
        &self,
        id: u32,
        _ext_memory: &mut E,
    ) -> Result<Type<PortableForm>, RegistryError<E>> {
        for short_registry_entry in self.types.iter() {
            if short_registry_entry.id == id {
                return Ok(short_registry_entry.ty.to_owned());
            }
        }
        Err(RegistryError::Internal(
            RegistryInternalError::TypeNotResolved { id },
        ))
    }
}

#[cfg(any(feature = "merkle-lean", test))]
impl<E, L> AsMetadata<E> for ShortMetadata<L, E>
where
    L: Leaf<LEN, E>,
    E: ExternalMemory,
{
    type TypeRegistry = ShortRegistry;

    type MetaStructureError = MetadataDescriptorError;

    fn types(&self) -> Self::TypeRegistry {
        self.short_registry.to_owned()
    }

    fn spec_name_version(&self) -> Result<SpecNameVersion, Self::MetaStructureError> {
        match &self.metadata_descriptor {
            MetadataDescriptor::V0 => Err(MetadataDescriptorError::DescriptorVersionIncompatible),
            MetadataDescriptor::V1 {
                call_ty: _,
                signed_extensions: _,
                spec_name_version,
                base58prefix: _,
                decimals: _,
                unit: _,
            } => Ok(spec_name_version.to_owned()),
        }
    }

    fn call_ty(&self) -> Result<UntrackedSymbol<TypeId>, Self::MetaStructureError> {
        match &self.metadata_descriptor {
            MetadataDescriptor::V0 => Err(MetadataDescriptorError::DescriptorVersionIncompatible),
            MetadataDescriptor::V1 {
                call_ty,
                signed_extensions: _,
                spec_name_version: _,
                base58prefix: _,
                decimals: _,
                unit: _,
            } => Ok(*call_ty),
        }
    }

    fn signed_extensions(&self) -> Result<Vec<SignedExtensionMetadata>, Self::MetaStructureError> {
        match &self.metadata_descriptor {
            MetadataDescriptor::V0 => Err(MetadataDescriptorError::DescriptorVersionIncompatible),
            MetadataDescriptor::V1 {
                call_ty: _,
                signed_extensions,
                spec_name_version: _,
                base58prefix: _,
                decimals: _,
                unit: _,
            } => Ok(signed_extensions.to_owned()),
        }
    }
}

#[cfg(any(feature = "merkle-lean", test))]
impl<E, L> HashableMetadata<E> for ShortMetadata<L, E>
where
    L: Leaf<LEN, E>,
    E: ExternalMemory,
{
    fn types_merkle_root(
        &self,
        ext_memory: &mut E,
    ) -> Result<[u8; LEN], MetaCutError<E, ShortMetadata<L, E>>> {
        let leaves_registry =
            <ShortRegistry as HashableRegistry<E>>::merkle_leaves_source(&self.short_registry)
                .map_err(MetaCutError::Registry)?;
        let leaves: Vec<[u8; LEN]> = leaves_registry
            .types
            .iter()
            .map(|entry| Blake3Hasher::make(&entry.encode()))
            .collect();
        let mut proof = MerkleProofMetadata::new_with_external_indices(
            leaves,
            self.indices.to_vec(),
            self.lemmas.to_vec(),
        )
        .map_err(MetaCutError::TreeConstructProof)?;
        proof
            .calculate_root(ext_memory)
            .map_err(MetaCutError::TreeCalculateRoot)
    }
}

#[cfg(any(feature = "merkle-lean", test))]
impl<E, L> ExtendedMetadata<E> for ShortMetadata<L, E>
where
    L: Leaf<LEN, E>,
    E: ExternalMemory,
{
    fn to_specs(&self) -> Result<ShortSpecs, Self::MetaStructureError> {
        match &self.metadata_descriptor {
            MetadataDescriptor::V0 => Err(MetadataDescriptorError::DescriptorVersionIncompatible),
            MetadataDescriptor::V1 {
                call_ty: _,
                signed_extensions: _,
                spec_name_version: _,
                base58prefix,
                decimals,
                unit,
            } => Ok(ShortSpecs {
                base58prefix: *base58prefix,
                decimals: *decimals,
                unit: unit.to_owned(),
            }),
        }
    }
}

#[cfg(any(feature = "merkle-standard", test))]
impl<E: ExternalMemory> HashableMetadata<E> for RuntimeMetadataV15 {
    fn types_merkle_root(
        &self,
        _ext_memory: &mut E,
    ) -> Result<[u8; LEN], MetaCutError<E, RuntimeMetadataV15>> {
        let leaves_registry =
            <PortableRegistry as HashableRegistry<E>>::merkle_leaves_source(&self.types)
                .map_err(MetaCutError::Registry)?;
        let leaves: Vec<[u8; LEN]> = leaves_registry
            .types
            .iter()
            .map(blake3_leaf::<PortableType>)
            .collect();
        Ok(CBMT::<[u8; LEN], Blake3Hasher>::build_merkle_root(&leaves))
    }
}
