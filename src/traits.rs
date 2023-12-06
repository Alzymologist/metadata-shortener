//! Traits for digest generation.
use crate::std::{borrow::ToOwned, vec::Vec};

use frame_metadata::v14::{ExtrinsicMetadata, RuntimeMetadataV14};
use merkle_cbt::{merkle_tree::Merge, MerkleProof, CBMT};
use parity_scale_codec::Encode;
use scale_info::{form::PortableForm, PortableRegistry, PortableType, Type, TypeDef};
use substrate_parser::{
    error::{ParserError, SignableError},
    parse_transaction, parse_transaction_unmarked,
    traits::{AddressableBuffer, AsMetadata, ExternalMemory, ResolveType, SpecNameVersion},
    ShortSpecs, TransactionParsed, TransactionUnmarkedParsed,
};

use crate::cut_metadata::{
    add_as_enum, add_ty_as_regular, DraftRegistry, MetadataDescriptor, ShortMetadata, ShortRegistry,
};
use crate::error::{MetaCutError, MetadataDescriptorError, RegistryCutError};

/// Hash merger, for Merkle tree construction.
pub(crate) struct MergeHashes;

impl Merge for MergeHashes {
    type Item = [u8; 32];
    fn merge(left: &Self::Item, right: &Self::Item) -> Self::Item {
        blake3::hash(&[*left, *right].concat()).into()
    }
}

/// Make blake3 hash for values implementing `Encode`.
///
/// Applied on individual [`PortableType`] in Merkle tree generation and on
/// [`MetadataDescriptor`] in digest calculation.
pub fn blake3_leaf<T: Encode>(value: &T) -> [u8; 32] {
    blake3::hash(value.encode().as_ref()).into()
}

/// [`AsMetadata`] with registry implementing [`HashableRegistry`].
pub trait HashableMetadata<E: ExternalMemory>: AsMetadata<E>
where
    <Self as AsMetadata<E>>::TypeRegistry: HashableRegistry<E>,
{
    /// Calculate Merkle tree root hash for original complete types data.
    ///
    /// This root hash must be identical both for shortened and full metadata.
    /// Note that for any shortened metadata in addition to known types data,
    /// serialized Merkle proof data would be required.
    fn types_merkle_root(&self) -> Result<[u8; 32], MetaCutError<E, Self>>;

    /// Calculate full digest with additionally provided chain [`ShortSpecs`].
    fn digest_with_short_specs(
        &self,
        short_specs: &ShortSpecs,
    ) -> Result<[u8; 32], MetaCutError<E, Self>> {
        let types_merkle_root = self.types_merkle_root()?;
        let metadata_descriptor = MetadataDescriptor::V1 {
            extrinsic: self
                .extrinsic()
                .map_err(|e| MetaCutError::Signable(SignableError::MetaStructure(e)))?,
            spec_name_version: self
                .spec_name_version()
                .map_err(|e| MetaCutError::Signable(SignableError::MetaStructure(e)))?,
            base58prefix: short_specs.base58prefix,
            decimals: short_specs.decimals,
            unit: short_specs.unit.to_owned(),
        };
        let metadata_descriptor_blake3 = blake3_leaf::<MetadataDescriptor>(&metadata_descriptor);
        Ok(MergeHashes::merge(
            &types_merkle_root,
            &metadata_descriptor_blake3,
        ))
    }
}

/// [`HashableMetadata`] with in-built [`ShortSpecs`].
pub trait ExtendedMetadata<E: ExternalMemory>: HashableMetadata<E> + Sized
where
    <Self as AsMetadata<E>>::TypeRegistry: HashableRegistry<E>,
{
    /// Extract [`ShortSpecs`].
    fn to_specs(&self) -> Result<ShortSpecs, <Self as AsMetadata<E>>::MetaStructureError>;

    /// Calculate full digest. Digest is added to transaction before signing.
    fn digest(&self) -> Result<[u8; 32], MetaCutError<E, Self>> {
        self.digest_with_short_specs(
            &self
                .to_specs()
                .map_err(|e| MetaCutError::Signable(SignableError::MetaStructure(e)))?,
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
    fn merkle_leaves(&self) -> Result<Vec<[u8; 32]>, RegistryCutError>;
}

/// Implement [`HashableRegistry`].
macro_rules! impl_hashable_registry {
    ($($ty: ty), *) => {
        $(
            impl<E: ExternalMemory> HashableRegistry<E> for $ty {
                fn merkle_leaves(&self) -> Result<Vec<[u8;32]>, RegistryCutError> {
                    let mut draft_registry = DraftRegistry::new();
                    for registry_entry in self.types.iter() {
                        match registry_entry.ty.type_def {
                                TypeDef::Variant(ref type_def_variant) => {
                                    for variant in type_def_variant.variants.iter() {
                                        add_as_enum(
                                            &mut draft_registry,
                                            &registry_entry.ty.path,
                                            variant.to_owned(),
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
                    let hashable_registry = draft_registry.into_leaves();
                    let leaves: Vec<[u8; 32]> = hashable_registry.types.iter().map(|entry| blake3_leaf::<PortableType>(entry)).collect();
                    Ok(leaves)
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
    ) -> Result<Type<PortableForm>, ParserError<E>> {
        for short_registry_entry in self.types.iter() {
            if short_registry_entry.id == id {
                return Ok(short_registry_entry.ty.to_owned());
            }
        }
        Err(ParserError::V14TypeNotResolved { id })
    }
}

impl<E: ExternalMemory> AsMetadata<E> for ShortMetadata {
    type TypeRegistry = ShortRegistry;

    type MetaStructureError = MetadataDescriptorError;

    fn types(&self) -> Self::TypeRegistry {
        self.short_registry.to_owned()
    }

    fn spec_name_version(&self) -> Result<SpecNameVersion, Self::MetaStructureError> {
        match &self.metadata_descriptor {
            MetadataDescriptor::V0 => Err(MetadataDescriptorError::DescriptorVersionIncompatible),
            MetadataDescriptor::V1 {
                extrinsic: _,
                spec_name_version,
                base58prefix: _,
                decimals: _,
                unit: _,
            } => Ok(spec_name_version.to_owned()),
        }
    }

    fn extrinsic(&self) -> Result<ExtrinsicMetadata<PortableForm>, Self::MetaStructureError> {
        match &self.metadata_descriptor {
            MetadataDescriptor::V0 => Err(MetadataDescriptorError::DescriptorVersionIncompatible),
            MetadataDescriptor::V1 {
                extrinsic,
                spec_name_version: _,
                base58prefix: _,
                decimals: _,
                unit: _,
            } => Ok(extrinsic.to_owned()),
        }
    }
}

impl<E: ExternalMemory> HashableMetadata<E> for ShortMetadata {
    fn types_merkle_root(&self) -> Result<[u8; 32], MetaCutError<E, ShortMetadata>> {
        let proof = MerkleProof::<[u8; 32], MergeHashes>::new(
            self.indices.to_owned(),
            self.lemmas.to_owned(),
        );
        let leaves = <ShortRegistry as HashableRegistry<E>>::merkle_leaves(&self.short_registry)
            .map_err(MetaCutError::Registry)?;
        proof.root(&leaves).ok_or(MetaCutError::TreeCalculateRoot)
    }
}

impl<E: ExternalMemory> ExtendedMetadata<E> for ShortMetadata {
    fn to_specs(&self) -> Result<ShortSpecs, Self::MetaStructureError> {
        match &self.metadata_descriptor {
            MetadataDescriptor::V0 => Err(MetadataDescriptorError::DescriptorVersionIncompatible),
            MetadataDescriptor::V1 {
                extrinsic: _,
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

impl<E: ExternalMemory> HashableMetadata<E> for RuntimeMetadataV14 {
    fn types_merkle_root(&self) -> Result<[u8; 32], MetaCutError<E, RuntimeMetadataV14>> {
        let leaves = <PortableRegistry as HashableRegistry<E>>::merkle_leaves(&self.types)
            .map_err(MetaCutError::Registry)?;
        Ok(CBMT::<[u8; 32], MergeHashes>::build_merkle_root(&leaves))
    }
}
