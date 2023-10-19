use crate::std::{borrow::ToOwned, vec::Vec};

use frame_metadata::v14::{ExtrinsicMetadata, RuntimeMetadataV14};
use merkle_cbt::{merkle_tree::Merge, MerkleProof, CBMT};
use parity_scale_codec::Encode;
use scale_info::{form::PortableForm, PortableRegistry, Type, TypeDef};
use substrate_parser::{
    error::{MetaVersionError, ParserError, SignableError},
    traits::{AsMetadata, ExternalMemory, ResolveType, SpecNameVersion},
    ShortSpecs,
};

use crate::cut_metadata::{
    add_as_enum, add_ty_as_regular, DraftRegistry, MetadataDescriptor, ShortMetadata, ShortRegistry,
};
use crate::error::MetaCutError;

pub struct MergeHashes;

impl Merge for MergeHashes {
    type Item = [u8; 32];
    fn merge(left: &Self::Item, right: &Self::Item) -> Self::Item {
        blake3::hash(&[*left, *right].concat()).into()
    }
}

pub trait HashableMetadata<E: ExternalMemory>: AsMetadata<E>
where
    <Self as AsMetadata<E>>::TypeRegistry: HashableRegistry<E>,
{
    fn types_merkle_root(&self) -> Result<[u8; 32], MetaCutError<E>>;
    fn digest_with_short_specs(
        &self,
        short_specs: &ShortSpecs,
    ) -> Result<[u8; 32], MetaCutError<E>> {
        let types_merkle_root = self.types_merkle_root()?;
        let metadata_descriptor = MetadataDescriptor::V0 {
            extrinsic: self.extrinsic(),
            spec_name_version: self
                .spec_name_version()
                .map_err(|e| MetaCutError::Signable(SignableError::MetaVersion(e)))?,
            base58prefix: short_specs.base58prefix,
            decimals: short_specs.decimals,
            unit: short_specs.unit.to_owned(),
        };
        let metadata_descriptor_blake3 = blake3::hash(metadata_descriptor.encode().as_ref());
        Ok(
            blake3::hash(&[types_merkle_root, *metadata_descriptor_blake3.as_bytes()].concat())
                .into(),
        )
    }
}

pub trait ExtendedMetadata<E: ExternalMemory>: HashableMetadata<E>
where
    <Self as AsMetadata<E>>::TypeRegistry: HashableRegistry<E>,
{
    fn digest(&self) -> Result<[u8; 32], MetaCutError<E>>;
}

pub trait HashableRegistry<E: ExternalMemory>: ResolveType<E> {
    fn merkle_leaves(&self) -> Result<Vec<[u8; 32]>, MetaCutError<E>>;
}

macro_rules! impl_hashable_registry {
    ($($ty: ty), *) => {
        $(
            impl<E: ExternalMemory> HashableRegistry<E> for $ty {
                fn merkle_leaves(&self) -> Result<Vec<[u8;32]>, MetaCutError<E>> {
                    let mut draft_registry = DraftRegistry::new();
                    for registry_entry in self.types.iter() {
                        match registry_entry.ty.type_def {
                                TypeDef::Variant(ref type_def_variant) => {
                                    for variant in type_def_variant.variants.iter() {
                                        add_as_enum::<E>(
                                            &mut draft_registry,
                                            &registry_entry.ty.path,
                                            variant.to_owned(),
                                            registry_entry.id,
                                        )?;
                                    }
                                }
                                _ => {
                                    add_ty_as_regular::<E>(
                                        &mut draft_registry,
                                        registry_entry.ty.to_owned(),
                                        registry_entry.id,
                                    )?;
                                }
                        }
                    }
                    let hashable_registry = draft_registry.finalize_to_hashable();
                    let leaves: Vec<[u8; 32]> = hashable_registry.types.iter().map(|entry| *blake3::hash(entry.encode().as_ref()).as_bytes()).collect();
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

    fn types(&self) -> Self::TypeRegistry {
        self.short_registry.to_owned()
    }

    fn spec_name_version(&self) -> Result<SpecNameVersion, MetaVersionError> {
        match &self.metadata_descriptor {
            MetadataDescriptor::V0 {
                extrinsic: _,
                spec_name_version,
                base58prefix: _,
                decimals: _,
                unit: _,
            } => Ok(spec_name_version.to_owned()),
        }
    }

    fn extrinsic(&self) -> ExtrinsicMetadata<PortableForm> {
        match &self.metadata_descriptor {
            MetadataDescriptor::V0 {
                extrinsic,
                spec_name_version: _,
                base58prefix: _,
                decimals: _,
                unit: _,
            } => extrinsic.to_owned(),
        }
    }
}

impl<E: ExternalMemory> HashableMetadata<E> for ShortMetadata {
    fn types_merkle_root(&self) -> Result<[u8; 32], MetaCutError<E>> {
        let proof = MerkleProof::<[u8; 32], MergeHashes>::new(
            self.indices.to_owned(),
            self.lemmas.to_owned(),
        );
        let leaves = <ShortRegistry as HashableRegistry<E>>::merkle_leaves(&self.short_registry)?;
        proof.root(&leaves).ok_or(MetaCutError::TreeCalculateRoot)
    }
}

impl<E: ExternalMemory> ExtendedMetadata<E> for ShortMetadata {
    fn digest(&self) -> Result<[u8; 32], MetaCutError<E>> {
        match &self.metadata_descriptor {
            MetadataDescriptor::V0 {
                extrinsic: _,
                spec_name_version: _,
                base58prefix,
                decimals,
                unit,
            } => self.digest_with_short_specs(&ShortSpecs {
                base58prefix: *base58prefix,
                decimals: *decimals,
                unit: unit.to_owned(),
            }),
        }
    }
}

impl<E: ExternalMemory> HashableMetadata<E> for RuntimeMetadataV14 {
    fn types_merkle_root(&self) -> Result<[u8; 32], MetaCutError<E>> {
        let leaves = <PortableRegistry as HashableRegistry<E>>::merkle_leaves(&self.types)?;
        Ok(CBMT::<[u8; 32], MergeHashes>::build_merkle_root(&leaves))
    }
}
