//! Tools for metadata cutting.
use crate::std::{borrow::ToOwned, string::String, vec::Vec};

#[cfg(not(feature = "std"))]
use core::any::TypeId;
#[cfg(all(not(feature = "std"), any(feature = "merkle-lean", test)))]
use core::marker::PhantomData;

#[cfg(feature = "std")]
use std::any::TypeId;
#[cfg(all(feature = "std", any(feature = "merkle-lean", test)))]
use std::marker::PhantomData;

use external_memory_tools::{AddressableBuffer, ExternalMemory};

#[cfg(any(feature = "proof-gen", test))]
use merkle_cbt_lean::Hasher;

#[cfg(any(feature = "merkle-lean", test))]
use merkle_cbt_lean::Leaf;

use parity_scale_codec::{Decode, Encode};

use scale_info::{
    form::PortableForm, interner::UntrackedSymbol, Field, Path, PortableType, Type, TypeDef,
    TypeDefBitSequence, TypeDefPrimitive, TypeDefVariant, Variant,
};

#[cfg(any(feature = "proof-gen", test))]
use substrate_parser::ShortSpecs;
use substrate_parser::{
    cards::Info,
    compacts::get_compact,
    decoding_sci::{decode_type_def_primitive, pick_variant, BitVecPositions, ResolvedTy, Ty},
    error::{ParserError, RegistryError, SignableError},
    propagated::{Checker, Propagated, SpecialtySet},
    special_indicators::{Hint, SpecialtyTypeHinted, ENUM_INDEX_ENCODED_LEN},
    traits::{AsMetadata, ResolveType, SignedExtensionMetadata, SpecNameVersion},
    MarkedData,
};

use crate::error::{MetaCutError, RegistryCutError};

#[cfg(any(feature = "proof-gen", test))]
use crate::traits::{Blake3Hasher, HashableMetadata, HashableRegistry, MerkleProofMetadata};

#[cfg(any(feature = "merkle-lean", test))]
use crate::traits::LEN;

/// Temporary registry.
///
/// Could be transformed both into [`ShortRegistry`] (for parsing) or into
/// [`LeavesRegistry`] (for Merkle tree generation).
///
/// When type is added to `DraftRegistry`, it has all its docs removed (i.e.
/// docs for type itself, for fields, and for enum variants).
#[derive(Debug)]
pub struct DraftRegistry {
    pub types: Vec<DraftRegistryEntry>,
}

/// Temporary registry entry: id and entry details.
#[derive(Debug)]
pub struct DraftRegistryEntry {
    pub id: u32,
    pub entry_details: EntryDetails,
}

/// Temporary registry entry details. Enums and non-enums are treated
/// separately.
#[derive(Debug)]
pub enum EntryDetails {
    Regular {
        ty: Type<PortableForm>,
    },
    ReduceableEnum {
        path: Path<PortableForm>,
        variants: Vec<Variant<PortableForm>>,
    },
}

/// Shortened type registry, for use in [`ShortMetadata`].
///
/// Note that although its inner structure is identical to that of
/// [`PortableRegistry`](scale_info::PortableRegistry), `ShortRegistry` has a
/// different implementation of type resolving with
/// [`ResolveType`] trait implementation.
///
/// In `PortableRegistry` type is resolved by `id` with in-built tools of
/// [`scale_info`] crate, effectively `id` being the index of corresponding
/// `PortableType` in `types` vector.
///
/// In `ShortRegistry` resolved `id` must match that of the `PortableType`,
/// regardless of the order.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct ShortRegistry {
    pub types: Vec<PortableType>,
}

/// Registry separated into elements that could be transformed into Merkle tree
/// leaves.
///
/// Each element is a [`PortableType`] with either a single type entry
/// (for non-enums) or with an enum entry with a single enum variant (for
/// enums). Note that if multiple variants of a single enum are present, they
/// are entered as separate [`PortableType`]s with the same id. `LeavesRegistry`
/// is not intended to be used for decoding, only for Merkle tree construction.
#[derive(Debug, PartialEq)]
pub struct LeavesRegistry {
    pub types: Vec<PortableType>,
}

impl DraftRegistry {
    /// New empty `DraftRegistry`.
    pub fn new() -> Self {
        Self { types: Vec::new() }
    }

    /// Transform into [`ShortRegistry`], suitable for decoding.
    ///
    /// In `ShortRegistry`:
    /// - Each type has an individual entry
    /// - Entries are sorted by id
    /// - Variants within single enum are sorted by variant index
    pub fn finalize_to_short(&self) -> ShortRegistry {
        let mut short_registry = ShortRegistry { types: Vec::new() };
        for draft_entry in self.types.iter() {
            let id = draft_entry.id;
            let ty = match &draft_entry.entry_details {
                EntryDetails::Regular { ty } => ty.to_owned(),
                EntryDetails::ReduceableEnum { path, variants } => Type {
                    path: path.to_owned(),
                    type_params: Vec::new(),
                    type_def: TypeDef::Variant(TypeDefVariant {
                        variants: variants.to_owned(),
                    }),
                    docs: Vec::new(),
                },
            };
            short_registry.types.push(PortableType { id, ty })
        }
        for entry in short_registry.types.iter_mut() {
            if let TypeDef::Variant(ref mut variants_entry) = entry.ty.type_def {
                variants_entry
                    .variants
                    .sort_by(|a, b| a.index.cmp(&b.index))
            }
        }
        short_registry.types.sort_by(|a, b| a.id.cmp(&b.id));
        short_registry
    }

    /// Transform into [`LeavesRegistry`], suitable for Merkle tree
    /// construction.
    ///
    /// In `LeavesRegistry`:
    /// - Each non-enum type has an individual entry
    /// - Each enum variant is transformed into enum type with a single variant,
    /// id is the same
    /// - Entries are sorted by id
    /// - Entries with identical id (enum variants) are sorted by variant index
    pub fn into_leaves(&self) -> LeavesRegistry {
        let mut leaves = LeavesRegistry { types: Vec::new() };
        for draft_entry in self.types.iter() {
            let id = draft_entry.id;
            match &draft_entry.entry_details {
                EntryDetails::Regular { ty } => leaves.types.push(PortableType {
                    id,
                    ty: ty.to_owned(),
                }),
                EntryDetails::ReduceableEnum { path, variants } => {
                    for variant in variants.iter() {
                        let ty = Type {
                            path: path.to_owned(),
                            type_params: Vec::new(),
                            type_def: TypeDef::Variant(TypeDefVariant {
                                variants: vec![variant.to_owned()],
                            }),
                            docs: Vec::new(),
                        };
                        leaves.types.push(PortableType { id, ty })
                    }
                }
            };
        }
        leaves.types.sort_by(|a, b| {
            if a.id == b.id {
                if let TypeDef::Variant(variants_a) = &a.ty.type_def {
                    if let TypeDef::Variant(variants_b) = &b.ty.type_def {
                        variants_a.variants[0]
                            .index
                            .cmp(&variants_b.variants[0].index)
                    } else {
                        unreachable!("only variants have more than one entry")
                    }
                } else {
                    unreachable!("only variants have more than one entry")
                }
            } else {
                a.id.cmp(&b.id)
            }
        });
        leaves
    }
}

impl Default for DraftRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Add type into `DraftRegistry` as regular type, i.e. as non-enum.
pub(crate) fn add_ty_as_regular(
    draft_registry: &mut DraftRegistry,
    mut ty: Type<PortableForm>,
    id: u32,
) -> Result<(), RegistryCutError> {
    for draft_registry_entry in draft_registry.types.iter() {
        if draft_registry_entry.id == id {
            match draft_registry_entry.entry_details {
                EntryDetails::Regular { ty: ref known_ty } => {
                    if known_ty == &ty {
                        return Ok(());
                    } else {
                        return Err(RegistryCutError::IndexTwice { id });
                    }
                }
                EntryDetails::ReduceableEnum {
                    path: _,
                    variants: _,
                } => return Err(RegistryCutError::IndexTwice { id }),
            }
        }
    }

    // Remove docs from each field in structs.
    // Enums with non-empty set of variants do not get added as regular type,
    // other types do not have internal field-related docs.
    if let TypeDef::Composite(ref mut type_def_composite) = ty.type_def {
        for field in type_def_composite.fields.iter_mut() {
            field.docs.clear();
        }
    }

    // Remove docs from type itself.
    ty.docs.clear();
    let entry_details = EntryDetails::Regular { ty };
    let draft_registry_entry = DraftRegistryEntry { id, entry_details };
    draft_registry.types.push(draft_registry_entry);
    Ok(())
}

/// Add type into `DraftRegistry` as an enum.
pub(crate) fn add_as_enum(
    draft_registry: &mut DraftRegistry,
    path: &Path<PortableForm>,
    mut variant: Variant<PortableForm>,
    id: u32,
) -> Result<(), RegistryCutError> {
    for draft_registry_entry in draft_registry.types.iter_mut() {
        if draft_registry_entry.id == id {
            match draft_registry_entry.entry_details {
                EntryDetails::Regular { ty: _ } => {
                    return Err(RegistryCutError::IndexTwice { id });
                }
                EntryDetails::ReduceableEnum {
                    path: ref known_path,
                    ref mut variants,
                } => {
                    if known_path == path {
                        // Remove variant docs.
                        variant.docs.clear();

                        // Remove docs for each field.
                        for field in variant.fields.iter_mut() {
                            field.docs.clear();
                        }

                        if !variants.contains(&variant) {
                            variants.push(variant)
                        }
                        return Ok(());
                    } else {
                        return Err(RegistryCutError::IndexTwice { id });
                    }
                }
            }
        }
    }

    // Remove variant docs.
    variant.docs.clear();

    // Remove docs for each field.
    for field in variant.fields.iter_mut() {
        field.docs.clear();
    }

    let variants = vec![variant];
    let entry_details = EntryDetails::ReduceableEnum {
        path: path.to_owned(),
        variants,
    };
    let draft_registry_entry = DraftRegistryEntry { id, entry_details };
    draft_registry.types.push(draft_registry_entry);
    Ok(())
}

/// Update [`DraftRegistry`] with types needed to parse a call part of a marked
/// transaction.
pub fn pass_call<B, E, M>(
    marked_data: &MarkedData<B, E, M>,
    ext_memory: &mut E,
    full_metadata: &M,
    draft_registry: &mut DraftRegistry,
) -> Result<(), MetaCutError<E, M>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    let data = marked_data.data_no_extensions();
    let mut position = marked_data.call_start();

    pass_call_unmarked(
        &data,
        &mut position,
        ext_memory,
        full_metadata,
        draft_registry,
    )?;
    if position != marked_data.extensions_start() {
        Err(MetaCutError::Signable(SignableError::SomeDataNotUsedCall {
            from: position,
            to: marked_data.extensions_start(),
        }))
    } else {
        Ok(())
    }
}

/// Update [`DraftRegistry`] with types needed to parse a call part of an
/// unmarked transaction.
pub fn pass_call_unmarked<B, E, M>(
    data: &B,
    position: &mut usize,
    ext_memory: &mut E,
    full_metadata: &M,
    draft_registry: &mut DraftRegistry,
) -> Result<(), MetaCutError<E, M>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    let call_ty = full_metadata
        .call_ty()
        .map_err(|e| MetaCutError::Signable(SignableError::MetaStructure(e)))?;

    pass_type::<B, E, M>(
        &Ty::Symbol(&call_ty),
        data,
        ext_memory,
        position,
        &full_metadata.types(),
        Propagated::new(),
        draft_registry,
    )
}

/// Update [`DraftRegistry`] with types needed to parse extensions of a marked
/// transaction.
pub fn pass_extensions<B, E, M>(
    marked_data: &MarkedData<B, E, M>,
    ext_memory: &mut E,
    full_metadata: &M,
    draft_registry: &mut DraftRegistry,
) -> Result<(), MetaCutError<E, M>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    let mut position = marked_data.extensions_start();
    let data = marked_data.data();

    pass_extensions_unmarked(
        data,
        &mut position,
        ext_memory,
        full_metadata,
        draft_registry,
    )
}

/// Update [`DraftRegistry`] with types needed to parse extensions of an
/// unmarked transaction.
pub fn pass_extensions_unmarked<B, E, M>(
    data: &B,
    position: &mut usize,
    ext_memory: &mut E,
    full_metadata: &M,
    draft_registry: &mut DraftRegistry,
) -> Result<(), MetaCutError<E, M>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    let full_metadata_types = full_metadata.types();
    let signed_extensions = full_metadata
        .signed_extensions()
        .map_err(|e| MetaCutError::Signable(SignableError::MetaStructure(e)))?;
    for signed_extensions_metadata in signed_extensions.iter() {
        pass_type::<B, E, M>(
            &Ty::Symbol(&signed_extensions_metadata.ty),
            data,
            ext_memory,
            position,
            &full_metadata_types,
            Propagated::from_ext_meta(signed_extensions_metadata),
            draft_registry,
        )?;
    }
    for signed_extensions_metadata in signed_extensions.iter() {
        pass_type::<B, E, M>(
            &Ty::Symbol(&signed_extensions_metadata.additional_signed),
            data,
            ext_memory,
            position,
            &full_metadata_types,
            Propagated::from_ext_meta(signed_extensions_metadata),
            draft_registry,
        )?;
    }
    // `position > data.total_len()` is ruled out elsewhere
    if *position != data.total_len() {
        Err(MetaCutError::Signable(
            SignableError::SomeDataNotUsedExtensions { from: *position },
        ))
    } else {
        Ok(())
    }
}

/// Shortened metadata, custom-made for specific transaction.
///
/// Contains all the data necessary to parse a signable transaction and to
/// generate a metadata digest.
#[cfg(any(feature = "merkle-lean", test))]
#[repr(C)]
#[derive(Debug, Decode, Encode, Eq, PartialEq)]
pub struct ShortMetadata<L, E>
where
    L: Leaf<LEN, E>,
    E: ExternalMemory,
{
    pub short_registry: ShortRegistry,
    pub indices: Vec<u32>,
    pub lemmas: Vec<L>,
    pub metadata_descriptor: MetadataDescriptor,
    ext_memory_type: PhantomData<E>,
}

/// Versioned metadata descriptor with non-registry entities necessary for
/// transaction parsing.
#[repr(C)]
#[non_exhaustive]
#[derive(Debug, Decode, Encode, Eq, PartialEq)]
pub enum MetadataDescriptor {
    V0,
    V1 {
        call_ty: UntrackedSymbol<TypeId>,
        signed_extensions: Vec<SignedExtensionMetadata>,
        spec_name_version: SpecNameVersion,
        base58prefix: u16,
        decimals: u8,
        unit: String,
    },
}

/// Construct [`ShortMetadata`] for a regular transaction.
///
/// Transaction could be separated into call and extension as the call is
/// prefixed with call length compact.
#[cfg(any(feature = "proof-gen", test))]
pub fn cut_metadata<B, E, L, M>(
    data: &B,
    ext_memory: &mut E,
    full_metadata: &M,
    short_specs: &ShortSpecs,
) -> Result<ShortMetadata<L, E>, MetaCutError<E, M>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    L: Leaf<LEN, E>,
    M: HashableMetadata<E>,
    <M as AsMetadata<E>>::TypeRegistry: HashableRegistry<E>,
{
    let mut draft_registry = DraftRegistry::new();

    let marked_data =
        MarkedData::<B, E, M>::mark(data, ext_memory).map_err(MetaCutError::Signable)?;
    pass_call::<B, E, M>(&marked_data, ext_memory, full_metadata, &mut draft_registry)?;
    pass_extensions::<B, E, M>(&marked_data, ext_memory, full_metadata, &mut draft_registry)?;

    let short_registry = draft_registry.finalize_to_short();

    let leaves_registry_short =
        <ShortRegistry as HashableRegistry<E>>::merkle_leaves_source(&short_registry)
            .map_err(MetaCutError::Registry)?;
    let leaves_registry_long = full_metadata
        .types()
        .merkle_leaves_source()
        .map_err(MetaCutError::Registry)?;

    let leaves_short: Vec<[u8; LEN]> = leaves_registry_short
        .types
        .iter()
        .map(|entry| Blake3Hasher::make(&entry.encode()))
        .collect();
    let leaves_long: Vec<[u8; LEN]> = leaves_registry_long
        .types
        .iter()
        .map(|entry| Blake3Hasher::make(&entry.encode()))
        .collect();

    let proof = MerkleProofMetadata::for_leaves_subset(leaves_long, &leaves_short, ext_memory)
        .map_err(MetaCutError::TreeCalculateProof)?;

    let metadata_descriptor = MetadataDescriptor::V1 {
        call_ty: full_metadata
            .call_ty()
            .map_err(|e| MetaCutError::Signable(SignableError::MetaStructure(e)))?,
        signed_extensions: full_metadata
            .signed_extensions()
            .map_err(|e| MetaCutError::Signable(SignableError::MetaStructure(e)))?,
        spec_name_version: full_metadata
            .spec_name_version()
            .map_err(|e| MetaCutError::Signable(SignableError::MetaStructure(e)))?,
        base58prefix: short_specs.base58prefix,
        decimals: short_specs.decimals,
        unit: short_specs.unit.to_owned(),
    };

    Ok(ShortMetadata {
        short_registry,
        indices: proof.indices(),
        lemmas: proof.lemmas,
        metadata_descriptor,
        ext_memory_type: PhantomData,
    })
}

/// Construct [`ShortMetadata`] for an unmarked transaction.
///
/// Unmarked transaction is not prefixed with call length compact, and thus call
/// and extensions could not be separated.
#[cfg(any(feature = "proof-gen", test))]
pub fn cut_metadata_transaction_unmarked<B, E, L, M>(
    data: &B,
    ext_memory: &mut E,
    full_metadata: &M,
    short_specs: &ShortSpecs,
) -> Result<ShortMetadata<L, E>, MetaCutError<E, M>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    L: Leaf<LEN, E>,
    M: HashableMetadata<E>,
    <M as AsMetadata<E>>::TypeRegistry: HashableRegistry<E>,
{
    let mut draft_registry = DraftRegistry::new();

    let mut position = 0;
    pass_call_unmarked::<B, E, M>(
        data,
        &mut position,
        ext_memory,
        full_metadata,
        &mut draft_registry,
    )?;
    pass_extensions_unmarked::<B, E, M>(
        data,
        &mut position,
        ext_memory,
        full_metadata,
        &mut draft_registry,
    )?;

    let short_registry = draft_registry.finalize_to_short();

    let leaves_registry_short =
        <ShortRegistry as HashableRegistry<E>>::merkle_leaves_source(&short_registry)
            .map_err(MetaCutError::Registry)?;
    let leaves_registry_long = full_metadata
        .types()
        .merkle_leaves_source()
        .map_err(MetaCutError::Registry)?;

    let leaves_short: Vec<[u8; LEN]> = leaves_registry_short
        .types
        .iter()
        .map(|entry| Blake3Hasher::make(&entry.encode()))
        .collect();
    let leaves_long: Vec<[u8; LEN]> = leaves_registry_long
        .types
        .iter()
        .map(|entry| Blake3Hasher::make(&entry.encode()))
        .collect();

    let proof = MerkleProofMetadata::for_leaves_subset(leaves_long, &leaves_short, ext_memory)
        .map_err(MetaCutError::TreeCalculateProof)?;

    let metadata_descriptor = MetadataDescriptor::V1 {
        call_ty: full_metadata
            .call_ty()
            .map_err(|e| MetaCutError::Signable(SignableError::MetaStructure(e)))?,
        signed_extensions: full_metadata
            .signed_extensions()
            .map_err(|e| MetaCutError::Signable(SignableError::MetaStructure(e)))?,
        spec_name_version: full_metadata
            .spec_name_version()
            .map_err(|e| MetaCutError::Signable(SignableError::MetaStructure(e)))?,
        base58prefix: short_specs.base58prefix,
        decimals: short_specs.decimals,
        unit: short_specs.unit.to_owned(),
    };

    Ok(ShortMetadata {
        short_registry,
        indices: proof.indices(),
        lemmas: proof.lemmas,
        metadata_descriptor,
        ext_memory_type: PhantomData,
    })
}

/// Update [`DraftRegistry`] for parsing data corresponding to a type.
pub fn pass_type<B, E, M>(
    ty_input: &Ty,
    data: &B,
    ext_memory: &mut E,
    position: &mut usize,
    registry: &M::TypeRegistry,
    mut propagated: Propagated,
    draft_registry: &mut DraftRegistry,
) -> Result<(), MetaCutError<E, M>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    let (ty, id) = match ty_input {
        Ty::Resolved(resolved_ty) => (resolved_ty.ty.to_owned(), resolved_ty.id),
        Ty::Symbol(ty_symbol) => (
            registry.resolve_ty(ty_symbol.id, ext_memory).map_err(|e| {
                MetaCutError::Signable(SignableError::Parsing(ParserError::Registry(e)))
            })?,
            ty_symbol.id,
        ),
    };

    let info_ty = Info::from_ty(&ty);
    propagated.add_info(&info_ty);

    match &ty.type_def {
        TypeDef::Composite(x) => {
            pass_fields::<B, E, M>(
                &x.fields,
                data,
                ext_memory,
                position,
                registry,
                propagated.checker,
                draft_registry,
            )?;
            add_ty_as_regular(draft_registry, ty.to_owned(), id).map_err(MetaCutError::Registry)
        }
        TypeDef::Variant(x) => {
            propagated.reject_compact().map_err(|e| {
                MetaCutError::Signable(SignableError::Parsing(ParserError::Registry(e)))
            })?;
            if !x.variants.is_empty() {
                pass_variant::<B, E, M>(
                    &x.variants,
                    data,
                    ext_memory,
                    position,
                    registry,
                    draft_registry,
                    &info_ty.path,
                    id,
                )
            } else {
                add_ty_as_regular(draft_registry, ty.to_owned(), id).map_err(MetaCutError::Registry)
            }
        }
        TypeDef::Sequence(x) => {
            let number_of_elements = get_compact::<u32, B, E>(data, ext_memory, position)
                .map_err(|e| MetaCutError::Signable(SignableError::Parsing(e)))?;
            propagated.checker.drop_cycle_check();
            pass_elements_set::<B, E, M>(
                &x.type_param,
                number_of_elements,
                data,
                ext_memory,
                position,
                registry,
                propagated,
                draft_registry,
            )?;
            add_ty_as_regular(draft_registry, ty, id).map_err(MetaCutError::Registry)
        }
        TypeDef::Array(x) => {
            pass_elements_set::<B, E, M>(
                &x.type_param,
                x.len,
                data,
                ext_memory,
                position,
                registry,
                propagated,
                draft_registry,
            )?;
            add_ty_as_regular(draft_registry, ty, id).map_err(MetaCutError::Registry)
        }
        TypeDef::Tuple(x) => {
            if x.fields.len() > 1 {
                propagated.reject_compact().map_err(|e| {
                    MetaCutError::Signable(SignableError::Parsing(ParserError::Registry(e)))
                })?;
                propagated.forget_hint();
            }
            for inner_ty_symbol in x.fields.iter() {
                let id = inner_ty_symbol.id;
                let ty = registry.resolve_ty(id, ext_memory).map_err(|e| {
                    MetaCutError::Signable(SignableError::Parsing(ParserError::Registry(e)))
                })?;
                pass_type::<B, E, M>(
                    &Ty::Resolved(ResolvedTy {
                        ty: ty.to_owned(),
                        id,
                    }),
                    data,
                    ext_memory,
                    position,
                    registry,
                    Propagated::for_ty(&propagated.checker, &ty, id).map_err(|e| {
                        MetaCutError::Signable(SignableError::Parsing(ParserError::Registry(e)))
                    })?,
                    draft_registry,
                )?;
            }
            add_ty_as_regular(draft_registry, ty, id).map_err(MetaCutError::Registry)
        }
        TypeDef::Primitive(x) => {
            decode_type_def_primitive::<B, E>(
                x,
                data,
                ext_memory,
                position,
                propagated.checker.specialty_set,
            )
            .map_err(|e| MetaCutError::Signable(SignableError::Parsing(e)))?;
            add_ty_as_regular(draft_registry, ty, id).map_err(MetaCutError::Registry)
        }
        TypeDef::Compact(x) => {
            propagated.reject_compact().map_err(|e| {
                MetaCutError::Signable(SignableError::Parsing(ParserError::Registry(e)))
            })?;
            propagated.checker.specialty_set.compact_at = Some(id);
            propagated.checker.check_id(x.type_param.id).map_err(|e| {
                MetaCutError::Signable(SignableError::Parsing(ParserError::Registry(e)))
            })?;
            pass_type::<B, E, M>(
                &Ty::Symbol(&x.type_param),
                data,
                ext_memory,
                position,
                registry,
                propagated,
                draft_registry,
            )?;
            add_ty_as_regular(draft_registry, ty, id).map_err(MetaCutError::Registry)
        }
        TypeDef::BitSequence(x) => {
            propagated.reject_compact().map_err(|e| {
                MetaCutError::Signable(SignableError::Parsing(ParserError::Registry(e)))
            })?;
            pass_type_def_bit_sequence::<B, E, M>(
                x,
                id,
                data,
                ext_memory,
                position,
                registry,
                draft_registry,
            )?;
            add_ty_as_regular(draft_registry, ty, id).map_err(MetaCutError::Registry)
        }
    }
}

/// Update [`DraftRegistry`] for parsing a [`Field`] set.
fn pass_fields<B, E, M>(
    fields: &[Field<PortableForm>],
    data: &B,
    ext_memory: &mut E,
    position: &mut usize,
    registry: &M::TypeRegistry,
    mut checker: Checker,
    draft_registry: &mut DraftRegistry,
) -> Result<(), MetaCutError<E, M>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    if fields.len() > 1 {
        // Only single-field structs can be processed as a compact.
        // Note: compact flag was already checked in enum processing at this
        // point.
        checker.reject_compact().map_err(|e| {
            MetaCutError::Signable(SignableError::Parsing(ParserError::Registry(e)))
        })?;

        // `Hint` remains relevant only if single-field struct is processed.
        // Note: checker gets renewed when fields of enum are processed.
        checker.forget_hint();
    }
    for field in fields.iter() {
        pass_type::<B, E, M>(
            &Ty::Symbol(&field.ty),
            data,
            ext_memory,
            position,
            registry,
            Propagated::for_field(&checker, field).map_err(|e| {
                MetaCutError::Signable(SignableError::Parsing(ParserError::Registry(e)))
            })?,
            draft_registry,
        )?;
    }
    Ok(())
}

/// Update [`DraftRegistry`] for parsing a set of identical elements (in a
/// vector or array).
#[allow(clippy::too_many_arguments)]
fn pass_elements_set<B, E, M>(
    element: &UntrackedSymbol<TypeId>,
    number_of_elements: u32,
    data: &B,
    ext_memory: &mut E,
    position: &mut usize,
    registry: &M::TypeRegistry,
    propagated: Propagated,
    draft_registry: &mut DraftRegistry,
) -> Result<(), MetaCutError<E, M>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    propagated
        .reject_compact()
        .map_err(|e| MetaCutError::Signable(SignableError::Parsing(ParserError::Registry(e))))?;

    let husked = husk_type_no_info::<E, M>(
        element,
        registry,
        ext_memory,
        propagated.checker,
        draft_registry,
    )?;

    for _i in 0..number_of_elements {
        pass_type::<B, E, M>(
            &Ty::Resolved(ResolvedTy {
                ty: husked.ty.to_owned(),
                id: husked.id,
            }),
            data,
            ext_memory,
            position,
            registry,
            Propagated::with_checker(husked.checker.clone()),
            draft_registry,
        )?;
    }
    Ok(())
}

/// Update [`DraftRegistry`] for parsing a [`Variant`].
#[allow(clippy::too_many_arguments)]
fn pass_variant<B, E, M>(
    variants: &[Variant<PortableForm>],
    data: &B,
    ext_memory: &mut E,
    position: &mut usize,
    registry: &M::TypeRegistry,
    draft_registry: &mut DraftRegistry,
    path: &Path<PortableForm>,
    enum_ty_id: u32,
) -> Result<(), MetaCutError<E, M>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    let found_variant = pick_variant::<B, E>(variants, data, ext_memory, *position)
        .map_err(|e| MetaCutError::Signable(SignableError::Parsing(e)))?;

    *position += ENUM_INDEX_ENCODED_LEN;

    pass_fields::<B, E, M>(
        &found_variant.fields,
        data,
        ext_memory,
        position,
        registry,
        Checker::new(),
        draft_registry,
    )?;

    add_as_enum(draft_registry, path, found_variant.to_owned(), enum_ty_id)
        .map_err(MetaCutError::Registry)
}

/// Update [`DraftRegistry`] for parsing a [`TypeDefBitSequence`].
fn pass_type_def_bit_sequence<B, E, M>(
    bit_ty: &TypeDefBitSequence<PortableForm>,
    id: u32,
    data: &B,
    ext_memory: &mut E,
    position: &mut usize,
    registry: &M::TypeRegistry,
    draft_registry: &mut DraftRegistry,
) -> Result<(), MetaCutError<E, M>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    // BitOrder
    let bitorder_type = registry
        .resolve_ty(bit_ty.bit_order_type.id, ext_memory)
        .map_err(|e| MetaCutError::Signable(SignableError::Parsing(ParserError::Registry(e))))?;
    add_ty_as_regular(draft_registry, bitorder_type, bit_ty.bit_order_type.id)
        .map_err(MetaCutError::Registry)?;

    // BitStore
    let bitstore_type = registry
        .resolve_ty(bit_ty.bit_store_type.id, ext_memory)
        .map_err(|e| MetaCutError::Signable(SignableError::Parsing(ParserError::Registry(e))))?;

    match bitstore_type.type_def {
        TypeDef::Primitive(TypeDefPrimitive::U8) => {
            pass_bitvec_decode::<u8, B, E>(data, ext_memory, position)
        }
        TypeDef::Primitive(TypeDefPrimitive::U16) => {
            pass_bitvec_decode::<u16, B, E>(data, ext_memory, position)
        }
        TypeDef::Primitive(TypeDefPrimitive::U32) => {
            pass_bitvec_decode::<u32, B, E>(data, ext_memory, position)
        }
        TypeDef::Primitive(TypeDefPrimitive::U64) => {
            pass_bitvec_decode::<u64, B, E>(data, ext_memory, position)
        }
        _ => Err(ParserError::Registry(RegistryError::NotBitStoreType { id })),
    }
    .map_err(|e| MetaCutError::Signable(SignableError::Parsing(e)))?;

    add_ty_as_regular(draft_registry, bitstore_type, bit_ty.bit_store_type.id)
        .map_err(MetaCutError::Registry)
}

/// Move current position after encountering a [`TypeDefBitSequence`].
fn pass_bitvec_decode<'a, T, B, E>(
    data: &B,
    ext_memory: &'a mut E,
    position: &'a mut usize,
) -> Result<(), ParserError<E>>
where
    B: AddressableBuffer<E>,
    E: ExternalMemory,
{
    let bitvec_positions = BitVecPositions::new::<T, B, E>(data, ext_memory, *position)?;
    *position = bitvec_positions.bitvec_end;
    Ok(())
}

/// Type, resolved as much as possible.
///
/// `HuskedTypeNoInfo` is useful when decoding sets of identical elements (in
/// vectors or arrays) and while searching for types with specified descriptors
/// (such as extrinsic type with pre-known structure).
///
/// No identical [`Type`] `id`s are expected to be encountered, otherwise the
/// resolving would go indefinitely.
///
/// [`Type`] `id`s are collected and checked in [`Checker`].
struct HuskedTypeNoInfo {
    checker: Checker,
    ty: Type<PortableForm>,
    id: u32,
}

/// Resolve compact and single-field structs into corresponding inner types.
///
/// Resolving stops when more complex structure or a specialty is encountered.
fn husk_type_no_info<E, M>(
    entry_symbol: &UntrackedSymbol<TypeId>,
    registry: &M::TypeRegistry,
    ext_memory: &mut E,
    mut checker: Checker,
    draft_registry: &mut DraftRegistry,
) -> Result<HuskedTypeNoInfo, MetaCutError<E, M>>
where
    E: ExternalMemory,
    M: AsMetadata<E>,
{
    let entry_symbol_id = entry_symbol.id;
    checker
        .check_id(entry_symbol_id)
        .map_err(|e| MetaCutError::Signable(SignableError::Parsing(ParserError::Registry(e))))?;
    checker.specialty_set = SpecialtySet {
        compact_at: None,
        hint: Hint::None,
    };

    let mut ty = registry
        .resolve_ty(entry_symbol_id, ext_memory)
        .map_err(|e| MetaCutError::Signable(SignableError::Parsing(ParserError::Registry(e))))?;
    let mut id = entry_symbol_id;

    while let SpecialtyTypeHinted::None = SpecialtyTypeHinted::from_type(&ty) {
        let type_def = ty.type_def.to_owned();
        match type_def {
            TypeDef::Composite(x) => {
                if x.fields.len() == 1 {
                    add_ty_as_regular(draft_registry, ty.to_owned(), id)
                        .map_err(MetaCutError::Registry)?;
                    id = x.fields[0].ty.id;
                    checker.check_id(id).map_err(|e| {
                        MetaCutError::Signable(SignableError::Parsing(ParserError::Registry(e)))
                    })?;
                    ty = registry.resolve_ty(id, ext_memory).map_err(|e| {
                        MetaCutError::Signable(SignableError::Parsing(ParserError::Registry(e)))
                    })?;
                    if let Hint::None = checker.specialty_set.hint {
                        checker.specialty_set.hint = Hint::from_field(&x.fields[0])
                    }
                } else {
                    break;
                }
            }
            TypeDef::Compact(x) => {
                add_ty_as_regular(draft_registry, ty.to_owned(), id)
                    .map_err(MetaCutError::Registry)?;
                checker.reject_compact().map_err(|e| {
                    MetaCutError::Signable(SignableError::Parsing(ParserError::Registry(e)))
                })?;
                checker.specialty_set.compact_at = Some(id);
                id = x.type_param.id;
                checker.check_id(id).map_err(|e| {
                    MetaCutError::Signable(SignableError::Parsing(ParserError::Registry(e)))
                })?;
                ty = registry.resolve_ty(id, ext_memory).map_err(|e| {
                    MetaCutError::Signable(SignableError::Parsing(ParserError::Registry(e)))
                })?;
            }
            _ => break,
        }
    }

    Ok(HuskedTypeNoInfo { checker, ty, id })
}

#[cfg(test)]
mod tests {
    use super::*;
    use scale_info::{Path, PortableRegistry};

    use crate::std::string::ToString;

    #[test]
    fn sort_draft_registry() {
        let mut draft_registry = DraftRegistry::new();
        add_as_enum(
            &mut draft_registry,
            &Path::<PortableForm> {
                segments: vec!["test".to_string(), "Path".to_string()],
            },
            Variant::<PortableForm> {
                name: "OtherVariant".to_string(),
                fields: Vec::new(),
                index: 3u8,
                docs: Vec::new(),
            },
            144,
        )
        .unwrap();
        add_as_enum(
            &mut draft_registry,
            &Path::<PortableForm> {
                segments: vec!["test".to_string(), "Path".to_string()],
            },
            Variant::<PortableForm> {
                name: "SomeVariant".to_string(),
                fields: Vec::new(),
                index: 1u8,
                docs: Vec::new(),
            },
            144,
        )
        .unwrap();
        add_as_enum(
            &mut draft_registry,
            &Path::<PortableForm> {
                segments: vec!["test".to_string(), "Path".to_string()],
            },
            Variant::<PortableForm> {
                name: "ThirdVariant".to_string(),
                fields: Vec::new(),
                index: 7u8,
                docs: Vec::new(),
            },
            144,
        )
        .unwrap();

        let to_short = draft_registry.finalize_to_short();
        assert_eq!(
            to_short,
            ShortRegistry {
                types: vec![PortableType {
                    id: 144,
                    ty: Type {
                        path: Path {
                            segments: vec!["test".to_string(), "Path".to_string()]
                        },
                        type_params: Vec::new(),
                        type_def: TypeDef::Variant(TypeDefVariant {
                            variants: vec![
                                Variant {
                                    name: "SomeVariant".to_string(),
                                    fields: Vec::new(),
                                    index: 1,
                                    docs: Vec::new()
                                },
                                Variant {
                                    name: "OtherVariant".to_string(),
                                    fields: Vec::new(),
                                    index: 3,
                                    docs: Vec::new()
                                },
                                Variant {
                                    name: "ThirdVariant".to_string(),
                                    fields: Vec::new(),
                                    index: 7,
                                    docs: Vec::new()
                                }
                            ]
                        }),
                        docs: Vec::new()
                    }
                }]
            }
        );

        let leaves = draft_registry.into_leaves();
        assert_eq!(
            leaves,
            LeavesRegistry {
                types: vec![
                    PortableType {
                        id: 144,
                        ty: Type {
                            path: Path {
                                segments: vec!["test".to_string(), "Path".to_string()]
                            },
                            type_params: Vec::new(),
                            type_def: TypeDef::Variant(TypeDefVariant {
                                variants: vec![Variant {
                                    name: "SomeVariant".to_string(),
                                    fields: Vec::new(),
                                    index: 1,
                                    docs: Vec::new()
                                }]
                            }),
                            docs: Vec::new()
                        }
                    },
                    PortableType {
                        id: 144,
                        ty: Type {
                            path: Path {
                                segments: vec!["test".to_string(), "Path".to_string()]
                            },
                            type_params: Vec::new(),
                            type_def: TypeDef::Variant(TypeDefVariant {
                                variants: vec![Variant {
                                    name: "OtherVariant".to_string(),
                                    fields: Vec::new(),
                                    index: 3,
                                    docs: Vec::new()
                                }]
                            }),
                            docs: Vec::new()
                        }
                    },
                    PortableType {
                        id: 144,
                        ty: Type {
                            path: Path {
                                segments: vec!["test".to_string(), "Path".to_string()]
                            },
                            type_params: Vec::new(),
                            type_def: TypeDef::Variant(TypeDefVariant {
                                variants: vec![Variant {
                                    name: "ThirdVariant".to_string(),
                                    fields: Vec::new(),
                                    index: 7,
                                    docs: Vec::new()
                                }]
                            }),
                            docs: Vec::new()
                        }
                    }
                ]
            }
        );
    }

    #[test]
    fn keep_empty_enums_portable() {
        let portable_registry = PortableRegistry {
            types: vec![PortableType {
                id: 0,
                ty: Type {
                    path: Path {
                        segments: vec!["test".to_string(), "Path".to_string()],
                    },
                    type_params: Vec::new(),
                    type_def: TypeDef::Variant(TypeDefVariant { variants: vec![] }),
                    docs: vec![
                        "important information".to_string(),
                        "danger ahead".to_string(),
                    ],
                },
            }],
        };
        let leaves_registry =
            <PortableRegistry as HashableRegistry<()>>::merkle_leaves_source(&portable_registry)
                .unwrap();
        assert_eq!(leaves_registry.types.len(), 1,);
    }

    #[test]
    fn keep_empty_enums_short() {
        let short_registry = ShortRegistry {
            types: vec![PortableType {
                id: 15,
                ty: Type {
                    path: Path {
                        segments: vec!["test".to_string(), "Path".to_string()],
                    },
                    type_params: Vec::new(),
                    type_def: TypeDef::Variant(TypeDefVariant { variants: vec![] }),
                    docs: vec![
                        "important information".to_string(),
                        "danger ahead".to_string(),
                    ],
                },
            }],
        };
        let leaves_registry =
            <ShortRegistry as HashableRegistry<()>>::merkle_leaves_source(&short_registry).unwrap();
        assert_eq!(leaves_registry.types.len(), 1,);
    }
}
