#[cfg(feature = "std")]
use frame_metadata::v14::RuntimeMetadataV14;
#[cfg(feature = "std")]
use metadata_shortener::{
    cut_metadata::{cut_metadata_transaction_unmarked, MetadataDescriptor, ShortMetadata},
    traits::{ExtendedMetadata, HashableMetadata},
};
#[cfg(feature = "std")]
use parity_scale_codec::{Decode, Encode};
#[cfg(feature = "std")]
use substrate_parser::{traits::AsMetadata, ShortSpecs};

#[cfg(feature = "std")]
fn main() {
    let meta_file = std::fs::read("for_tests/westend9430").unwrap();
    let meta = Vec::<u8>::decode(&mut &meta_file[..]).unwrap();
    println!("length of basic meta: {}", meta.len());
    let meta_v14 = RuntimeMetadataV14::decode(&mut &meta[5..]).unwrap();

    let specs_westend = ShortSpecs {
        base58prefix: 42,
        decimals: 12,
        unit: "WND".to_string(),
    };

    let data = hex::decode("100208060007001b2c3ef70006050c0008264834504a64ace1373f0c8ed5d57381ddf54a2f67a318fa42b1352681606d00aebb0211dbb07b4d335a657257b8ac5e53794c901e4f616d4a254f2490c43934009ae581fef1fc06828723715731adcf810e42ce4dadad629b1b7fa5c3c144a81d55000800d624000007000000e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e5b1d91c89d3de85a4d6eee76ecf3a303cf38b59e7d81522eb7cd24b02eb161ff").unwrap();

    // Make short metadata here. It is sufficient to decode the transaction above. Decoding capabilities are checked in `tests` module.
    let short_metadata =
        cut_metadata_transaction_unmarked(&data.as_ref(), &mut (), &meta_v14, &specs_westend)
            .unwrap();
    let short_meta_scaled = short_metadata.encode();
    println!(
        "length of shortened meta: {}, number of leaves: {}, number of lemmas: {}",
        short_meta_scaled.len(),
        short_metadata.indices.len(),
        short_metadata.lemmas.len()
    );

    // Calculate root for short metadata and full metadata. Only types part here. Part with specs must be mixed in later.
    let root_short_metadata =
        <ShortMetadata as HashableMetadata<()>>::types_merkle_root(&short_metadata).unwrap();
    let root_full_metadata =
        <RuntimeMetadataV14 as HashableMetadata<()>>::types_merkle_root(&meta_v14).unwrap();

    // Roots are equal.
    assert_eq!(root_short_metadata, root_full_metadata);

    // Calculate digests for short metadata and full metadata. Specs mixed in.
    let digest_short_metadata =
        <ShortMetadata as ExtendedMetadata<()>>::digest(&short_metadata).unwrap();
    let descriptor_full_metadata = MetadataDescriptor::V0 {
        extrinsic: <RuntimeMetadataV14 as AsMetadata<()>>::extrinsic(&meta_v14),
        spec_name_version: <RuntimeMetadataV14 as AsMetadata<()>>::spec_name_version(&meta_v14)
            .unwrap(),
        base58prefix: specs_westend.base58prefix,
        decimals: specs_westend.decimals,
        unit: specs_westend.unit,
    };
    let digest_full_metadata =
        <RuntimeMetadataV14 as HashableMetadata<()>>::digest_with_descriptor(
            &meta_v14,
            &descriptor_full_metadata,
        )
        .unwrap();

    // Digests are equal.
    assert_eq!(digest_short_metadata, digest_full_metadata);
}

#[cfg(not(feature = "std"))]
fn main() {
    panic!("Example is not intended for no-std.");
}
