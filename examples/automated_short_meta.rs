#[cfg(all(feature = "std", feature = "merkle-standard", feature = "proof-gen"))]
use frame_metadata::v15::RuntimeMetadataV15;

#[cfg(all(feature = "std", feature = "merkle-standard", feature = "proof-gen"))]
use metadata_shortener::{
    cutter::{cut_metadata, ShortMetadata},
    traits::{Blake3Leaf, ExtendedMetadata, HashableMetadata},
};

#[cfg(all(feature = "std", feature = "merkle-standard", feature = "proof-gen"))]
use parity_scale_codec::{Decode, Encode};

#[cfg(all(feature = "std", feature = "merkle-standard", feature = "proof-gen"))]
use substrate_parser::ShortSpecs;

#[cfg(all(feature = "std", feature = "merkle-standard", feature = "proof-gen"))]
fn main() {
    let meta_hex = std::fs::read_to_string("for_tests/westend1006001").unwrap();
    let meta = hex::decode(meta_hex.trim()).unwrap();
    println!("length of basic meta: {}", meta.len());
    let full_metadata = RuntimeMetadataV15::decode(&mut &meta[5..]).unwrap();

    let specs_westend = ShortSpecs {
        base58prefix: 42,
        decimals: 12,
        unit: "WND".to_string(),
    };

    let data = hex::decode("c901100208060007001b2c3ef70006050c0008264834504a64ace1373f0c8ed5d57381ddf54a2f67a318fa42b1352681606d00aebb0211dbb07b4d335a657257b8ac5e53794c901e4f616d4a254f2490c43934009ae581fef1fc06828723715731adcf810e42ce4dadad629b1b7fa5c3c144a81d55000800d624000007000000e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e5b1d91c89d3de85a4d6eee76ecf3a303cf38b59e7d81522eb7cd24b02eb161ff").unwrap();

    // Make short metadata here. It is sufficient to decode the transaction above. Decoding capabilities are checked in `tests` module.
    let short_metadata =
        cut_metadata(&data.as_ref(), &mut (), &full_metadata, &specs_westend).unwrap();
    let short_meta_scaled = short_metadata.encode();
    println!(
        "length of shortened meta: {}, number of leaves: {}, number of lemmas: {}",
        short_meta_scaled.len(),
        short_metadata.indices.len(),
        short_metadata.lemmas.len()
    );

    // Calculate root for short metadata and full metadata. Only types part here. Part with specs must be mixed in later.
    let root_short_metadata =
        <ShortMetadata<Blake3Leaf, ()> as HashableMetadata<()>>::types_merkle_root(
            &short_metadata,
            &mut (),
        )
        .unwrap();
    let root_full_metadata =
        <RuntimeMetadataV15 as HashableMetadata<()>>::types_merkle_root(&full_metadata, &mut ())
            .unwrap();

    // Roots are equal.
    assert_eq!(root_short_metadata, root_full_metadata);

    // Calculate digests for short metadata and full metadata. Specs mixed in.
    let digest_short_metadata =
        <ShortMetadata<Blake3Leaf, ()> as ExtendedMetadata<()>>::digest(&short_metadata, &mut ())
            .unwrap();
    let digest_full_metadata =
        <RuntimeMetadataV15 as HashableMetadata<()>>::digest_with_short_specs(
            &full_metadata,
            &specs_westend,
            &mut (),
        )
        .unwrap();

    // Digests are equal.
    assert_eq!(digest_short_metadata, digest_full_metadata);
}

#[cfg(not(all(feature = "std", feature = "merkle-standard", feature = "proof-gen")))]
fn main() {
    panic!("Examples should be run under std, with merkle-standard and proof-gen features both included.");
}
