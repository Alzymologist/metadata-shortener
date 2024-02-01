use crate::std::{
    string::{String, ToString},
    vec::Vec,
};
use frame_metadata::{v14::RuntimeMetadataV14, v15::RuntimeMetadataV15};
use parity_scale_codec::Decode;
use primitive_types::H256;
use substrate_parser::{
    cards::ExtendedCard, parse_transaction, parse_transaction_unmarked, AsMetadata, ShortSpecs,
};

use crate::{
    cut_metadata::{cut_metadata, cut_metadata_transaction_unmarked, ShortMetadata},
    traits::{Blake3Leaf, ExtendedMetadata, HashableMetadata, HashableRegistry},
};

fn metadata_v14(filename: &str) -> RuntimeMetadataV14 {
    let metadata_hex = std::fs::read_to_string(filename).unwrap();
    let metadata_vec = hex::decode(metadata_hex.trim()).unwrap();
    RuntimeMetadataV14::decode(&mut &metadata_vec[5..]).unwrap()
}

fn metadata_v15(filename: &str) -> RuntimeMetadataV15 {
    let metadata_hex = std::fs::read_to_string(filename).unwrap();
    let metadata_vec = hex::decode(metadata_hex.trim()).unwrap();
    RuntimeMetadataV15::decode(&mut &metadata_vec[5..]).unwrap()
}

fn genesis_hash_acala() -> H256 {
    H256(
        hex::decode("fc41b9bd8ef8fe53d58c7ea67c794c7ec9a73daf05e6d54b14ff6342c99ba64c")
            .unwrap()
            .try_into()
            .unwrap(),
    )
}

fn genesis_hash_astar() -> H256 {
    H256(
        hex::decode("9eb76c5184c4ab8679d2d5d819fdf90b9c001403e9e17da2e14b6d8aec4029c6")
            .unwrap()
            .try_into()
            .unwrap(),
    )
}

fn genesis_hash_bifrost() -> H256 {
    H256(
        hex::decode("262e1b2ad728475fd6fe88e62d34c200abe6fd693931ddad144059b1eb884e5b")
            .unwrap()
            .try_into()
            .unwrap(),
    )
}

fn genesis_hash_polkadot() -> H256 {
    H256(
        hex::decode("91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3")
            .unwrap()
            .try_into()
            .unwrap(),
    )
}

fn genesis_hash_rococo() -> H256 {
    H256(
        hex::decode("f421bf66696bba5abfa1ae7aa8ec8bac9ed151f7ce16b996b5d3bbde614c3441")
            .unwrap()
            .try_into()
            .unwrap(),
    )
}

fn genesis_hash_westend() -> H256 {
    H256(
        hex::decode("e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e")
            .unwrap()
            .try_into()
            .unwrap(),
    )
}

fn specs_acala() -> ShortSpecs {
    ShortSpecs {
        base58prefix: 10,
        decimals: 12,
        unit: "ACA".to_string(),
    }
}

fn specs_astar() -> ShortSpecs {
    ShortSpecs {
        base58prefix: 5,
        decimals: 18,
        unit: "ASTR".to_string(),
    }
}

fn specs_bifrost() -> ShortSpecs {
    ShortSpecs {
        base58prefix: 6,
        decimals: 12,
        unit: "BNC".to_string(),
    }
}

fn specs_polkadot() -> ShortSpecs {
    ShortSpecs {
        base58prefix: 0,
        decimals: 10,
        unit: "DOT".to_string(),
    }
}

fn specs_rococo() -> ShortSpecs {
    ShortSpecs {
        base58prefix: 42,
        decimals: 12,
        unit: "ROC".to_string(),
    }
}

fn specs_westend() -> ShortSpecs {
    ShortSpecs {
        base58prefix: 42,
        decimals: 12,
        unit: "WND".to_string(),
    }
}

fn compare_registry_hashes<M>(short_metadata: &ShortMetadata<Blake3Leaf, ()>, full_metadata: &M)
where
    M: HashableMetadata<()>,
    <M as AsMetadata<()>>::TypeRegistry: HashableRegistry<()>,
{
    let root_short_metadata =
        <ShortMetadata<Blake3Leaf, ()> as HashableMetadata<()>>::types_merkle_root(
            short_metadata,
            &mut (),
        )
        .unwrap();
    let root_full_metadata = full_metadata.types_merkle_root(&mut ()).unwrap();
    assert_eq!(root_short_metadata, root_full_metadata);
}

fn compare_digests<M>(
    short_metadata: &ShortMetadata<Blake3Leaf, ()>,
    full_metadata: &M,
    specs: &ShortSpecs,
) where
    M: HashableMetadata<()>,
    <M as AsMetadata<()>>::TypeRegistry: HashableRegistry<()>,
{
    let digest_short_metadata =
        <ShortMetadata<Blake3Leaf, ()> as ExtendedMetadata<()>>::digest(short_metadata, &mut ())
            .unwrap();
    let digest_full_metadata = full_metadata
        .digest_with_short_specs(specs, &mut ())
        .unwrap();
    assert_eq!(digest_short_metadata, digest_full_metadata);
}

fn compare_parsing(parsed_with_full: &[ExtendedCard], parsed_with_short: &[ExtendedCard]) {
    let printed_full = format!(
        "\n{}\n",
        parsed_with_full
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let printed_short = format!(
        "\n{}\n",
        parsed_with_short
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    assert_eq!(printed_full, printed_short);
}

fn test_procedure<M>(data: Vec<u8>, full_metadata: &M, specs: &ShortSpecs, genesis_hash: H256)
where
    M: HashableMetadata<()>,
    <M as AsMetadata<()>>::TypeRegistry: HashableRegistry<()>,
{
    // Data could be parsed with full metadata
    let parsed_with_full =
        parse_transaction(&data.as_ref(), &mut (), full_metadata, Some(genesis_hash))
            .unwrap()
            .card(specs, &full_metadata.spec_name_version().unwrap().spec_name);

    // Metadata could be shortened
    let short_metadata = cut_metadata(&data.as_ref(), &mut (), full_metadata, specs).unwrap();

    // Registry hashes match
    compare_registry_hashes(&short_metadata, full_metadata);

    // Digests match
    compare_digests(&short_metadata, full_metadata, specs);

    // Data could be parsed with short metadata
    let parsed_with_short = short_metadata
        .parse_transaction(&data.as_ref(), &mut ())
        .unwrap()
        .card(
            &<ShortMetadata<Blake3Leaf, ()> as ExtendedMetadata<()>>::to_specs(&short_metadata)
                .unwrap(),
            &<ShortMetadata<Blake3Leaf, ()> as AsMetadata<()>>::spec_name_version(&short_metadata)
                .unwrap()
                .spec_name,
        );

    // Call data is identical (printed cards with no docs)
    compare_parsing(
        &parsed_with_full.call_result.unwrap(),
        &parsed_with_short.call_result.unwrap(),
    );

    // Extensions data is identical (printed cards with no docs)
    compare_parsing(&parsed_with_full.extensions, &parsed_with_short.extensions);
}

fn test_procedure_transaction_unmarked<M>(
    data: Vec<u8>,
    full_metadata: &M,
    specs: &ShortSpecs,
    genesis_hash: H256,
) where
    M: HashableMetadata<()>,
    <M as AsMetadata<()>>::TypeRegistry: HashableRegistry<()>,
{
    // Data could be parsed with full metadata
    let parsed_with_full =
        parse_transaction_unmarked(&data.as_ref(), &mut (), full_metadata, Some(genesis_hash))
            .unwrap()
            .card(specs, &full_metadata.spec_name_version().unwrap().spec_name);

    // Metadata could be shortened
    let short_metadata =
        cut_metadata_transaction_unmarked(&data.as_ref(), &mut (), full_metadata, specs).unwrap();

    // Registry hashes match
    compare_registry_hashes(&short_metadata, full_metadata);

    // Digests match
    compare_digests(&short_metadata, full_metadata, specs);

    // Data could be parsed with short metadata
    let parsed_with_short = short_metadata
        .parse_transaction_unmarked(&data.as_ref(), &mut ())
        .unwrap()
        .card(
            &<ShortMetadata<Blake3Leaf, ()> as ExtendedMetadata<()>>::to_specs(&short_metadata)
                .unwrap(),
            &<ShortMetadata<Blake3Leaf, ()> as AsMetadata<()>>::spec_name_version(&short_metadata)
                .unwrap()
                .spec_name,
        );

    // Call data is identical (printed cards with no docs)
    compare_parsing(&parsed_with_full.call, &parsed_with_short.call);

    // Extensions data is identical (printed cards with no docs)
    compare_parsing(&parsed_with_full.extensions, &parsed_with_short.extensions);
}

#[test]
fn short_metadata_1() {
    let data = hex::decode("4d0210020806000046ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a07001b2c3ef70006050c0008264834504a64ace1373f0c8ed5d57381ddf54a2f67a318fa42b1352681606d00aebb0211dbb07b4d335a657257b8ac5e53794c901e4f616d4a254f2490c43934009ae581fef1fc06828723715731adcf810e42ce4dadad629b1b7fa5c3c144a81d550008009723000007000000e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e5b1d91c89d3de85a4d6eee76ecf3a303cf38b59e7d81522eb7cd24b02eb161ff").unwrap();
    let metadata_westend = metadata_v14("for_tests/westend9111");
    test_procedure(
        data,
        &metadata_westend,
        &specs_westend(),
        genesis_hash_westend(),
    );
}

#[test]
fn short_metadata_2() {
    let data = hex::decode("a00a0304a84b841c4d9d1a179be03bb31131c14ebf6ce22233158139ae28a3dfaac5fe1560a5e9e05cd5038d248ed73e0d9808000003000000fc41b9bd8ef8fe53d58c7ea67c794c7ec9a73daf05e6d54b14ff6342c99ba64cfc41b9bd8ef8fe53d58c7ea67c794c7ec9a73daf05e6d54b14ff6342c99ba64c").unwrap();
    let metadata_acala = metadata_v14("for_tests/acala2200");
    test_procedure(data, &metadata_acala, &specs_acala(), genesis_hash_acala());
}

#[test]
fn short_metadata_3() {
    let data = hex::decode("641a04100000083434000008383800000c31333200000c313736d503040b63ce64c10c05d62400001800000091b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c391b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3").unwrap();
    let metadata_polkadot = metadata_v14("for_tests/polkadot9430");
    test_procedure(
        data,
        &metadata_polkadot,
        &specs_polkadot(),
        genesis_hash_polkadot(),
    );
}

#[test]
fn short_metadata_4() {
    let data = hex::decode("6301039508080401380074063d03aeada02cc26977d0ab68927e12516a3287a3c72cc937981d1e7c9ade0cf91f0300eda947e425ea94b7642cc2d3939d30207e457a92049804580804044e7eca0311ba0594016808003d3d080701ada1020180d1043985798860eb63723790bda41de487e0730251717471e9660ab0aa5a6a65dde70807042c021673020808049d604a87138c0704aa060102ab90ebe5eeaf95088767ace3e78d04147180b016cf193a542fe5c9a4291e70784f6d64fb705349e4a361c453b28d18ba43b8e0bee72dad92845acbe281f21ea6c270f553481dc183b60ca8c1803544f33691adef9c5d4f807827e288143f4af2aa1c2c0b9e6087db1decedb85e2774f792c9bbc61ed85f031d11d175f93ecf7d030800a90307010107d5ebd78dfce4bdb789c0e310e2172b3f3a13ec09e39ba8b644e368816bd7acd57f10030025867d9fc900c0f7afe1ce1fc756f152b3f38e5a010001dec102c8abb0449d91dd617be6a7dc4d7ea0ae7f7cebaf1c9e4c9f0a64716c3d007800000000d50391010b63ce64c10c05d62400001800000091b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c391b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3").unwrap();
    let metadata_polkadot = metadata_v14("for_tests/polkadot9430");
    test_procedure_transaction_unmarked(
        data,
        &metadata_polkadot,
        &specs_polkadot(),
        genesis_hash_polkadot(),
    );
}

#[test]
fn short_metadata_5() {
    let data = hex::decode("1f00001b7a61c73f450f4518731981d9cdd99013cfe044294617b74f93ba4bba6090d00b63ce64c10c05d5030403d202964942000000020000009eb76c5184c4ab8679d2d5d819fdf90b9c001403e9e17da2e14b6d8aec4029c69eb76c5184c4ab8679d2d5d819fdf90b9c001403e9e17da2e14b6d8aec4029c6").unwrap();
    let metadata_astar = metadata_v14("for_tests/astar66");
    test_procedure_transaction_unmarked(
        data,
        &metadata_astar,
        &specs_astar(),
        genesis_hash_astar(),
    );
}

#[test]
fn short_metadata_6() {
    let data = hex::decode("15000600a9569408db2bf9dd45318e13074b02ffce42dcf91b89cbef0fbe92191eb9627f019b02f1160003792192b533ff24d1ac92297d3905d02aac6dc63c10d62400001800000091b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c391b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3").unwrap();
    let metadata_polkadot = metadata_v14("for_tests/polkadot9430");
    test_procedure_transaction_unmarked(
        data,
        &metadata_polkadot,
        &specs_polkadot(),
        genesis_hash_polkadot(),
    );
}

#[test]
fn short_metadata_7() {
    let data = hex::decode("0c000785720a647b9dbf43890b68e8b75b6832581f522fdea8e0c71662a6d19110a85e6c5b41a0cc1c39c26bbe080e79b823d7b34756c1d3df05ca8d1b6a6bac81c76aa268f92ccd919550fd8c6e8b9489f419aaebd697e43d3b0dffd0bb3355b59406322d0b39a7d7481762b339321a4819c955ace60098ca898ab5c4de1e796efd3214de768a4857b88dce6946c280aa643806ce9cc345548b9770dea758c8c974b116b2e142d947a6b2fe037df9ef0744ab4ea4341d68c3a2aeeafc1b295094725f3afbb1833f908cd16a7c8928bf4683f4e8a300034f82cea733248c934b7ee4aa706c1e1bd238ad3a37d62400001800000091b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c391b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3").unwrap();
    let metadata_polkadot = metadata_v14("for_tests/polkadot9430");
    test_procedure_transaction_unmarked(
        data,
        &metadata_polkadot,
        &specs_polkadot(),
        genesis_hash_polkadot(),
    );
}

#[test]
fn short_metadata_8() {
    let data = hex::decode("78000006000001010000004a6e76f5062e334f7322752db2dae9d19edfe764172aaed603000001000000262e1b2ad728475fd6fe88e62d34c200abe6fd693931ddad144059b1eb884e5bc16d68cf9978c938e405eec35d283be02e720072e8a0f66b11c722bb85d86f01").unwrap();
    let metadata_bifrost = metadata_v14("for_tests/bifrost982");
    test_procedure_transaction_unmarked(
        data,
        &metadata_bifrost,
        &specs_bifrost(),
        genesis_hash_bifrost(),
    );
}

#[test]
fn short_metadata_9() {
    let data = hex::decode("0403008465567bd3ad504ab85a6d3ecbc0ce39eec6aacc180c38b564513d9f6113e14c070010a5d4e805000000002427000016000000f421bf66696bba5abfa1ae7aa8ec8bac9ed151f7ce16b996b5d3bbde614c3441f421bf66696bba5abfa1ae7aa8ec8bac9ed151f7ce16b996b5d3bbde614c344100").unwrap();
    let metadata_rococo = metadata_v14("for_tests/rococo_updated");
    test_procedure_transaction_unmarked(
        data,
        &metadata_rococo,
        &specs_rococo(),
        genesis_hash_rococo(),
    );
}

#[test]
fn short_metadata_10() {
    let data = hex::decode("0403008465567bd3ad504ab85a6d3ecbc0ce39eec6aacc180c38b564513d9f6113e14c070010a5d4e805000000012427000016000000f421bf66696bba5abfa1ae7aa8ec8bac9ed151f7ce16b996b5d3bbde614c3441f421bf66696bba5abfa1ae7aa8ec8bac9ed151f7ce16b996b5d3bbde614c3441017a090b369e6a7472778569cb3e42ba5dcf4eca8ab505e895cd5463ca48d64ac9").unwrap();
    let metadata_rococo = metadata_v14("for_tests/rococo_updated");
    test_procedure_transaction_unmarked(
        data,
        &metadata_rococo,
        &specs_rococo(),
        genesis_hash_rococo(),
    );
}

#[test]
fn short_metadata_11() {
    let data = hex::decode("641a04100000083434000008383800000c31333200000c313736d503040b63ce64c10c0541420f001800000091b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c391b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3").unwrap();
    let metadata_polkadot = metadata_v15("for_tests/polkadot1000001_v15");
    test_procedure(
        data,
        &metadata_polkadot,
        &specs_polkadot(),
        genesis_hash_polkadot(),
    );
}

#[test]
#[ignore]
// This test was supposed to check if the short metadata is identical in
// between `RuntimeMetadataV14` and `RuntimeMetadataV15` which happen to be
// available at the same time. Well, it is not.
// In `RuntimeMetadataV14` the type of unchecked extrinsic (`Vec<u8>` or
// construction resolveable into `Vec<u8>` with parameters corresponding to call,
// address, signature, and extra of unchecked extrinsic) is present close to the
// type registry tail, thus shifting the types that are in registry *after* it
// to `+1` id.
// `PortableRegistry` has tool to eliminate some types from the registry and
// correspondingly adjust remaining types id's, however, it shuffles remaining
// types, and therefore is not suitable for the task as is.
// As `RuntimeMetadataV15` inevitably replaces `RuntimeMetadataV14`, there
// could be no sense to force `RuntimeMetadataV14` registry to compatibility,
// with focus made on supporting `RuntimeMetadataV15` instead.
fn short_metadata_12() {
    let data = hex::decode("641a04100000083434000008383800000c31333200000c313736d503040b63ce64c10c0541420f001800000091b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c391b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3").unwrap();
    let specs = specs_polkadot();

    let metadata_polkadot_v14 = metadata_v14("for_tests/polkadot1000001_v14");
    let short_metadata_v14: ShortMetadata<Blake3Leaf, ()> =
        cut_metadata(&data.as_ref(), &mut (), &metadata_polkadot_v14, &specs).unwrap();

    let metadata_polkadot_v15 = metadata_v15("for_tests/polkadot1000001_v15");
    let short_metadata_v15: ShortMetadata<Blake3Leaf, ()> =
        cut_metadata(&data.as_ref(), &mut (), &metadata_polkadot_v15, &specs).unwrap();

    assert_eq!(short_metadata_v14, short_metadata_v15);
}
