use crate::std::{
    string::{String, ToString},
    vec::Vec,
};
use frame_metadata::v15::RuntimeMetadataV15;
use parity_scale_codec::Decode;
use primitive_types::H256;
use substrate_parser::{
    cards::ExtendedCard, parse_transaction, parse_transaction_unmarked, AsMetadata, ShortSpecs,
};

use crate::{
    cutter::{cut_metadata, cut_metadata_transaction_unmarked, ShortMetadata},
    traits::{Blake3Leaf, ExtendedMetadata, HashableMetadata},
};

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

fn compare_registry_hashes(
    short_metadata: &ShortMetadata<Blake3Leaf, ()>,
    full_metadata: &RuntimeMetadataV15,
) {
    let root_short_metadata =
        <ShortMetadata<Blake3Leaf, ()> as HashableMetadata<()>>::types_merkle_root(
            short_metadata,
            &mut (),
        )
        .unwrap();
    let root_full_metadata = full_metadata.types_merkle_root(&mut ()).unwrap();
    assert_eq!(root_short_metadata, root_full_metadata);
}

fn compare_digests(
    short_metadata: &ShortMetadata<Blake3Leaf, ()>,
    full_metadata: &RuntimeMetadataV15,
    specs: &ShortSpecs,
) {
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

fn test_procedure(
    data: Vec<u8>,
    full_metadata: &RuntimeMetadataV15,
    specs: &ShortSpecs,
    genesis_hash: H256,
) {
    // Data could be parsed with full metadata
    let parsed_with_full =
        parse_transaction(&data.as_ref(), &mut (), full_metadata, Some(genesis_hash))
            .unwrap()
            .card(
                specs,
                &<RuntimeMetadataV15 as AsMetadata<()>>::spec_name_version(full_metadata)
                    .unwrap()
                    .spec_name,
            );

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

fn test_procedure_transaction_unmarked(
    data: Vec<u8>,
    full_metadata: &RuntimeMetadataV15,
    specs: &ShortSpecs,
    genesis_hash: H256,
) {
    // Data could be parsed with full metadata
    let parsed_with_full =
        parse_transaction_unmarked(&data.as_ref(), &mut (), full_metadata, Some(genesis_hash))
            .unwrap()
            .card(
                specs,
                &<RuntimeMetadataV15 as AsMetadata<()>>::spec_name_version(full_metadata)
                    .unwrap()
                    .spec_name,
            );

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
    let data = hex::decode("c901100208060007001b2c3ef70006050c0008264834504a64ace1373f0c8ed5d57381ddf54a2f67a318fa42b1352681606d00aebb0211dbb07b4d335a657257b8ac5e53794c901e4f616d4a254f2490c43934009ae581fef1fc06828723715731adcf810e42ce4dadad629b1b7fa5c3c144a81d55000800b1590f0007000000e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e5b1d91c89d3de85a4d6eee76ecf3a303cf38b59e7d81522eb7cd24b02eb161ff").unwrap();
    let metadata_westend = metadata_v15("for_tests/westend1006001");
    test_procedure(
        data,
        &metadata_westend,
        &specs_westend(),
        genesis_hash_westend(),
    );
}

#[test]
fn short_metadata_2() {
    let data = hex::decode("a00a0304a84b841c4d9d1a179be03bb31131c14ebf6ce22233158139ae28a3dfaac5fe1560a5e9e05cd5038d248ed73e0db608000003000000fc41b9bd8ef8fe53d58c7ea67c794c7ec9a73daf05e6d54b14ff6342c99ba64cfc41b9bd8ef8fe53d58c7ea67c794c7ec9a73daf05e6d54b14ff6342c99ba64c").unwrap();
    let metadata_acala = metadata_v15("for_tests/acala2230");
    test_procedure(data, &metadata_acala, &specs_acala(), genesis_hash_acala());
}

#[test]
fn short_metadata_3() {
    let data = hex::decode("641a04100000083434000008383800000c31333200000c313736d503040b63ce64c10c0541420f001800000091b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c391b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3").unwrap();
    let metadata_polkadot = metadata_v15("for_tests/polkadot1000001");
    test_procedure(
        data,
        &metadata_polkadot,
        &specs_polkadot(),
        genesis_hash_polkadot(),
    );
}

#[test]
fn short_metadata_4() {
    let data = hex::decode("6301039508080401380074063d03aeada02cc26977d0ab68927e12516a3287a3c72cc937981d1e7c9ade0cf91f0300eda947e425ea94b7642cc2d3939d30207e457a92049804580804044e7eca0311ba0594016808003d3d080701ada1020180d1043985798860eb63723790bda41de487e0730251717471e9660ab0aa5a6a65dde70807042c021673020808049d604a87138c0704aa060102ab90ebe5eeaf95088767ace3e78d04147180b016cf193a542fe5c9a4291e70784f6d64fb705349e4a361c453b28d18ba43b8e0bee72dad92845acbe281f21ea6c270f553481dc183b60ca8c1803544f33691adef9c5d4f807827e288143f4af2aa1c2c0b9e6087db1decedb85e2774f792c9bbc61ed85f031d11d175f93ecf7d030800a90307010107d5ebd78dfce4bdb789c0e310e2172b3f3a13ec09e39ba8b644e368816bd7acd57f10030025867d9fc900c0f7afe1ce1fc756f152b3f38e5a010001dec102c8abb0449d91dd617be6a7dc4d7ea0ae7f7cebaf1c9e4c9f0a64716c3d007800000000d50391010b63ce64c10c0541420f001800000091b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c391b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3").unwrap();
    let metadata_polkadot = metadata_v15("for_tests/polkadot1000001");
    test_procedure_transaction_unmarked(
        data,
        &metadata_polkadot,
        &specs_polkadot(),
        genesis_hash_polkadot(),
    );
}

#[test]
fn short_metadata_6() {
    let data = hex::decode("15000400a9569408db2bf9dd45318e13074b02ffce42dcf91b89cbef0fbe92191eb9627f019b02f1160003792192b533ff24d1ac92297d3905d02aac6dc63c1041420f001800000091b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c391b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3").unwrap();
    let metadata_polkadot = metadata_v15("for_tests/polkadot1000001");
    test_procedure_transaction_unmarked(
        data,
        &metadata_polkadot,
        &specs_polkadot(),
        genesis_hash_polkadot(),
    );
}

#[test]
fn short_metadata_7() {
    let data = hex::decode("0c000785720a10b88dce6946c280aa643806ce9cc345548b9770dea758c8c974b116b2e142d947a6b2fe037df9ef0744ab4ea4341d68c3a2aeeafc1b295094725f3afbb1833f908cd16a7c8928bf4683f4e8a300034f82cea733248c934b7ee4aa706c1e1bd238ad3a3741420f001800000091b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c391b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3").unwrap();
    let metadata_polkadot = metadata_v15("for_tests/polkadot1000001");
    test_procedure_transaction_unmarked(
        data,
        &metadata_polkadot,
        &specs_polkadot(),
        genesis_hash_polkadot(),
    );
}

#[test]
fn short_metadata_8() {
    let data = hex::decode("78000006000001010000004a6e76f5062e334f7322752db2dae9d19edfe764172aaee003000001000000262e1b2ad728475fd6fe88e62d34c200abe6fd693931ddad144059b1eb884e5bc16d68cf9978c938e405eec35d283be02e720072e8a0f66b11c722bb85d86f01").unwrap();
    let metadata_bifrost = metadata_v15("for_tests/bifrost992");
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
    let metadata_rococo = metadata_v15("for_tests/rococo1006002_experimental");
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
    let metadata_rococo = metadata_v15("for_tests/rococo1006002_experimental");
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
    let metadata_polkadot = metadata_v15("for_tests/polkadot1000001");
    test_procedure(
        data,
        &metadata_polkadot,
        &specs_polkadot(),
        genesis_hash_polkadot(),
    );
}
