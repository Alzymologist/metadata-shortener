use crate::std::{
    string::{String, ToString},
    vec::Vec,
};
use frame_metadata::v14::RuntimeMetadataV14;
use parity_scale_codec::Decode;
use primitive_types::H256;
use substrate_parser::{parse_transaction, parse_transaction_unmarked, AsMetadata, ShortSpecs};

use crate::{
    cut_metadata::{cut_metadata, cut_metadata_transaction_unmarked, ShortMetadata},
    traits::{ExtendedMetadata, HashableMetadata},
};

fn metadata(filename: &str) -> RuntimeMetadataV14 {
    let metadata_hex = std::fs::read_to_string(filename).unwrap();
    let metadata_vec = hex::decode(metadata_hex.trim()).unwrap()[5..].to_vec();
    RuntimeMetadataV14::decode(&mut &metadata_vec[..]).unwrap()
}

fn specs_westend() -> ShortSpecs {
    ShortSpecs {
        base58prefix: 42,
        decimals: 12,
        unit: "WND".to_string(),
    }
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

fn specs_polkadot() -> ShortSpecs {
    ShortSpecs {
        base58prefix: 0,
        decimals: 10,
        unit: "DOT".to_string(),
    }
}

fn compare_registry_hashes(short_metadata: &ShortMetadata, full_metadata: &RuntimeMetadataV14) {
    let root_short_metadata =
        <ShortMetadata as HashableMetadata<()>>::types_merkle_root(short_metadata).unwrap();
    let root_full_metadata =
        <RuntimeMetadataV14 as HashableMetadata<()>>::types_merkle_root(full_metadata).unwrap();
    assert_eq!(root_short_metadata, root_full_metadata);
}

fn compare_digests(
    short_metadata: &ShortMetadata,
    full_metadata: &RuntimeMetadataV14,
    specs: &ShortSpecs,
) {
    let digest_short_metadata =
        <ShortMetadata as ExtendedMetadata<()>>::digest(short_metadata).unwrap();
    let digest_full_metadata =
        <RuntimeMetadataV14 as HashableMetadata<()>>::digest_with_short_specs(full_metadata, specs)
            .unwrap();
    assert_eq!(digest_short_metadata, digest_full_metadata);
}

#[test]
fn short_metadata_1_decode() {
    let data = hex::decode("4d0210020806000046ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a07001b2c3ef70006050c0008264834504a64ace1373f0c8ed5d57381ddf54a2f67a318fa42b1352681606d00aebb0211dbb07b4d335a657257b8ac5e53794c901e4f616d4a254f2490c43934009ae581fef1fc06828723715731adcf810e42ce4dadad629b1b7fa5c3c144a81d550008009723000007000000e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e5b1d91c89d3de85a4d6eee76ecf3a303cf38b59e7d81522eb7cd24b02eb161ff").unwrap();

    let metadata_westend = metadata("for_tests/westend9111");
    let specs_westend = specs_westend();

    let short_metadata =
        cut_metadata(&data.as_ref(), &mut (), &metadata_westend, &specs_westend).unwrap();

    compare_registry_hashes(&short_metadata, &metadata_westend);
    compare_digests(&short_metadata, &metadata_westend, &specs_westend);

    let reply = parse_transaction(
        &data.as_ref(),
        &mut (),
        &short_metadata,
        H256(
            hex::decode("e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e")
                .unwrap()
                .try_into()
                .unwrap(),
        ),
    )
    .unwrap()
    .card(
        &short_metadata.to_specs(),
        &<ShortMetadata as AsMetadata<()>>::spec_name_version(&short_metadata)
            .unwrap()
            .spec_name,
    );

    let call_printed = format!(
        "\n{}\n",
        reply
            .call_result
            .unwrap()
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let call_known = "
Pallet: Utility
  Call: batch_all
    Field Name: calls
      Sequence: 2 element(s)
        Pallet: Staking
          Call: bond
            Field Name: controller
              Enum
                Enum Variant Name: Id
                  Id: 5DfhGyQdFobKM8NsWvEeAKk5EQQgYe9AydgJ7rMB6E1EqRzV
            Field Name: value
              Balance: 1.061900000000 WND
            Field Name: payee
              Enum
                Enum Variant Name: Staked
        Pallet: Staking
          Call: nominate
            Field Name: targets
              Sequence: 3 element(s)
                Enum
                  Enum Variant Name: Id
                    Id: 5CFPcUJgYgWryPaV1aYjSbTpbTLu42V32Ytw1L9rfoMAsfGh
                Enum
                  Enum Variant Name: Id
                    Id: 5G1ojzh47Yt8KoYhuAjXpHcazvsoCXe3G8LZchKDvumozJJJ
                Enum
                  Enum Variant Name: Id
                    Id: 5FZoQhgUCmqBxnkHX7jCqThScS2xQWiwiF61msg63CFL3Y8f
";
    assert_eq!(call_known, call_printed);

    let extensions_printed = format!(
        "\n{}\n",
        reply
            .extensions
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let extensions_known = "
Era: Mortal, phase: 5, period: 64
Nonce: 2
Tip: 0 pWND
Chain: westend9111
Tx Version: 7
Block Hash: 5b1d91c89d3de85a4d6eee76ecf3a303cf38b59e7d81522eb7cd24b02eb161ff
";
    assert_eq!(extensions_known, extensions_printed);
}

#[test]
fn short_metadata_2_decode() {
    let data = hex::decode("a00a0304a84b841c4d9d1a179be03bb31131c14ebf6ce22233158139ae28a3dfaac5fe1560a5e9e05cd5038d248ed73e0d9808000003000000fc41b9bd8ef8fe53d58c7ea67c794c7ec9a73daf05e6d54b14ff6342c99ba64cfc41b9bd8ef8fe53d58c7ea67c794c7ec9a73daf05e6d54b14ff6342c99ba64c").unwrap();

    let metadata_acala = metadata("for_tests/acala2200");
    let specs_acala = specs_acala();

    let short_metadata =
        cut_metadata(&data.as_ref(), &mut (), &metadata_acala, &specs_acala).unwrap();

    compare_registry_hashes(&short_metadata, &metadata_acala);
    compare_digests(&short_metadata, &metadata_acala, &specs_acala);

    let reply = parse_transaction(
        &data.as_ref(),
        &mut (),
        &short_metadata,
        H256(
            hex::decode("fc41b9bd8ef8fe53d58c7ea67c794c7ec9a73daf05e6d54b14ff6342c99ba64c")
                .unwrap()
                .try_into()
                .unwrap(),
        ),
    )
    .unwrap()
    .card(
        &short_metadata.to_specs(),
        &<ShortMetadata as AsMetadata<()>>::spec_name_version(&short_metadata)
            .unwrap()
            .spec_name,
    );

    let call_printed = format!(
        "\n{}\n",
        reply
            .call_result
            .unwrap()
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let call_known = "
Pallet: Balances
  Call: transfer_keep_alive
    Field Name: dest
      Enum
        Enum Variant Name: Address20
          Sequence u8: a84b841c4d9d1a179be03bb31131c14ebf6ce222
    Field Name: value
      Balance: 123456789012345.678901234567890123456789 TACA
";
    assert_eq!(call_known, call_printed);

    let extensions_printed = format!(
        "\n{}\n",
        reply
            .extensions
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let extensions_known = "
Era: Mortal, phase: 61, period: 64
Struct: 1 field(s)
  Field Name: nonce
    Nonce: 2339
Tip: 55.555555 uACA
Chain: acala2200
Tx Version: 3
Block Hash: fc41b9bd8ef8fe53d58c7ea67c794c7ec9a73daf05e6d54b14ff6342c99ba64c
";
    assert_eq!(extensions_known, extensions_printed);
}

#[test]
fn short_metadata_3_decode() {
    let data = hex::decode("641a04100000083434000008383800000c31333200000c313736d503040b63ce64c10c05d62400001800000091b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c391b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3").unwrap();

    let metadata_polkadot = metadata("for_tests/polkadot9430");
    let specs_polkadot = specs_polkadot();

    let short_metadata =
        cut_metadata(&data.as_ref(), &mut (), &metadata_polkadot, &specs_polkadot).unwrap();

    compare_registry_hashes(&short_metadata, &metadata_polkadot);
    compare_digests(&short_metadata, &metadata_polkadot, &specs_polkadot);

    let reply = parse_transaction(
        &data.as_ref(),
        &mut (),
        &short_metadata,
        H256(
            hex::decode("91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3")
                .unwrap()
                .try_into()
                .unwrap(),
        ),
    )
    .unwrap()
    .card(
        &short_metadata.to_specs(),
        &<ShortMetadata as AsMetadata<()>>::spec_name_version(&short_metadata)
            .unwrap()
            .spec_name,
    );

    let call_printed = format!(
        "\n{}\n",
        reply
            .call_result
            .unwrap()
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let call_known = "
Pallet: Utility
  Call: force_batch
    Field Name: calls
      Sequence: 4 element(s)
        Pallet: System
          Call: remark
            Field Name: remark
              Text: 44
        Pallet: System
          Call: remark
            Field Name: remark
              Text: 88
        Pallet: System
          Call: remark
            Field Name: remark
              Text: 132
        Pallet: System
          Call: remark
            Field Name: remark
              Text: 176
";
    assert_eq!(call_known, call_printed);

    let extensions_printed = format!(
        "\n{}\n",
        reply
            .extensions
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let extensions_known = "
Era: Mortal, phase: 61, period: 64
Nonce: 1
Tip: 555.2342355555 DOT
Chain: polkadot9430
Tx Version: 24
Block Hash: 91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3
";
    assert_eq!(extensions_known, extensions_printed);
}

#[test]
fn short_metadata_4_decode() {
    let data = hex::decode("6301039508080401380074063d03aeada02cc26977d0ab68927e12516a3287a3c72cc937981d1e7c9ade0cf91f0300eda947e425ea94b7642cc2d3939d30207e457a92049804580804044e7eca0311ba0594016808003d3d080701ada1020180d1043985798860eb63723790bda41de487e0730251717471e9660ab0aa5a6a65dde70807042c021673020808049d604a87138c0704aa060102ab90ebe5eeaf95088767ace3e78d04147180b016cf193a542fe5c9a4291e70784f6d64fb705349e4a361c453b28d18ba43b8e0bee72dad92845acbe281f21ea6c270f553481dc183b60ca8c1803544f33691adef9c5d4f807827e288143f4af2aa1c2c0b9e6087db1decedb85e2774f792c9bbc61ed85f031d11d175f93ecf7d030800a90307010107d5ebd78dfce4bdb789c0e310e2172b3f3a13ec09e39ba8b644e368816bd7acd57f10030025867d9fc900c0f7afe1ce1fc756f152b3f38e5a010001dec102c8abb0449d91dd617be6a7dc4d7ea0ae7f7cebaf1c9e4c9f0a64716c3d007800000000d50391010b63ce64c10c05d62400001800000091b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c391b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3").unwrap();

    let metadata_polkadot = metadata("for_tests/polkadot9430");
    let specs_polkadot = specs_polkadot();

    let short_metadata = cut_metadata_transaction_unmarked(
        &data.as_ref(),
        &mut (),
        &metadata_polkadot,
        &specs_polkadot,
    )
    .unwrap();

    compare_registry_hashes(&short_metadata, &metadata_polkadot);
    compare_digests(&short_metadata, &metadata_polkadot, &specs_polkadot);

    let reply = parse_transaction_unmarked(
        &data.as_ref(),
        &mut (),
        &short_metadata,
        H256(
            hex::decode("91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3")
                .unwrap()
                .try_into()
                .unwrap(),
        ),
    )
    .unwrap()
    .card(
        &short_metadata.to_specs(),
        &<ShortMetadata as AsMetadata<()>>::spec_name_version(&short_metadata)
            .unwrap()
            .spec_name,
    );

    let call_printed = format!(
        "\n{}\n",
        reply
            .call
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let call_known = "
Pallet: XcmPallet
  Call: teleport_assets
    Field Name: dest
      Enum
        Enum Variant Name: V3
          Struct: 2 field(s)
            Field Name: parents
              u8: 149
            Field Name: interior
              Enum
                Enum Variant Name: X8
                  Field Number: 1
                    Enum
                      Enum Variant Name: Plurality
                        Field Name: id
                          Enum
                            Enum Variant Name: Technical
                        Field Name: part
                          Enum
                            Enum Variant Name: Members
                              Field Name: count
                                u32: 14
                  Field Number: 2
                    Enum
                      Enum Variant Name: Parachain
                        u32: 29
                  Field Number: 3
                    Enum
                      Enum Variant Name: GeneralKey
                        Field Name: length
                          u8: 61
                        Field Name: data
                          Sequence u8: 03aeada02cc26977d0ab68927e12516a3287a3c72cc937981d1e7c9ade0cf91f
                  Field Number: 4
                    Enum
                      Enum Variant Name: AccountKey20
                        Field Name: network
                          Option: None
                        Field Name: key
                          Sequence u8: eda947e425ea94b7642cc2d3939d30207e457a92
                  Field Number: 5
                    Enum
                      Enum Variant Name: PalletInstance
                        u8: 152
                  Field Number: 6
                    Enum
                      Enum Variant Name: PalletInstance
                        u8: 88
                  Field Number: 7
                    Enum
                      Enum Variant Name: Plurality
                        Field Name: id
                          Enum
                            Enum Variant Name: Technical
                        Field Name: part
                          Enum
                            Enum Variant Name: MoreThanProportion
                              Field Name: nom
                                u32: 15900563
                              Field Name: denom
                                u32: 11908
                  Field Number: 8
                    Enum
                      Enum Variant Name: GeneralIndex
                        u128: 37
    Field Name: beneficiary
      Enum
        Enum Variant Name: V2
          Struct: 2 field(s)
            Field Name: parents
              u8: 104
            Field Name: interior
              Enum
                Enum Variant Name: X8
                  Field Number: 1
                    Enum
                      Enum Variant Name: Parachain
                        u32: 3919
                  Field Number: 2
                    Enum
                      Enum Variant Name: Plurality
                        Field Name: id
                          Enum
                            Enum Variant Name: Defense
                        Field Name: part
                          Enum
                            Enum Variant Name: Members
                              Field Name: count
                                u32: 10347
                  Field Number: 3
                    Enum
                      Enum Variant Name: AccountIndex64
                        Field Name: network
                          Enum
                            Enum Variant Name: Named
                              Sequence u8: d1043985798860eb63723790bda41de487e0730251717471e9660ab0aa5a6a65
                        Field Name: index
                          u64: 14839
                  Field Number: 4
                    Enum
                      Enum Variant Name: Plurality
                        Field Name: id
                          Enum
                            Enum Variant Name: Defense
                        Field Name: part
                          Enum
                            Enum Variant Name: MoreThanProportion
                              Field Name: nom
                                u32: 11
                              Field Name: denom
                                u32: 10274176
                  Field Number: 5
                    Enum
                      Enum Variant Name: Plurality
                        Field Name: id
                          Enum
                            Enum Variant Name: Administration
                        Field Name: part
                          Enum
                            Enum Variant Name: MoreThanProportion
                              Field Name: nom
                                u32: 6183
                              Field Name: denom
                                u32: 587522514
                  Field Number: 6
                    Enum
                      Enum Variant Name: OnlyChild
                  Field Number: 7
                    Enum
                      Enum Variant Name: PalletInstance
                        u8: 170
                  Field Number: 8
                    Enum
                      Enum Variant Name: GeneralKey
                        Sequence u8: ab90ebe5eeaf95088767ace3e78d04147180b016cf193a542fe5c9a4291e70784f6d64fb705349e4a361c453b28d18ba43b8e0bee72dad92845acbe281f21ea6c270f553481dc183b60ca8c1803544f33691adef9c5d4f807827e288143f4af2aa1c2c0b9e6087db1decedb85e2774f792c9bbc61ed85f031d11d175f93ecf7d
    Field Name: assets
      Enum
        Enum Variant Name: V3
          Sequence: 2 element(s)
            Struct: 2 field(s)
              Field Name: id
                Enum
                  Enum Variant Name: Concrete
                    Struct: 2 field(s)
                      Field Name: parents
                        u8: 169
                      Field Name: interior
                        Enum
                          Enum Variant Name: X3
                            Field Number: 1
                              Enum
                                Enum Variant Name: OnlyChild
                            Field Number: 2
                              Enum
                                Enum Variant Name: AccountId32
                                  Field Name: network
                                    Enum
                                      Enum Variant Name: Ethereum
                                        Field Name: chain_id
                                          u64: 15093
                                  Field Name: id
                                    Sequence u8: d78dfce4bdb789c0e310e2172b3f3a13ec09e39ba8b644e368816bd7acd57f10
                            Field Number: 3
                              Enum
                                Enum Variant Name: AccountKey20
                                  Field Name: network
                                    Option: None
                                  Field Name: key
                                    Sequence u8: 25867d9fc900c0f7afe1ce1fc756f152b3f38e5a
              Field Name: fun
                Enum
                  Enum Variant Name: NonFungible
                    Enum
                      Enum Variant Name: Undefined
            Struct: 2 field(s)
              Field Name: id
                Enum
                  Enum Variant Name: Abstract
                    Sequence u8: dec102c8abb0449d91dd617be6a7dc4d7ea0ae7f7cebaf1c9e4c9f0a64716c3d
              Field Name: fun
                Enum
                  Enum Variant Name: Fungible
                    u128: 30
    Field Name: fee_asset_item
      u32: 0
";
    assert_eq!(call_known, call_printed);

    let extensions_printed = format!(
        "\n{}\n",
        reply
            .extensions
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let extensions_known = "
Era: Mortal, phase: 61, period: 64
Nonce: 100
Tip: 555.2342355555 DOT
Chain: polkadot9430
Tx Version: 24
Block Hash: 91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3
";
    assert_eq!(extensions_known, extensions_printed);
}

#[test]
fn short_metadata_5_decode() {
    let data = hex::decode("1f00001b7a61c73f450f4518731981d9cdd99013cfe044294617b74f93ba4bba6090d00b63ce64c10c05d5030403d202964942000000020000009eb76c5184c4ab8679d2d5d819fdf90b9c001403e9e17da2e14b6d8aec4029c69eb76c5184c4ab8679d2d5d819fdf90b9c001403e9e17da2e14b6d8aec4029c6").unwrap();

    let metadata_astar = metadata("for_tests/astar66");
    let specs_astar = specs_astar();

    let short_metadata =
        cut_metadata_transaction_unmarked(&data.as_ref(), &mut (), &metadata_astar, &specs_astar)
            .unwrap();

    compare_registry_hashes(&short_metadata, &metadata_astar);
    compare_digests(&short_metadata, &metadata_astar, &specs_astar);

    let reply = parse_transaction_unmarked(
        &data.as_ref(),
        &mut (),
        &short_metadata,
        H256(
            hex::decode("9eb76c5184c4ab8679d2d5d819fdf90b9c001403e9e17da2e14b6d8aec4029c6")
                .unwrap()
                .try_into()
                .unwrap(),
        ),
    )
    .unwrap()
    .card(
        &short_metadata.to_specs(),
        &<ShortMetadata as AsMetadata<()>>::spec_name_version(&short_metadata)
            .unwrap()
            .spec_name,
    );

    let call_printed = format!(
        "\n{}\n",
        reply
            .call
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let call_known = "
Pallet: Balances
  Call: transfer_allow_death
    Field Name: dest
      Enum
        Enum Variant Name: Id
          Id: WZKwYJmVxzxqF9UbaATqjyYY2859mZEfcTAQEDaXipQYG5w
    Field Name: value
      Balance: 5.552342355555 uASTR
";
    assert_eq!(call_known, call_printed);

    let extensions_printed = format!(
        "\n{}\n",
        reply
            .extensions
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let extensions_known = "
Era: Mortal, phase: 61, period: 64
Nonce: 1
Tip: 1.234567890 nASTR
Chain: astar66
Tx Version: 2
Block Hash: 9eb76c5184c4ab8679d2d5d819fdf90b9c001403e9e17da2e14b6d8aec4029c6
";
    assert_eq!(extensions_known, extensions_printed);
}

#[test]
fn short_metadata_6_decode() {
    let data = hex::decode("15000600a9569408db2bf9dd45318e13074b02ffce42dcf91b89cbef0fbe92191eb9627f019b02f1160003792192b533ff24d1ac92297d3905d02aac6dc63c10d62400001800000091b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c391b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3").unwrap();

    let metadata_polkadot = metadata("for_tests/polkadot9430");
    let specs_polkadot = specs_polkadot();

    let short_metadata = cut_metadata_transaction_unmarked(
        &data.as_ref(),
        &mut (),
        &metadata_polkadot,
        &specs_polkadot,
    )
    .unwrap();

    compare_registry_hashes(&short_metadata, &metadata_polkadot);
    compare_digests(&short_metadata, &metadata_polkadot, &specs_polkadot);

    println!("{short_metadata:?}");

    let reply = parse_transaction_unmarked(
        &data.as_ref(),
        &mut (),
        &short_metadata,
        H256(
            hex::decode("91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3")
                .unwrap()
                .try_into()
                .unwrap(),
        ),
    )
    .unwrap()
    .card(
        &short_metadata.to_specs(),
        &<ShortMetadata as AsMetadata<()>>::spec_name_version(&short_metadata)
            .unwrap()
            .spec_name,
    );

    let call_printed = format!(
        "\n{}\n",
        reply
            .call
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let call_known = "
Pallet: Referenda
  Call: submit
    Field Name: proposal_origin
      Enum
        Enum Variant Name: Void
          Enum With No Variants
    Field Name: proposal
      Enum
        Enum Variant Name: Legacy
          Field Name: hash
            H256: a9569408db2bf9dd45318e13074b02ffce42dcf91b89cbef0fbe92191eb9627f
    Field Name: enactment_moment
      Enum
        Enum Variant Name: After
          u32: 384893595
";
    assert_eq!(call_known, call_printed);

    let extensions_printed = format!(
        "\n{}\n",
        reply
            .extensions
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let extensions_known = "
Era: Immortal
Nonce: 3046252921
Tip: 2158321035032515.9632029318439228220671 TDOT
Chain: polkadot9430
Tx Version: 24
Block Hash: 91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3
";
    assert_eq!(extensions_known, extensions_printed);
}

#[test]
fn short_metadata_7_decode() {
    let data = hex::decode("0c000785720a647b9dbf43890b68e8b75b6832581f522fdea8e0c71662a6d19110a85e6c5b41a0cc1c39c26bbe080e79b823d7b34756c1d3df05ca8d1b6a6bac81c76aa268f92ccd919550fd8c6e8b9489f419aaebd697e43d3b0dffd0bb3355b59406322d0b39a7d7481762b339321a4819c955ace60098ca898ab5c4de1e796efd3214de768a4857b88dce6946c280aa643806ce9cc345548b9770dea758c8c974b116b2e142d947a6b2fe037df9ef0744ab4ea4341d68c3a2aeeafc1b295094725f3afbb1833f908cd16a7c8928bf4683f4e8a300034f82cea733248c934b7ee4aa706c1e1bd238ad3a37d62400001800000091b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c391b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3").unwrap();

    let metadata_polkadot = metadata("for_tests/polkadot9430");
    let specs_polkadot = specs_polkadot();

    let short_metadata = cut_metadata_transaction_unmarked(
        &data.as_ref(),
        &mut (),
        &metadata_polkadot,
        &specs_polkadot,
    )
    .unwrap();

    compare_registry_hashes(&short_metadata, &metadata_polkadot);
    compare_digests(&short_metadata, &metadata_polkadot, &specs_polkadot);

    let reply = parse_transaction_unmarked(
        &data.as_ref(),
        &mut (),
        &short_metadata,
        H256(
            hex::decode("91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3")
                .unwrap()
                .try_into()
                .unwrap(),
        ),
    )
    .unwrap()
    .card(
        &short_metadata.to_specs(),
        &<ShortMetadata as AsMetadata<()>>::spec_name_version(&short_metadata)
            .unwrap()
            .spec_name,
    );

    let call_printed = format!(
        "\n{}\n",
        reply
            .call
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let call_known = "
Pallet: ImOnline
  Call: heartbeat
    Field Name: heartbeat
      Struct: 5 field(s)
        Field Name: block_number
          u32: 175277319
        Field Name: network_state
          Struct: 2 field(s)
            Field Name: peer_id
              Sequence u8: 7b9dbf43890b68e8b75b6832581f522fdea8e0c71662a6d191
            Field Name: external_addresses
              Sequence: 4 element(s)
                Sequence u8: 5e6c5b41a0cc1c39c26bbe080e79b823d7b34756c1d3df05ca8d1b6a6bac81c76aa268f92ccd919550fd
                Sequence u8: 6e8b9489f419aaebd697e43d3b0dffd0bb3355b59406322d0b39a7d7481762b339321a
                Sequence u8: 19c955ace60098ca898ab5c4de1e796efd32
                Sequence u8: de768a4857
        Field Name: session_index
          u32: 1775144376
        Field Name: authority_index
          u32: 2860565062
        Field Name: validators_len
          u32: 3456514148
    Field Name: signature
      Signature Sr25519: 9cc345548b9770dea758c8c974b116b2e142d947a6b2fe037df9ef0744ab4ea4341d68c3a2aeeafc1b295094725f3afbb1833f908cd16a7c8928bf4683f4e8a3
";
    assert_eq!(call_known, call_printed);

    let extensions_printed = format!(
        "\n{}\n",
        reply
            .extensions
            .iter()
            .map(|card| card.show())
            .collect::<Vec<String>>()
            .join("\n")
    );
    let extensions_known = "
Era: Immortal
Nonce: 2815328847
Tip: 7341220634462856.2280923863194730204196 TDOT
Chain: polkadot9430
Tx Version: 24
Block Hash: 91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3
";
    assert_eq!(extensions_known, extensions_printed);
}
