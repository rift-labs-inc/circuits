use bitcoin::consensus::encode::deserialize;

use bitcoin::hashes::Hash;

use bitcoin::Block;

use crypto_bigint::U256;
use hex_literal::hex;

use rift_lib::lp::{compute_lp_hash, encode_liquidity_providers, LiquidityReservation};

use rift_lib::{validate_rift_transaction, CircuitInput, CircuitPublicValues};
use serde::Serialize;
use utils::transaction::{serialize_no_segwit, P2WPKHBitcoinWallet};
use utils::{
    generate_merkle_proof_and_root, get_retarget_height_from_block_height, load_hex_bytes,
    to_little_endian, to_rift_optimized_block,
};

use clap::Parser;
use sp1_sdk::{ProverClient, SP1Stdin};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const MAIN_ELF: &[u8] = include_bytes!("../../../elf/riscv32im-succinct-zkvm-elf");

fn get_test_case_circuit_input() -> CircuitInput {
    let order_nonce = hex!("f0ad57e677a89d2c2aaae4c5fd52ba20c63c0a05c916619277af96435f874c64");
    let lp_reservations: Vec<LiquidityReservation> = vec![
        LiquidityReservation {
            amount_reserved: U256::from_u64(99835000000000),
            btc_exchange_rate: 205000000000,
            script_pub_key: hex!("001463dff5f8da08ca226ba01f59722c62ad9b9b3eaa"),
        },
        LiquidityReservation {
            amount_reserved: U256::from_u64(99835000000000),
            btc_exchange_rate: 205000000000,
            script_pub_key: hex!("0014aa86191235be8883693452cf30daf854035b085b"),
        },
        LiquidityReservation {
            amount_reserved: U256::from_u64(99835000000000),
            btc_exchange_rate: 205000000000,
            script_pub_key: hex!("00146ab8f6c80b8a7dc1b90f7deb80e9b59ae16b7a5a"),
        },
    ];

    let lp_reservation_data_encoded = encode_liquidity_providers(&lp_reservations);

    let expected_payout: u64 = 299505000000000;
    // get current working dir
    let cwd = std::env::current_dir().unwrap();
    println!("Current working dir: {:?}", cwd);

    let mined_blocks = [
        deserialize::<Block>(&load_hex_bytes("tests/data/block_854373.hex")).unwrap(),
        deserialize::<Block>(&load_hex_bytes("tests/data/block_854374.hex")).unwrap(),
        deserialize::<Block>(&load_hex_bytes("tests/data/block_854375.hex")).unwrap(),
        deserialize::<Block>(&load_hex_bytes("tests/data/block_854376.hex")).unwrap(),
        deserialize::<Block>(&load_hex_bytes("tests/data/block_854377.hex")).unwrap(),
        deserialize::<Block>(&load_hex_bytes("tests/data/block_854378.hex")).unwrap(),
        deserialize::<Block>(&load_hex_bytes("tests/data/block_854379.hex")).unwrap(),
    ];

    let mined_block_height = 854374;
    let mined_block = deserialize::<Block>(&load_hex_bytes(
        format!("tests/data/block_{mined_block_height}.hex").as_str(),
    ))
    .unwrap();
    let mined_txid = hex!("fb7ea6c1a58f9e827c50aefb3117ce41dd5fecb969041864ec0eff9273b08038");
    let retarget_block_height = get_retarget_height_from_block_height(mined_block_height);
    let mined_retarget_block = deserialize::<Block>(&load_hex_bytes(
        format!("tests/data/block_{retarget_block_height}.hex").as_str(),
    ))
    .unwrap();

    // This is a real mainnet transaction so we don't need to build rift payment transaction

    let mined_transaction = mined_block
        .txdata
        .iter()
        .find(|tx| to_little_endian(tx.compute_txid().to_byte_array()) == mined_txid);

    assert!(
        mined_transaction.is_some(),
        "Mined transaction not found in the block"
    );
    let mined_transaction = mined_transaction.unwrap();
    let mined_transaction_serialized_no_segwit = serialize_no_segwit(&mined_transaction);

    let txn = to_little_endian(*mined_transaction.compute_txid().as_byte_array());

    let (merkle_proof, calculated_merkle_root) = generate_merkle_proof_and_root(
        mined_block
            .txdata
            .iter()
            .map(|tx| to_little_endian(*tx.compute_txid().as_raw_hash().as_byte_array()))
            .collect(),
        txn,
    );

    assert_eq!(
        calculated_merkle_root,
        to_little_endian(mined_block.compute_merkle_root().unwrap().to_byte_array()),
        "Invalid merkle root"
    );

    CircuitInput::new(
        CircuitPublicValues::new(
            to_little_endian(mined_transaction.compute_txid().to_byte_array()),
            to_little_endian(mined_block.header.merkle_root.to_byte_array()),
            compute_lp_hash(
                &lp_reservation_data_encoded.to_vec(),
                lp_reservations.len() as u32,
            ),
            order_nonce,
            expected_payout,
            lp_reservations.len() as u64,
            to_little_endian(mined_retarget_block.header.block_hash().to_byte_array()),
            mined_block_height - 1,
            1,
            5,
            retarget_block_height,
            mined_blocks
                .iter()
                .map(|block| to_little_endian(block.header.block_hash().to_byte_array()))
                .collect(),
        ),
        mined_transaction_serialized_no_segwit,
        merkle_proof,
        lp_reservation_data_encoded.to_vec(),
        mined_blocks
            .iter()
            .enumerate()
            .map(|(i, block)| to_rift_optimized_block(mined_block_height - 1 + i as u64, block))
            .collect(),
        to_rift_optimized_block(retarget_block_height, &mined_retarget_block),
    )
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    let circuit_input = get_test_case_circuit_input();

    println!("Circuit input generated successfully.");

    // Setup the prover client.
    let client = ProverClient::new();

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();

    // TODO: Update this to match the expected inputs of the program.
    stdin.write(&circuit_input);
    println!("Inputs serialized successfully.");

    /*
    // Execute the program
    let (output, report) = client.execute(MAIN_ELF, stdin).run().unwrap();
    println!("Program executed successfully.");

    // TODO: Decode the output, and verify it
    // Record the number of cycles executed.
    println!("Number of cycles: {}", report.total_instruction_count());
    */

    // Setup the program for proving.
    let (pk, vk) = client.setup(MAIN_ELF);

    // Generate the proof
    let proof = client
        .prove(&pk, stdin)
        .plonk()
        .run()
        .expect("failed to generate proof");

    println!("Successfully generated proof!");

    // Verify the proof.
    client.verify(&proof, &vk).expect("failed to verify proof");
    println!("Successfully verified proof!");
}
