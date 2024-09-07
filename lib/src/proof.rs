use bitcoin::hashes::Hash;

use bitcoin::Block;

use crypto_bigint::U256;

use rift_core::lp::{compute_lp_hash, encode_liquidity_providers, LiquidityReservation};

use crate::transaction::serialize_no_segwit;
use crate::{
    generate_merkle_proof_and_root, get_retarget_height_from_block_height,
    to_little_endian, to_rift_optimized_block,
};
use rift_core::{CircuitInput, CircuitPublicValues};

use sp1_sdk::{ExecutionReport, ProverClient, SP1Stdin};

pub fn build_proof_input(
    order_nonce: &[u8; 32],
    liquidity_reservations: &Vec<LiquidityReservation>,
    blocks: &Vec<Block>,
    proposed_block_index: usize,
    proposed_txid: &[u8; 32],
    retarget_block: &Block,
) -> CircuitInput {
    let proposed_block = &blocks[proposed_block_index];

    let proposed_transaction = proposed_block
        .txdata
        .iter()
        .find(|tx| to_little_endian(tx.compute_txid().to_byte_array()) == *proposed_txid);

    assert!(
        proposed_transaction.is_some(),
        "Mined transaction not found in the block"
    );
    let proposed_transaction = proposed_transaction.unwrap();
    let mined_transaction_serialized_no_segwit = serialize_no_segwit(&proposed_transaction);

    let (merkle_proof, calculated_merkle_root) = generate_merkle_proof_and_root(
        proposed_block
            .txdata
            .iter()
            .map(|tx| to_little_endian(*tx.compute_txid().as_raw_hash().as_byte_array()))
            .collect(),
        *proposed_txid,
    );

    assert_eq!(
        calculated_merkle_root,
        to_little_endian(
            proposed_block
                .compute_merkle_root()
                .unwrap()
                .to_byte_array()
        ),
        "Invalid merkle root"
    );

    let lp_reservation_data_encoded = encode_liquidity_providers(&liquidity_reservations);

    let mut expected_payout = U256::from_u8(0);
    for lp in liquidity_reservations {
        expected_payout = expected_payout.saturating_add(&lp.amount_reserved);
    }

    let safe_block_height = blocks.first().unwrap().bip34_block_height().unwrap();
    let retarget_block_height = get_retarget_height_from_block_height(safe_block_height as u64);

    CircuitInput::new(
        CircuitPublicValues::new(
            to_little_endian(proposed_transaction.compute_txid().to_byte_array()),
            to_little_endian(proposed_block.header.merkle_root.to_byte_array()),
            compute_lp_hash(
                &lp_reservation_data_encoded.to_vec(),
                liquidity_reservations.len() as u32,
            ),
            *order_nonce,
            expected_payout,
            liquidity_reservations.len() as u64,
            /*
             *lp_count: u64,
            retarget_block_hash: [u8; 32],
            safe_block_height: u64,
            safe_block_height_delta: u64,
            confirmation_block_height_delta: u64,
            retarget_block_height: u64,

             */
            to_little_endian(retarget_block.header.block_hash().to_byte_array()),
            safe_block_height as u64,
            proposed_block_index as u64,
            blocks.len() as u64 - 1 - proposed_block_index as u64,
            retarget_block_height,
            blocks
                .iter()
                .map(|block| to_little_endian(block.header.block_hash().to_byte_array()))
                .collect(),
        ),
        mined_transaction_serialized_no_segwit,
        merkle_proof,
        lp_reservation_data_encoded.to_vec(),
        blocks
            .iter()
            .enumerate()
            .map(|(i, block)| to_rift_optimized_block(safe_block_height + i as u64, block))
            .collect(),
        to_rift_optimized_block(retarget_block_height, &retarget_block),
    )
}

/// We can't assume that the ELF file will always be available at this location
//pub const MAIN_ELF: &[u8] = include_bytes!("../../elf/riscv32im-succinct-zkvm-elf");

pub fn generate_plonk_proof(
    circuit_input: CircuitInput,
    program_elf: &[u8],
    verify: Option<bool>,
) -> String {
    sp1_sdk::utils::setup_logger();
    // Setup the prover client.
    let client = ProverClient::new();
    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    stdin.write(&circuit_input);
    // Setup the program for proving.
    let (pk, vk) = client.setup(program_elf);
    // Generate the proof
    let proof = client
        .prove(&pk, stdin)
        .plonk()
        .run()
        .expect("failed to generate proof");

    // Verify the proof.
    if verify.unwrap_or(true) {
        client.verify(&proof, &vk).expect("failed to verify proof");
    }

    proof.raw()
}

pub fn execute(circuit_input: CircuitInput, program_elf: &[u8]) -> ExecutionReport {
    sp1_sdk::utils::setup_logger();
    let client = ProverClient::new();
    let mut stdin = SP1Stdin::new();
    stdin.write(&circuit_input);
    let (_, report) = client.execute(program_elf, stdin).run().unwrap();
    report
}
