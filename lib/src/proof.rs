use bitcoin::hashes::Hash;

use bitcoin::Block;

use crypto_bigint::{Encoding, U256};

use rift_core::btc_light_client::AsLittleEndianBytes;
use rift_core::lp::{compute_lp_hash, encode_liquidity_providers, LiquidityReservation};

use crate::transaction::serialize_no_segwit;
use crate::{
    generate_merkle_proof_and_root, AsRiftOptimizedBlock,
};
use rift_core::{CircuitInput, CircuitPublicValues};

use sp1_sdk::{ExecutionReport, ProverClient, SP1Stdin};

pub fn build_proof_input(
    order_nonce: &[u8; 32],
    liquidity_reservations: &Vec<LiquidityReservation>,
    safe_chainwork: U256,
    blocks: &Vec<Block>,
    proposed_block_index: usize,
    proposed_txid: &[u8; 32],
    retarget_block: &Block,
) -> CircuitInput {
    let proposed_block = &blocks[proposed_block_index];
    let chainworks: Vec<_> = blocks
        .iter()
        .map(|block| block.as_rift_optimized_block())
        .scan(safe_chainwork, |chainwork_acc, block| {
            *chainwork_acc = block.compute_chainwork(*chainwork_acc);
            Some(*chainwork_acc)
        })
        .map(|chainwork| chainwork.to_be_bytes())
        .collect();

    let proposed_transaction = proposed_block
        .txdata
        .iter()
        .find(|tx| tx.compute_txid().to_byte_array().to_little_endian() == *proposed_txid);

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
            .map(|tx| {
                tx.compute_txid()
                    .as_raw_hash()
                    .as_byte_array()
                    .to_little_endian()
            })
            .collect(),
        *proposed_txid,
    );

    assert_eq!(
        calculated_merkle_root,
        proposed_block
            .compute_merkle_root()
            .unwrap()
            .to_byte_array()
            .to_little_endian(),
        "Invalid merkle root"
    );

    let lp_reservation_data_encoded = encode_liquidity_providers(&liquidity_reservations);

    let safe_block_height = blocks.first().unwrap().bip34_block_height().unwrap();

    CircuitInput::new(
        CircuitPublicValues::new(
            proposed_transaction
                .compute_txid()
                .to_byte_array()
                .to_little_endian(),
            proposed_block
                .header
                .merkle_root
                .to_byte_array()
                .to_little_endian(),
            compute_lp_hash(
                &lp_reservation_data_encoded.to_vec(),
                liquidity_reservations.len() as u32,
            ),
            *order_nonce,
            liquidity_reservations.len() as u64,
            retarget_block
                .header
                .block_hash()
                .to_byte_array()
                .to_little_endian(),
            safe_block_height as u64,
            proposed_block_index as u64,
            blocks.len() as u64 - 1 - proposed_block_index as u64,
            blocks
                .iter()
                .map(|block| block.header.block_hash().to_byte_array().to_little_endian())
                .collect(),
            chainworks,
        ),
        mined_transaction_serialized_no_segwit,
        merkle_proof,
        lp_reservation_data_encoded.to_vec(),
        blocks
            .iter()
            .map(|block| block.as_rift_optimized_block())
            .collect(),
        retarget_block.as_rift_optimized_block(),
    )
}

/// We can't assume that the ELF file will always be available at this location
//pub const MAIN_ELF: &[u8] = include_bytes!("../../elf/riscv32im-succinct-zkvm-elf");

pub fn generate_plonk_proof(
    circuit_input: CircuitInput,
    program_elf: &[u8],
    verify: Option<bool>,
) -> sp1_sdk::SP1ProofWithPublicValues {
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

    proof
}

pub fn execute(circuit_input: CircuitInput, program_elf: &[u8]) -> (String, ExecutionReport) {
    let client = ProverClient::new();
    let mut stdin = SP1Stdin::new();
    stdin.write(&circuit_input);
    let (public_values, report) = client.execute(program_elf, stdin).run().unwrap();
    (public_values.raw(), report)
}
