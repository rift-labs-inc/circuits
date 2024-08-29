use bitcoin::consensus::encode::deserialize;

use bitcoin::hashes::Hash;

use bitcoin::Block;

use crypto_bigint::U256;

use rift_lib::lp::{compute_lp_hash, encode_liquidity_providers, LiquidityReservation};

use rift_lib::{validate_rift_transaction, CircuitInput, CircuitPublicValues};
use serde::Serialize;
use crate::transaction::{serialize_no_segwit, P2WPKHBitcoinWallet};
use crate::{
    generate_merkle_proof_and_root, get_retarget_height_from_block_height, load_hex_bytes,
    to_little_endian, to_rift_optimized_block,
};

use sp1_sdk::{ExecutionReport, ProverClient, SP1Stdin};

/// We can't assume that the ELF file will always be available at this location 
//pub const MAIN_ELF: &[u8] = include_bytes!("../../elf/riscv32im-succinct-zkvm-elf");

pub fn generate_plonk_proof(circuit_input: CircuitInput, program_elf: &[u8], verify: Option<bool>) -> String {
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
    let (output, report) = client.execute(program_elf, stdin).run().unwrap();
    report
}

