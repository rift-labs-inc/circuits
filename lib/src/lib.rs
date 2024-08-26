pub mod constants;
pub mod tx_hash;
pub mod sha256_merkle;

use alloy_sol_types::sol;
use constants::MAX_BLOCKS;
use crypto_bigint::U256;
use serde::{Serialize, Deserialize};

#[derive(Default, Serialize, Deserialize, Clone)]
pub struct CircuitPublicValues {
    pub natural_txid: [u8; 32],
    pub merkle_root: [u8; 32],
    pub lp_reservation_hash: [u8; 32],
    pub order_nonce: [u8; 32],
    pub expected_payout: [u8; 32], // this needs to be decoded in the program as a U256, this gets
                                   // around having to serde a U256
    pub lp_count: u64,
    pub retarget_block_hash: [u8; 32],
    pub safe_block_height: u64,
    pub safe_block_height_delta: u64,
    pub confirmation_block_height_delta: u64,
    pub retarget_block_height: u64,
    pub block_hashes: [[u8; 32]; MAX_BLOCKS],
}

#[derive(Default, Serialize, Deserialize)]
pub struct CircuitInput {
    #[serde(flatten)]
    pub public_values: CircuitPublicValues,
    pub txn_data_no_segwit: Vec<u8>,
    pub merkle_proof: Vec<u8>,
    pub lp_reservation_data: [[u8; 32]; 4],
}


sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct SolidityPublicValues {
        bytes32 natural_txid;
        bytes32 merkle_root;
        bytes32 lp_reservation_hash;
        bytes32 order_nonce;
        uint256 expected_payout;
        uint64 lp_count;
        bytes32 retarget_block_hash;
        uint64 safe_block_height;
        uint64 safe_block_height_delta;
        uint64 confirmation_block_height_delta;
        uint64 retarget_block_height;
        bytes32[] block_hashes;
    }
}

pub fn validate_rift_transaction(
    circuit_input: CircuitInput,
) -> CircuitPublicValues {
    // Transaction Hash Verification
    assert_eq!(
        tx_hash::get_natural_txid(&circuit_input.txn_data_no_segwit),
        circuit_input.public_values.natural_txid,
        "Invalid transaction hash"
    );
    
    // Transaction Inclusion Verification
    /*
    sha256_merkle::assert_merkle_proof_equality(
        
        circuit_input.public_values.merkle_root,
        circuit_input.public_values.natural_txid,
        circuit_input.merkle_proof, 
    );
    */

    // Payment Verification + Lp Hash Verification


    circuit_input.public_values
}

/*
   // Transaction Hash Verification
   txn_hash_encoded: pub [Field; 2],
   intermediate_hash_encoded_and_txn_data: [Field; constants::MAX_ENCODED_CHUNKS + 2],
   // Transaction Inclusion Verification
   proposed_merkle_root_encoded: [Field; 2],
   proposed_merkle_proof: [sha256_merkle::MerkleProofStep; 20],
   // Payment Verification + Lp Hash Verification
   lp_reservation_hash_encoded: pub [Field; 2],
   order_nonce_encoded: pub [Field; 2],
   expected_payout: pub u64,
   lp_count: pub u64,
   lp_reservation_data_flat_encoded: [Field; constants::MAX_LIQUIDITY_PROVIDERS*4],
   // Block Verification
   retarget_block_hash_encoded: pub [Field; 2],
   safe_block_height: pub u64,
   safe_block_height_delta: pub u64,
   confirmation_block_height_delta: pub u64,
   retarget_block_height: pub u64,
   block_hashes_encoded: pub [Field; MAX_BLOCK_HASHES*2],
*/

/// Compute the n'th fibonacci number (wrapping around on overflows), using normal Rust code.
pub fn fibonacci(n: u32) -> (u32, u32) {
    let mut a = 0u32;
    let mut b = 1u32;
    for _ in 0..n {
        let c = a.wrapping_add(b);
        a = b;
        b = c;
    }
    (a, b)
}
