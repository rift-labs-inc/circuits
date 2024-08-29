pub mod btc_light_client;
pub mod constants;
pub mod sha256_merkle;
pub mod tx_hash;
pub mod lp;
pub mod payment;

use alloy_sol_types::sol;
use constants::{MAX_BLOCKS, MAX_LIQUIDITY_PROVIDERS};
use crypto_bigint::U256;
use serde::{Deserialize, Serialize};
use sha256_merkle::MerkleProofStep;

#[derive(Default, Serialize, Deserialize, Clone)]
pub struct CircuitPublicValues {
    pub natural_txid: [u8; 32],
    pub merkle_root: [u8; 32],
    pub lp_reservation_hash: [u8; 32],
    pub order_nonce: [u8; 32],
    pub expected_payout: u64, 
    pub lp_count: u64,
    pub retarget_block_hash: [u8; 32],
    pub safe_block_height: u64,
    pub safe_block_height_delta: u64,
    pub confirmation_block_height_delta: u64,
    pub retarget_block_height: u64,
    pub block_hashes: [[u8; 32]; MAX_BLOCKS],
}

impl CircuitPublicValues {
    pub fn new(
        natural_txid: [u8; 32],
        merkle_root: [u8; 32],
        lp_reservation_hash: [u8; 32],
        order_nonce: [u8; 32],
        expected_payout: u64,
        lp_count: u64,
        retarget_block_hash: [u8; 32],
        safe_block_height: u64,
        safe_block_height_delta: u64,
        confirmation_block_height_delta: u64,
        retarget_block_height: u64,
        block_hashes: Vec<[u8; 32]>,
    ) -> Self {
        let mut padded_block_hashes = [[0u8; 32]; MAX_BLOCKS];
        for (i, block_hash) in block_hashes.iter().enumerate() {
            padded_block_hashes[i] = *block_hash;
        }
        
        Self {
            natural_txid,
            merkle_root,
            lp_reservation_hash,
            order_nonce,
            expected_payout,
            lp_count,
            retarget_block_hash,
            safe_block_height,
            safe_block_height_delta,
            confirmation_block_height_delta,
            retarget_block_height,
            block_hashes: padded_block_hashes
        }
    }
}

#[derive(Default, Serialize, Deserialize)]
pub struct CircuitInput {
    #[serde(flatten)]
    pub public_values: CircuitPublicValues,
    pub txn_data_no_segwit: Vec<u8>,
    pub merkle_proof: Vec<MerkleProofStep>,
    pub lp_reservation_data: Vec<[[u8; 32]; 3]>,
    pub blocks: Vec<btc_light_client::Block>,
    pub retarget_block: btc_light_client::Block,
}

impl CircuitInput {
    pub fn new(
        public_values: CircuitPublicValues,
        txn_data_no_segwit: Vec<u8>,
        merkle_proof: Vec<MerkleProofStep>,
        lp_reservation_data: Vec<[[u8; 32]; 3]>,
        blocks: Vec<btc_light_client::Block>,
        retarget_block: btc_light_client::Block,
    ) -> Self {
        Self {
            public_values,
            txn_data_no_segwit,
            merkle_proof,
            lp_reservation_data,
            blocks,
            retarget_block,
        }
}
}

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct SolidityPublicValues {
        bytes32 natural_txid;
        bytes32 merkle_root;
        bytes32 lp_reservation_hash;
        bytes32 order_nonce;
        uint64 expected_payout;
        uint64 lp_count;
        bytes32 retarget_block_hash;
        uint64 safe_block_height;
        uint64 safe_block_height_delta;
        uint64 confirmation_block_height_delta;
        uint64 retarget_block_height;
        bytes32[] block_hashes;
    }
}

pub fn validate_rift_transaction(circuit_input: CircuitInput) -> CircuitPublicValues {

    // Block Verification
    btc_light_client::assert_blockchain(
        circuit_input.public_values.block_hashes
            [0..(circuit_input.public_values.safe_block_height_delta as usize)]
            .to_vec(),
        circuit_input.public_values.safe_block_height,
        circuit_input.public_values.retarget_block_hash,
        circuit_input.public_values.retarget_block_height,
        circuit_input.blocks,
        circuit_input.retarget_block,
    );

    // Transaction Hash Verification
    assert_eq!(
        tx_hash::get_natural_txid(&circuit_input.txn_data_no_segwit),
        circuit_input.public_values.natural_txid,
        "Invalid transaction hash"
    );

    // Transaction Inclusion Verification
    sha256_merkle::assert_merkle_proof_equality(
        circuit_input.public_values.merkle_root,
        circuit_input.public_values.natural_txid,
        circuit_input.merkle_proof.as_slice(),
    );

    // LP Hash Verification
    lp::assert_lp_hash(
        circuit_input.public_values.lp_reservation_hash,
        &circuit_input.lp_reservation_data,
        circuit_input.lp_reservation_data.len() as u32
    );

    // Payment Verification 
    payment::assert_bitcoin_payment(
        &circuit_input.txn_data_no_segwit,
        circuit_input.lp_reservation_data,
        circuit_input.public_values.order_nonce,
        circuit_input.public_values.expected_payout,
        circuit_input.public_values.lp_count,
    );

    circuit_input.public_values
}
