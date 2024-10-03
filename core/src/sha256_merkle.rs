use crate::{btc_light_client::AsLittleEndianBytes, tx_hash::sha256_hash};
use serde::{Deserialize, Serialize};

#[derive(Default, Serialize, Deserialize, Clone, Copy, Debug)]
pub struct MerkleProofStep {
    pub hash: [u8; 32],
    pub direction: bool,
}

pub fn hash_pairs(hash_1: [u8; 32], hash_2: [u8; 32]) -> [u8; 32] {
    // [0] & [1] Combine hashes into one 64 byte array, reversing byte order
    let combined_hashes: [u8; 64] = hash_1
        .into_iter()
        .rev()
        .chain(hash_2.into_iter().rev())
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();

    // [2] Double sha256 combined hashes
    let new_hash_be = sha256_hash(&sha256_hash(&combined_hashes));

    // [3] Convert new hash to little-endian
    new_hash_be.to_little_endian()
}

pub fn assert_merkle_proof_equality(
    merkle_root: [u8; 32],
    proposed_txn_hash: [u8; 32],
    proposed_merkle_proof: &[MerkleProofStep],
) {
    let mut current_hash: [u8; 32] = proposed_txn_hash;

    let zero_hash = [0; 32];
    let mut count = 0;
    for i in 0..proposed_merkle_proof.len() {
        if proposed_merkle_proof[i].hash != zero_hash {
            let proof_step = proposed_merkle_proof[count];
            if proof_step.direction {
                current_hash = hash_pairs(current_hash, proof_step.hash);
            } else {
                current_hash = hash_pairs(proof_step.hash, current_hash);
            }
            count += 1;
        }
    }
    assert!(
        current_hash == merkle_root,
        "Merkle proof verification failed"
    );
}
