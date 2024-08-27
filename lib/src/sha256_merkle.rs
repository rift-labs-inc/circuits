use crate::tx_hash::sha256_hash;
use serde::{Deserialize, Serialize};

#[derive(Default, Serialize, Deserialize, Clone, Copy)]
pub struct MerkleProofStep {
    pub hash: [u8; 32],
    pub direction: bool,
}



pub fn hash_pairs(hash_1: [u8; 32], hash_2: [u8; 32]) -> [u8; 32] {
    // [0] convert hashes to little-endian
    let mut hash1: [u8; 32] = [0; 32];
    let mut hash2: [u8; 32] = [0; 32];
    for i in 0..32 {
        hash1[i] = hash_1[31 - i] as u8;
        hash2[i] = hash_2[31 - i] as u8;
    }

    // [1] combine hashes into one 64 byte array
    let mut combined_hashes: [u8; 64] = [0; 64];
    for i in 0..32 {
        combined_hashes[i] = hash1[i];
        combined_hashes[i+32] = hash2[i];
    }

    // [2] double sha256 combined hashes
    let first_hash = sha256_hash(combined_hashes.as_slice());
    let new_hash_be = sha256_hash(first_hash.as_slice());

    // [3] convert new hash to little-endian
    let mut new_hash: [u8; 32] = [0; 32];
    for i in 0..32 {
        new_hash[i] = new_hash_be[31 - i] as u8;
    }

    new_hash
}

pub fn assert_merkle_proof_equality(
    merkle_root: [u8; 32],
    proposed_txn_hash: [u8; 32],
    proposed_merkle_proof: [MerkleProofStep; 20],
) {
    let mut current_hash: [u8;32] = [0; 32];
    for i in 0..32 {
        current_hash[i] = proposed_txn_hash[31 - i];
    }

    let zero_hash = [0; 32];
    let mut count = 0;
    for i in 0..20 {
        if proposed_merkle_proof[i].hash != zero_hash {
            let proof_step = proposed_merkle_proof[count];
            if proof_step.direction == true {
                current_hash = hash_pairs(current_hash, proof_step.hash);
            } else {
                current_hash = hash_pairs(proof_step.hash, current_hash);
            }
            count += 1;
        }
    }
	assert!(current_hash == merkle_root, "Merkle proof verification failed");
}

pub fn generate_merkle_proof_and_root(leaves: Vec<[u8; 32]>, desired_leaf: [u8; 32]) -> (Vec<MerkleProofStep>, [u8; 32]) {
    let mut current_level = leaves;
    let mut proof: Vec<MerkleProofStep> = Vec::new();
    let mut desired_index = current_level.iter().position(|&leaf| leaf == desired_leaf)
        .expect("Desired leaf not found in the list of leaves");

    while current_level.len() > 1 {
        let mut next_level = Vec::new();
        let mut i = 0;

        while i < current_level.len() {
            let left = current_level[i];
            let right = if i + 1 < current_level.len() {
                current_level[i + 1]
            } else {
                left
            };

            let parent_hash = hash_pairs(left, right);
            next_level.push(parent_hash);

            if i == desired_index || i + 1 == desired_index {
                let proof_step = if i == desired_index {
                    MerkleProofStep {
                        hash: right,
                        direction: true,
                    }
                } else {
                    MerkleProofStep {
                        hash: left,
                        direction: false,
                    }
                };
                proof.push(proof_step);
                desired_index /= 2;
            }

            i += 2;
        }

        current_level = next_level;
    }

    let merkle_root = current_level[0];
    (proof, merkle_root)
}
