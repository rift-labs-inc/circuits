mod errors;
use errors::{BitcoinRpcError};
use bitcoincore_rpc_async::{Auth, Client, RpcApi};
use rift_lib::sha256_merkle::{MerkleProofStep, hash_pairs};
use std::fmt::Write;



pub fn generate_merkle_proof(txn_hashes: &[[u8; 32]], target_hash: &[u8; 32]) -> Vec<MerkleProofStep> {
    let mut proof = Vec::new();
    let mut current_level = txn_hashes.to_vec();
    let mut target_index = current_level.iter().position(|hash| hash == target_hash).unwrap();

    while current_level.len() > 1 {
        let mut new_level = Vec::new();
        let mut extended_level = current_level.clone();
        
        if extended_level.len() % 2 == 1 {
            extended_level.push(*extended_level.last().unwrap());
        }

        for i in (0..extended_level.len()).step_by(2) {
            let left = extended_level[i];
            let right = extended_level[i + 1];

            if i <= target_index && target_index < i + 2 {
                if target_index == i {
                    proof.push(MerkleProofStep {
                        hash: right,
                        direction: true, // right
                    });
                } else {
                    proof.push(MerkleProofStep {
                        hash: left,
                        direction: false, // left
                    });
                }
                target_index = new_level.len();
            }
            new_level.push(hash_pairs(left, right));
        }

        current_level = new_level;
        target_index /= 2;
    }

    proof
}

pub fn flip_endianness<const N: usize>(input: [u8; N]) -> [u8; N] {
    let mut output = [0; N];
    for (i, &byte) in input.iter().enumerate() {
        output[N - 1 - i] = byte;
    }
    output
}

pub fn to_hex_string(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}
