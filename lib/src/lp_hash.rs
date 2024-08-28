use sha2::{Sha256, Digest};
use crate::constants::MAX_LIQUIDITY_PROVIDERS;

fn build_hashable_chunk(lp_data: [[u8; 32]; 4], intermediate_vault_hash: [u8; 32]) -> [u8; 128] {
    let mut solidity_encoded_lp_data = [0u8; 128];
    
    // Copy the first 3 32-byte chunks directly
    solidity_encoded_lp_data[0..96].copy_from_slice(&lp_data[0..3].concat());
    
    // Copy the last 32-byte chunk
    solidity_encoded_lp_data[96..].copy_from_slice(&intermediate_vault_hash);
    
    solidity_encoded_lp_data
}

pub fn assert_lp_hash(
    lp_reservation_hash: [u8; 32],
    lp_reservation_data_encoded: [[[u8; 32]; 4]; MAX_LIQUIDITY_PROVIDERS],
    lp_count: u32
) {
    let mut intermediate_vault_hash = [0u8; 32];
    
    for lp_data in lp_reservation_data_encoded.iter().take(lp_count as usize) {
        let hashable_chunk = build_hashable_chunk(*lp_data, intermediate_vault_hash);
        intermediate_vault_hash = Sha256::digest(hashable_chunk).into();
    }
    
    assert_eq!(intermediate_vault_hash, lp_reservation_hash, "Invalid LP hash");
}
