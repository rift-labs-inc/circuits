use crate::constants::MAX_LIQUIDITY_PROVIDERS;
use crypto_bigint::{Encoding, U256};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy)]
pub struct LiquidityReservation {
    pub amount_reserved: U256,
    pub btc_exchange_rate: u64,
    pub script_pub_key: [u8; 22],
}

pub fn build_hashable_chunk(
    lp_data: [[u8; 32]; 3],
    intermediate_vault_hash: [u8; 32],
) -> [u8; 128] {
    let mut solidity_encoded_lp_data = [0u8; 128];

    // Copy the first 3 32-byte chunks directly
    solidity_encoded_lp_data[0..96].copy_from_slice(&lp_data[0..3].concat());

    // Copy the last 32-byte chunk
    solidity_encoded_lp_data[96..].copy_from_slice(&intermediate_vault_hash);

    solidity_encoded_lp_data
}

pub fn decode_liqudity_providers(
    liquidity_providers_encoded: Vec<[[u8; 32]; 3]>,
) -> [LiquidityReservation; MAX_LIQUIDITY_PROVIDERS] {
    let mut liquidity_providers = [LiquidityReservation {
        amount_reserved: U256::ZERO,
        btc_exchange_rate: 0,
        script_pub_key: [0; 22],
    }; MAX_LIQUIDITY_PROVIDERS];

    for i in 0..MAX_LIQUIDITY_PROVIDERS {
        // Extract amount reserved
        liquidity_providers[i].amount_reserved =
            U256::from_be_slice(&liquidity_providers_encoded[i][0]);

        // Extract BTC exchange rate
        liquidity_providers[i].btc_exchange_rate = u64::from_be_bytes(
            liquidity_providers_encoded[i][1][32 - 8..]
                .try_into()
                .unwrap(),
        );

        // Extract script pub key
        liquidity_providers[i]
            .script_pub_key
            .copy_from_slice(&liquidity_providers_encoded[i][2][0..22]);
    }

    liquidity_providers
}

pub fn encode_liquidity_providers(
    liquidity_providers: &Vec<LiquidityReservation>,
) -> [[[u8; 32]; 3]; MAX_LIQUIDITY_PROVIDERS] {
    assert!(
        liquidity_providers.len() <= MAX_LIQUIDITY_PROVIDERS,
        "Too many liquidity providers"
    );
    let mut liquidity_providers_encoded = [[[0u8; 32]; 3]; MAX_LIQUIDITY_PROVIDERS];

    for i in 0..liquidity_providers.len() {
        // Encode amount reserved
        liquidity_providers_encoded[i][0] = liquidity_providers[i].amount_reserved.to_be_bytes();

        // Encode BTC exchange rate
        liquidity_providers_encoded[i][1][32 - 8..]
            .copy_from_slice(&liquidity_providers[i].btc_exchange_rate.to_be_bytes());

        // Encode script pub key
        liquidity_providers_encoded[i][2][0..22]
            .copy_from_slice(&liquidity_providers[i].script_pub_key);
    }

    for i in liquidity_providers.len()..MAX_LIQUIDITY_PROVIDERS {
        liquidity_providers_encoded[i] = [[0u8; 32]; 3];
    }

    liquidity_providers_encoded
}

pub fn compute_lp_hash(
    lp_reservation_data_encoded: &Vec<[[u8; 32]; 3]>,
    lp_count: u32,
) -> [u8; 32] {
    assert!(
        lp_reservation_data_encoded.len() <= MAX_LIQUIDITY_PROVIDERS,
        "Too many liquidity providers"
    );
    let mut intermediate_vault_hash = [0u8; 32];

    for lp_data in lp_reservation_data_encoded.iter().take(lp_count as usize) {
        let hashable_chunk = build_hashable_chunk(*lp_data, intermediate_vault_hash);
        intermediate_vault_hash = Sha256::digest(hashable_chunk).into();
    }

    intermediate_vault_hash
}

pub fn assert_lp_hash(
    lp_reservation_hash: [u8; 32],
    lp_reservation_data_encoded: &Vec<[[u8; 32]; 3]>,
    lp_count: u32,
) {
    assert!(
        lp_reservation_data_encoded.len() <= MAX_LIQUIDITY_PROVIDERS,
        "Too many liquidity providers"
    );
    assert_eq!(
        compute_lp_hash(lp_reservation_data_encoded, lp_count),
        lp_reservation_hash,
        "Invalid LP hash"
    );
}
