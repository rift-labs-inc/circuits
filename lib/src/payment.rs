use std::ops::Div;

use crypto_bigint::{ArrayEncoding, NonZero, Zero, U256, CheckedMul, CheckedAdd};

use crate::constants::MAX_LIQUIDITY_PROVIDERS;

// Constants
const MAX_SCRIPTSIG_SIZE: u64 = 22;
const MAX_INPUT_COUNT: u64 = 1;
const MAX_SCRIPT_INSCRPITION_SIZE: u64 = 80;
const VERSION_LEN: u8 = 4;
const TXID_LEN: u8 = 32;
const VOUT_LEN: u8 = 4;
const SEQUENCE_LEN: u8 = 4;
const AMOUNT_LEN: u8 = 8;
const OP_RETURN_CODE: u8 = 0x6a;
const OP_PUSHBYTES_32: u8 = 0x20;
const DATA_LEN: u8 = 80;

// Structs
struct TxOut {
    value: u64,
    txout_script_length: u8,
    txout_script: [u8; MAX_SCRIPTSIG_SIZE as usize],
}

#[derive(Debug, Clone, Copy)]
pub struct LiquidityReservation {
    pub amount_reserved: U256,
    pub btc_exchange_rate: u64,
    pub script_pub_key: [u8; 22],
}

// Helper functions
fn to_int<const N: usize>(bytes: [u8; N]) -> u64 {
    bytes.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64)
}

pub fn compint_to_u64<const N: usize>(compact_bytes: [u8; N]) -> u64 {
    let start_byte = compact_bytes[0];
    match start_byte {
        0xFD => to_int(grab_bytes_le::<2>(&compact_bytes[1..])),
        0xFE => to_int(grab_bytes_le::<4>(&compact_bytes[1..])),
        0xFF => to_int(grab_bytes_le::<8>(&compact_bytes[1..])),
        _ => start_byte as u64,
    }
}

fn compint_start_to_byte_len(start_byte: u8) -> u8 {
    match start_byte {
        0xFD => 3,
        0xFE => 5,
        0xFF => 9,
        _ => 1,
    }
}

fn extract_int_from_compint_pointer(data_pointer: u64, txn_data: &[u8]) -> (u64, u8) {
    let counter_byte_len = compint_start_to_byte_len(txn_data[data_pointer as usize]);
    let counter = compint_to_u64(grab_bytes_be_conditional::<9>(
        txn_data,
        data_pointer,
        |i| i < counter_byte_len as u64,
    ));
    (counter, counter_byte_len)
}

fn decode_liqudity_providers(
    liquidity_providers_encoded: [[[u8; 32]; 3]; MAX_LIQUIDITY_PROVIDERS],
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
        liquidity_providers[i].btc_exchange_rate =
            u64::from_be_bytes(liquidity_providers_encoded[i][1][0..8].try_into().unwrap());

        // Extract script pub key
        liquidity_providers[i]
            .script_pub_key
            .copy_from_slice(&liquidity_providers_encoded[i][2][0..22]);
    }

    liquidity_providers
}

fn assert_payment_utxos_exist(
    txn_data: &[u8],
    reserved_liquidity_providers: &[LiquidityReservation; MAX_LIQUIDITY_PROVIDERS],
    lp_count: u64,
    order_nonce: [u8; 32],
    expected_payout: u64,
) {
    let mut data_pointer = 4;
    let (input_counter, input_counter_byte_len) =
        extract_int_from_compint_pointer(data_pointer, txn_data);
    data_pointer += input_counter_byte_len as u64;
    println!("Input Counter: {}", input_counter);
    assert_eq!(input_counter, MAX_INPUT_COUNT);

    // Skip inputs
    for _ in 0..MAX_INPUT_COUNT {
        data_pointer += (TXID_LEN + VOUT_LEN) as u64;
        let (sig_counter, sig_counter_byte_len) =
            extract_int_from_compint_pointer(data_pointer, txn_data);
        data_pointer += sig_counter as u64 + sig_counter_byte_len as u64 + SEQUENCE_LEN as u64;
    }

    let (output_counter, output_counter_byte_len) =
        extract_int_from_compint_pointer(data_pointer, txn_data);
    assert!(output_counter <= MAX_LIQUIDITY_PROVIDERS as u64);
    assert!(lp_count + 1 <= output_counter);
    data_pointer += output_counter_byte_len as u64;

    let mut calculated_payout: U256 = U256::ZERO;

    for i in 0..MAX_LIQUIDITY_PROVIDERS {
        if i < lp_count as usize {
            let value = U256::from_u64(to_int::<8>(grab_bytes_le::<8>(
                &txn_data[data_pointer as usize..],
            )));
            data_pointer += AMOUNT_LEN as u64;
            let (sig_counter, sig_counter_byte_len) =
                extract_int_from_compint_pointer(data_pointer, txn_data);
            data_pointer += sig_counter_byte_len as u64;

            assert_eq!(sig_counter, 22);

            let locking_script =
                grab_bytes_be_conditional::<22>(txn_data, data_pointer, |i| i < sig_counter as u64);

            // value here is always in sats which has word size of 64 bits
            let exchange_rate = NonZero::new(U256::from_u64(
                reserved_liquidity_providers[i].btc_exchange_rate,
            ))
            .unwrap();

            let amount_reserved =
                NonZero::new(reserved_liquidity_providers[i].amount_reserved).unwrap();

            assert_eq!(value, amount_reserved.div(exchange_rate));

            assert_eq!(
                locking_script,
                reserved_liquidity_providers[i].script_pub_key
            );

            let product = value
                .checked_mul(&U256::from_u64(
                    reserved_liquidity_providers[i].btc_exchange_rate,
                ))
                .unwrap();

            calculated_payout = calculated_payout.checked_add(&product).unwrap();
            data_pointer += sig_counter;
        }
    }

    assert_eq!(calculated_payout, U256::from_u64(expected_payout));

    data_pointer += AMOUNT_LEN as u64;
    let (sig_counter, sig_counter_byte_len) =
        extract_int_from_compint_pointer(data_pointer, txn_data);
    data_pointer += sig_counter_byte_len as u64;
    println!("sig_counter: {}", sig_counter);

    assert_eq!(sig_counter, 34);

    assert_eq!(txn_data[data_pointer as usize], OP_RETURN_CODE);
    data_pointer += 1;
    assert_eq!(txn_data[data_pointer as usize], OP_PUSHBYTES_32);
    data_pointer += 1;

    let inscribed_order_nonce =
        grab_bytes_be_conditional::<32>(txn_data, data_pointer, |i| i < sig_counter as u64);
    assert_eq!(inscribed_order_nonce, order_nonce);
}

pub fn assert_bitcoin_payment(
    txn_data_no_segwit: &[u8],
    lp_reservation_data_encoded: [[[u8; 32]; 3]; MAX_LIQUIDITY_PROVIDERS],
    order_nonce: [u8; 32],
    expected_payout: u64,
    lp_count: u64,
) {
    let liquidity_providers = decode_liqudity_providers(lp_reservation_data_encoded);
    assert_payment_utxos_exist(
        txn_data_no_segwit,
        &liquidity_providers,
        lp_count,
        order_nonce,
        expected_payout,
    );
}

// Helper functions (placeholders, implement as needed)
fn grab_bytes_le<const N: usize>(data: &[u8]) -> [u8; N] {
    let mut result = [0u8; N];
    result.copy_from_slice(&data[..N]);
    result.reverse();
    result
}

fn grab_bytes_be_conditional<const N: usize>(
    data: &[u8],
    start: u64,
    condition: impl Fn(u64) -> bool,
) -> [u8; N] {
    let mut result = [0u8; N];
    for i in 0..N {
        if condition(i as u64) {
            result[i] = data[start as usize + i];
        }
    }
    result
}

fn decode_field_encoded_hash(encoded: [[u8; 32]; 2]) -> [u8; 32] {
    let mut result = [0u8; 32];
    result.copy_from_slice(&encoded[0]);
    result
}
