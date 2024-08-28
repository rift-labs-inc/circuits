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
struct RiftLiquidityReservation {
    amount_reserved: u64,
    btc_exchange_rate: u64,
    script_pub_key: [u8; 22],
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
    liquidity_providers_encoded: [[u8; 32]; MAX_LIQUIDITY_PROVIDERS],
) -> [RiftLiquidityReservation; MAX_LIQUIDITY_PROVIDERS] {
    let mut liquidity_providers = [RiftLiquidityReservation {
        amount_reserved: 0,
        btc_exchange_rate: 0,
        script_pub_key: [0; 22],
    }; MAX_LIQUIDITY_PROVIDERS];

    for i in 0..MAX_LIQUIDITY_PROVIDERS {
        let slot0: [u8; 31] = liquidity_providers_encoded[i][..31].try_into().unwrap();
        let slot1: [u8; 31] = liquidity_providers_encoded[i][32..63].try_into().unwrap();
        let slot2: [u8; 31] = liquidity_providers_encoded[i][64..95].try_into().unwrap();

        // Extract amount reserved
        let mut value_bytes = [0u8; 8];
        value_bytes.copy_from_slice(&slot0[24..]);
        value_bytes[7] = slot1[0];
        liquidity_providers[i].amount_reserved = u64::from_be_bytes(value_bytes);

        // Extract BTC exchange rate
        let mut btc_exchange_rate_bytes = [0u8; 8];
        btc_exchange_rate_bytes[..7].copy_from_slice(&slot1[25..]);
        btc_exchange_rate_bytes[6..].copy_from_slice(&slot2[..2]);
        liquidity_providers[i].btc_exchange_rate = u64::from_be_bytes(btc_exchange_rate_bytes);

        // Extract script pub key
        liquidity_providers[i].script_pub_key.copy_from_slice(&slot2[2..24]);
    }

    liquidity_providers
}

fn assert_payment_utxos_exist(
    txn_data: &[u8],
    reserved_liquidity_providers: &[RiftLiquidityReservation; MAX_LIQUIDITY_PROVIDERS],
    lp_count: u64,
    order_nonce: [u8; 32],
    expected_payout: u64,
) {
    let mut data_pointer = 4;
    let (input_counter, input_counter_byte_len) = extract_int_from_compint_pointer(data_pointer, txn_data);
    data_pointer += input_counter_byte_len as u64;
    println!("Input Counter: {}", input_counter);
    assert_eq!(input_counter, MAX_INPUT_COUNT);

    // Skip inputs
    for _ in 0..MAX_INPUT_COUNT {
        data_pointer += (TXID_LEN + VOUT_LEN) as u64;
        let (sig_counter, sig_counter_byte_len) = extract_int_from_compint_pointer(data_pointer, txn_data);
        data_pointer += sig_counter as u64 + sig_counter_byte_len as u64 + SEQUENCE_LEN as u64;
    }

    let (output_counter, output_counter_byte_len) = extract_int_from_compint_pointer(data_pointer, txn_data);
    assert!(output_counter <= MAX_LIQUIDITY_PROVIDERS as u64);
    assert!(lp_count + 1 <= output_counter);
    data_pointer += output_counter_byte_len as u64;

    let mut calculated_payout: u128 = 0;

    for i in 0..MAX_LIQUIDITY_PROVIDERS {
        if i < lp_count as usize {
            let value = to_int::<8>(grab_bytes_le::<8>(&txn_data[data_pointer as usize..]));
            data_pointer += AMOUNT_LEN as u64;
            let (sig_counter, sig_counter_byte_len) = extract_int_from_compint_pointer(data_pointer, txn_data);
            data_pointer += sig_counter_byte_len as u64;

            assert_eq!(sig_counter, 22);

            let locking_script = grab_bytes_be_conditional::<22>(
                txn_data,
                data_pointer,
                |i| i < sig_counter as u64,
            );

            assert_eq!(value, reserved_liquidity_providers[i].amount_reserved / reserved_liquidity_providers[i].btc_exchange_rate);
            assert_eq!(locking_script, reserved_liquidity_providers[i].script_pub_key);
            calculated_payout += (value as u128) * (reserved_liquidity_providers[i].btc_exchange_rate as u128);

            data_pointer += sig_counter;
        }
    }

    assert_eq!(calculated_payout, expected_payout as u128);

    data_pointer += AMOUNT_LEN as u64;
    let (sig_counter, sig_counter_byte_len) = extract_int_from_compint_pointer(data_pointer, txn_data);
    data_pointer += sig_counter_byte_len as u64;
    println!("sig_counter: {}", sig_counter);

    assert_eq!(sig_counter, 34);

    assert_eq!(txn_data[data_pointer as usize], OP_RETURN_CODE);
    data_pointer += 1;
    assert_eq!(txn_data[data_pointer as usize], OP_PUSHBYTES_32);
    data_pointer += 1;

    let inscribed_order_nonce = grab_bytes_be_conditional::<32>(
        txn_data,
        data_pointer,
        |i| i < sig_counter as u64,
    );
    assert_eq!(inscribed_order_nonce, order_nonce);
}

fn assert_txn_data_is_equal(txn_data_encoded: [[u8; 32]; MAX_ENCODED_CHUNKS], txn_data: &[u8]) {
    for (i, chunk) in txn_data_encoded.iter().enumerate() {
        for (j, &byte) in chunk[..31].iter().enumerate() {
            assert_eq!(txn_data[i * 31 + j], byte);
        }
    }
}

fn assert_bitcoin_payment(
    txn_data_no_segwit: &[u8],
    lp_reservation_data_encoded: [[u8; 32]; MAX_LIQUIDITY_PROVIDERS],
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

// Constants (placeholders, define as needed)
const MAX_LIQUIDITY_PROVIDERS: usize = 10;
const MAX_ENCODED_CHUNKS: usize = 100;
