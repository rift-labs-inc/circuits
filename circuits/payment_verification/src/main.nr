use dep::rift_lib::byte_lib;
use dep::rift_lib::byte_lib::{CompConstant};
use dep::rift_lib::constants;

// current maxes, could be changed
// p2pkh -> 25 bytes, p2wpkh -> 22 bytes
global MAX_SCRIPTSIG_SIZE: u64 = 22;
global MAX_INPUT_COUNT: u64 = 1; //1000

global MAX_SCRIPT_INSCRPITION_SIZE: u64 = 80;

// constants (don't change)
global VERSION_LEN: u8 = 4;
global TXID_LEN: u8 = 32;
global VOUT_LEN: u8 = 4;
global SEQUENCE_LEN: u8 = 4;
global AMOUNT_LEN: u8 = 8; 
global OP_RETURN_CODE = 0x6a;
global OP_PUSHBYTES_32 = 0x20;
global DATA_LEN = 80;

/*
reference
struct Txn {
    version_no: u32,				// 4 bytes: for the version number
	marker: Option<u8>,				// 1 byte: must be `00`
    flag: Option<u8>,				// 1 byte: must be `01` or greater 
    in_counter: CompInt,			// 1-9 bytes CompInt for the number of inputs
    inputs: Vec<TxIn>,				// A vector of TxIn structs
    out_counter: CompInt,			// 1-9 bytes CompInt the number of outputs
    outputs: Vec<TxOut>,			// A vector of TxOut structs
    witnesses: Option<Vec<Witness>>,// Optional, present if there is witness data
    lock_time: u32,					// 4 bytes for the lock_time
}
*/

// fits in a 31 byte word
struct TxOut {
    value: u64,                     // [u8; 5] is the real size of this: for the value in Satoshis
    txout_script_length: u8,		// decoded varint (we only support decoding script lengths of < 252 )
    txout_script: [u8; MAX_SCRIPTSIG_SIZE],          // Script itself as a vector of bytes
}


struct MinifiedTxn {
    version: u32,				// 4 bytes: for the version number
	// marker: Option<u8>,				// 1 byte: must be `00`
    // flag: Option<u8>,				// 1 byte: must be `01` or greater 
    in_counter: u64,			// 1-9 bytes CompInt for the number of inputs
    // inputs: Vec<TxIn>,				// A vector of TxIn structs
    out_counter: u64,			// 1-9 bytes CompInt the number of outputs
    outputs: BoundedVec<TxOut, constants::MAX_LIQUIDITY_PROVIDERS>,// A vector of TxOut structs
    // witnesses: Option<Vec<Witness>>,// Optional, present if there is witness data
    // lock_time: u32,					// 4 bytes for the lock_time
}

impl MinifiedTxn {
    fn new(
        version: u32,
        in_counter: u64,
        out_counter: u64,
        outputs: BoundedVec<TxOut, constants::MAX_LIQUIDITY_PROVIDERS>,
    ) -> MinifiedTxn {
        MinifiedTxn { version, in_counter, out_counter, outputs }
    }
}


// what
global COMP_TIME_2: CompConstant<2> = CompConstant::new();
global COMP_TIME_3: CompConstant<3> = CompConstant::new();
global COMP_TIME_4: CompConstant<4> = CompConstant::new();
global COMP_TIME_5: CompConstant<5> = CompConstant::new();
global COMP_TIME_6: CompConstant<6> = CompConstant::new();
global COMP_TIME_7: CompConstant<7> = CompConstant::new();
global COMP_TIME_8: CompConstant<8> = CompConstant::new();
global COMP_TIME_9: CompConstant<9> = CompConstant::new();
global COMP_TIME_22: CompConstant<22> = CompConstant::new();
global COMP_TIME_32: CompConstant<32> = CompConstant::new();



fn to_int<N>(bytes: [u8; N]) -> u64 {
    bytes.fold(0 as u64, |acc: u64, b: u8| ((acc << 8) | (b as u64)))
}

// convert compact int to u64 (as le)
fn compint_to_u64<N>(compact_bytes: [u8; N]) -> u64 {
    let start_byte = compact_bytes[0];
    let mut output: u64 = start_byte as u64;
    if start_byte == 0xFD {
        output = to_int(byte_lib::grab_bytes_le(COMP_TIME_2, compact_bytes, 1));
    } else if start_byte == 0xFE {
        output = to_int(byte_lib::grab_bytes_le(COMP_TIME_4, compact_bytes, 1));
    } else if start_byte == 0xFF {
        output = to_int(byte_lib::grab_bytes_le(COMP_TIME_8, compact_bytes, 1));
    }
    output
}

fn compint_start_to_byte_len(start_byte: u8) -> u8 {
    let mut len = 1;
    if start_byte == 0xFD {
        len += 2;
    } else if start_byte == 0xFE {
        len += 4;
    } else if start_byte == 0xFF {
        len += 8;
    }
    len
}


fn extract_int_from_compint_pointer(data_pointer: u64, txn_data: [u8; constants::MAX_TXN_BYTES]) -> (u64, u8) {
	let counter_byte_len = compint_start_to_byte_len(txn_data[data_pointer]);
	let counter = compint_to_u64(
		byte_lib::grab_bytes_be_conditional(
			COMP_TIME_9,
			txn_data,
			data_pointer,
			|i|  i < counter_byte_len as u64
		)
	);
	(counter, counter_byte_len)
}


struct RiftLiquidityReservation {
	amount_reserved: u64,
	btc_exchange_rate: u64,
	script_pub_key: [u8; 22]
}


// this is essentially decoding from abi.encode'd data 
pub fn decode_liqudity_providers(
	liquidity_providers_encoded: [[Field; 4]; constants::MAX_LIQUIDITY_PROVIDERS]
) -> [RiftLiquidityReservation; constants::MAX_LIQUIDITY_PROVIDERS] {
	let mut liquidity_providers: [RiftLiquidityReservation; constants::MAX_LIQUIDITY_PROVIDERS] = [
		RiftLiquidityReservation {
			amount_reserved: 0,
			btc_exchange_rate: 0,
			script_pub_key: [0; 22]
		}; constants::MAX_LIQUIDITY_PROVIDERS];
	for i in 0..constants::MAX_LIQUIDITY_PROVIDERS {

		let slot0: [u8; 31] = liquidity_providers_encoded[i][0].to_be_bytes(31).as_array();
		let slot1: [u8; 31] = liquidity_providers_encoded[i][1].to_be_bytes(31).as_array();
		let slot2: [u8; 31] = liquidity_providers_encoded[i][2].to_be_bytes(31).as_array();

		// EXTRACT AMOUNT RESERVED
		let mut value_bytes: [u8; 8] = [0; 8];
		// only 8 bytes will be used for value, skip the first set of 0s, and iterate to the end of the field
		for j in 24..32 {
			value_bytes[j-24] = slot0[j];
		}
		// get the overflow byte
		value_bytes[7] = slot1[0];
		liquidity_providers[i].amount_reserved = byte_lib::u8_bytes_to_field(value_bytes) as u64;
		
		// EXTRACT BTC EXCHANGE RATE
		let mut btc_exchange_rate_bytes: [u8; 8] = [0; 8];
		// only 8 bytes will be used for value, skip the first set of 0s, and iterate to the end of the field
		for j in 25..32 {
			btc_exchange_rate_bytes[j-25] = slot1[j];
		}
		// get the overflow bytes (2 this time)
		btc_exchange_rate_bytes[6] = slot2[0];
		btc_exchange_rate_bytes[7] = slot2[1];

		liquidity_providers[i].btc_exchange_rate = byte_lib::u8_bytes_to_field(btc_exchange_rate_bytes) as u64;


		// EXTRACT SCRIPT PUB KEY
		// only 22 bytes consumed from the beginning
		for j in 2..24 {
			liquidity_providers[i].script_pub_key[j-2] = slot2[j];
		}
	}
	liquidity_providers
}



pub fn assert_payment_utxos_exist(
	txn_data: [u8; constants::MAX_TXN_BYTES],
	reserved_liquidity_providers: [RiftLiquidityReservation; constants::MAX_LIQUIDITY_PROVIDERS],
	order_nonce: [u8; 32],
	expected_payout: u64
) {
    let version: u32 = to_int(byte_lib::grab_bytes_le(COMP_TIME_4, txn_data, 0)) as u32;
    let mut is_segwit = false;
    if (txn_data[4] == 0x00) & (txn_data[5] >= 0x01) {
        is_segwit = true;
    }
	assert(is_segwit);
    let mut data_pointer = 6; //segwit marker and flag
	let (input_counter, input_counter_byte_len) = extract_int_from_compint_pointer(data_pointer, txn_data);
    data_pointer += input_counter_byte_len as u64;
	assert(input_counter <= MAX_INPUT_COUNT);

	// we would extract inputs here if we cared about them
	for i in 0..MAX_INPUT_COUNT {
		if i  < input_counter as u64 {
			// for every input item, determine how much of the slice it's consuming
			data_pointer += (TXID_LEN + VOUT_LEN) as u64;
			let (sig_counter, sig_counter_byte_len) = extract_int_from_compint_pointer(data_pointer, txn_data);
			data_pointer += sig_counter as u64 + sig_counter_byte_len as u64 + SEQUENCE_LEN as u64;
		}
	}

	let (output_counter, output_counter_byte_len) = extract_int_from_compint_pointer(data_pointer, txn_data);
	assert(output_counter <= constants::MAX_LIQUIDITY_PROVIDERS);
    data_pointer += output_counter_byte_len as u64;

	let mut calculated_payout: u64 = 0;

	// the setup here is the first n-2 outputs are all liquidity providers who are being paid,
	// the second to last output is the order nonce (inscription)
	// the last output is the miner fee
	for i in 0..constants::MAX_LIQUIDITY_PROVIDERS {
		if i < output_counter-2 as u64 {
			// for every output item, determine how much of the slice it's consuming
			let value: u64 = to_int(byte_lib::grab_bytes_le(COMP_TIME_8, txn_data, data_pointer)) as u64;
			data_pointer += AMOUNT_LEN as u64;
			let (sig_counter, sig_counter_byte_len) = extract_int_from_compint_pointer(data_pointer, txn_data);
			data_pointer += sig_counter_byte_len as u64;

			// Only p2wpkh is supported
			assert(sig_counter == 22);

			let lockingScript = byte_lib::grab_bytes_be_conditional(
				COMP_TIME_22,
				txn_data,
				data_pointer,
				|i|  i < sig_counter as u64
			);

			assert(value == reserved_liquidity_providers[i].amount_reserved);
			assert(lockingScript == reserved_liquidity_providers[i].script_pub_key);
			calculated_payout += value / reserved_liquidity_providers[i].btc_exchange_rate;

			// TODO: Here, assert that all the LP data exists
			data_pointer += sig_counter;
		}
	}
	assert(calculated_payout == expected_payout);
	// Now we're at the end of the payment outputs, the second to last output should always be the order nonce inscription (give last output so that the user can pay miner fee

	// the second to last output is the order nonce (inscription)
	data_pointer += AMOUNT_LEN as u64;
	let (sig_counter, sig_counter_byte_len) = extract_int_from_compint_pointer(data_pointer, txn_data);
	data_pointer += sig_counter_byte_len as u64;

	assert(sig_counter == 34);

	assert(txn_data[data_pointer] == OP_RETURN_CODE);
	data_pointer += 1;
	assert(txn_data[data_pointer] == OP_PUSHBYTES_32);
	data_pointer += 1;

	let inscribedOrderNonce = byte_lib::grab_bytes_be_conditional(
		COMP_TIME_32,
		txn_data,
		data_pointer,
		|i|  i < sig_counter as u64
	);
	assert(inscribedOrderNonce == order_nonce);
	// theres witness data and lock time past this point but we don't need it now so ignore
}


#[recursive]
fn main(
	txn_data: pub [u8; constants::MAX_TXN_BYTES],
	liquidity_providers_encoded: pub [[Field; 4]; constants::MAX_LIQUIDITY_PROVIDERS],
	order_nonce_encoded: pub [Field; 2],
	expected_payout: pub u64
) {
	let liquidity_providers = decode_liqudity_providers(liquidity_providers_encoded);
	assert_payment_utxos_exist(
		txn_data,
		liquidity_providers,
		byte_lib::decode_field_encoded_hash(order_nonce_encoded),
		expected_payout
	);
}


#[test]
fn test_liquidity_provider_decoder(){
	let mut liquidity_providers_encoded: [[Field; 4]; constants::MAX_LIQUIDITY_PROVIDERS] = [[0;4]; constants::MAX_LIQUIDITY_PROVIDERS];
	liquidity_providers_encoded[0][0] = 0x0000000000000000000000000000000000000000000000000de0b6b3a76400;
	liquidity_providers_encoded[0][1] = 0x00000000000000000000000000000000000000000000000000000000000000;
	liquidity_providers_encoded[0][2] = 0x00450014841b80d2cc75f5345c482af96294d04fdd66b2b700000000000000;
	liquidity_providers_encoded[0][3] = 0x000000;
	
	let liquidity_providers = decode_liqudity_providers(liquidity_providers_encoded);
	assert(liquidity_providers[0].amount_reserved == 1000000000000000000);
	assert(liquidity_providers[0].btc_exchange_rate == 69);
	assert(liquidity_providers[0].script_pub_key == [0, 20, 132, 27, 128, 210, 204, 117, 245, 52, 92, 72, 42, 249, 98, 148
, 208, 79, 221, 102, 178, 183]);

}


#[test]
fn test_compint() {

	assert(0x01 == compint_to_u64([0x01 as u8]));

    assert(0xFC == compint_to_u64([0xFC as u8]));

    assert(0xF1 == compint_to_u64([0xF1 as u8]));

    assert(0xCDAB == compint_to_u64([0xFD, 0xAB, 0xCD]));

    assert(0x01EFCDAB == compint_to_u64([0xFE, 0xAB, 0xCD, 0xEF, 0x01, 0x00]));

    assert(
        0x01EFCDAB01EFCDAB
        == compint_to_u64([0xFF, 0xAB, 0xCD, 0xEF, 0x01, 0xAB, 0xCD, 0xEF, 0x01])
    );

    assert(99999 == compint_to_u64([0xFE, 0x9f, 0x86, 0x01, 0x00]));
}

