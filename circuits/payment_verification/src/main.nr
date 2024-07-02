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
global OP_PUSHDATA1 = 0x4c;
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
global COMP_TIME_22: CompConstant<25> = CompConstant::new();
global COMP_TIME_80: CompConstant<80> = CompConstant::new();



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

fn arr_to_bvec<T, N>(arr: [T; N]) -> BoundedVec<T, N> {
    let mut out: BoundedVec<T, N> = BoundedVec::new();
    out.extend_from_array(arr);
    out
}


pub fn assert_payment_utxos_exist(txn_data: [u8; constants::MAX_TXN_BYTES], utxos: [u64; constants::MAX_LIQUIDITY_PROVIDERS]) {

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
	for i in 0..constants::MAX_LIQUIDITY_PROVIDERS {
		if i < output_counter-2 as u64 {
			// for every output item, determine how much of the slice it's consuming
			let value: u64 = to_int(byte_lib::grab_bytes_le(COMP_TIME_8, txn_data, data_pointer)) as u64;
			data_pointer += AMOUNT_LEN as u64;
			let (sig_counter, sig_counter_byte_len) = extract_int_from_compint_pointer(data_pointer, txn_data);
			data_pointer += sig_counter_byte_len as u64;

			// Only p2wpkh is supported
			assert(sig_counter == 22);

			let scriptSig = byte_lib::grab_bytes_be_conditional(
				COMP_TIME_22,
				txn_data,
				data_pointer,
				|i|  i < sig_counter as u64
			);
			// WIP



			// TODO: Here, assert that all the LP data exists
			data_pointer += sig_counter;
		}
	}
	// Now we're at the end of the payment outputs, the second to last output should always be the order nonce inscription (give last output so that the user can pay miner fee




	// theres witness data and lock time past this point but we don't need it now so ignore
}


/*
struct TxOut {
    value: u64,                     // [u8; 5] is the real size of this: for the value in Satoshis
    txout_script_length: u8,		// decoded varint (we only support decoding script lengths of < 252 )
    txout_script: [u8; MAX_SCRIPTSIG_SIZE],          // Script itself as a vector of bytes
}
*/

pub fn encode_tx_out_parts(value: [u8; 5], txout_script_length: u8, txout_script: [u8; MAX_SCRIPTSIG_SIZE]) -> Field {
	let mut bytes: [u8; 31] = [0 as u8; 31];
	for i in 0..5 {
		bytes[i] = value[i];
	}
	bytes[5] = txout_script_length;
	for i in 0..MAX_SCRIPTSIG_SIZE {
		bytes[6 + i] = txout_script[i];	
	}
	byte_lib::u8_bytes_to_field(bytes)
}

// each field in encoded_outputs is one of the above ^
// TODO: This needs to be reworked so you don't have to pass a ton of empty bytes in the worst case, ideally some ids/tagging
pub fn assert_outputs_exist_in_txn(txn_data: [u8; constants::MAX_TXN_BYTES], encoded_outputs: [Field; constants::MAX_LIQUIDITY_PROVIDERS]) {
	let decoded_outputs = decode_txn(txn_data).outputs;
	for i in 0..decoded_outputs.len() {
		let output = decoded_outputs.get(i);
		assert(encode_tx_out_parts(
			byte_lib::extract_bytes_from_u64(COMP_TIME_5, output.value),
			output.txout_script_length,
			output.txout_script
		) == encoded_outputs[i]);
	}
}

#[recursive]
fn main(txn_data: [u8; constants::MAX_TXN_BYTES], encoded_outputs: [Field; constants::MAX_LIQUIDITY_PROVIDERS]){
	assert_outputs_exist_in_txn(txn_data, encoded_outputs);
}


#[test]
fn test_simple_legacy_txn_decode() {

	// txhash: f8c24461e0a08ede06539433affaba93e303ca9929c300cfc00a8929e8025a80
	let mut data: BoundedVec<u8, constants::MAX_TXN_BYTES> = BoundedVec::new();
	data.extend_from_array([0x01,0x00,0x00,0x00,0x01,0x10,0xdd,0xd8,0x30,0x59,0x9b,0x17,0xcc,0x69,0x05,0x35,0xf7,0xdf,0x28,0xa8,0x44,0x66,0xea,0xca,0x3c,0x22,0xf0,0xd5,0x5b,0x79,0x02,0x3b,0x65,0x70,0xf4,0xfb,0xc5,0x01,0x00,0x00,0x00,0x8b,0x48,0x30,0x45,0x02,0x21,0x00,0xe6,0x18,0x6d,0x6f,0x34,0x4c,0xe4,0xdf,0x46,0xb2,0xe1,0x5d,0x87,0x09,0x3d,0x34,0xed,0xbf,0x5b,0x50,0x46,0x2b,0x6b,0x45,0xf9,0xbd,0x49,0x9a,0x6a,0x62,0xfb,0xc4,0x02,0x20,0x55,0xf5,0x6a,0x1c,0x4a,0x24,0xea,0x6b,0xe6,0x15,0x64,0x59,0x3c,0x41,0x96,0xb4,0x74,0x78,0xa2,0x5c,0xf5,0x96,0xc1,0xba,0xf5,0x9f,0x5a,0x9a,0x22,0x9b,0x63,0x7c,0x01,0x41,0x04,0xa4,0x1e,0x99,0x7b,0x66,0x56,0xbc,0x4f,0x5d,0xd1,0xf9,0xb9,0xdf,0x3b,0x48,0x84,0xcb,0xec,0x25,0x4d,0x3b,0x71,0xd9,0x28,0x58,0x76,0x95,0xb0,0xdf,0x0a,0x80,0x41,0x74,0x32,0xf4,0xca,0x62,0x76,0xbc,0x62,0x0b,0x1f,0x04,0x30,0x8e,0x82,0xe7,0x00,0x15,0xa4,0x0f,0x59,0x7d,0x82,0x60,0x91,0x2f,0x80,0x1e,0x4b,0x62,0xab,0x08,0x9e,0xff,0xff,0xff,0xff,0x02,0x00,0xe9,0xc8,0x29,0x01,0x00,0x00,0x00,0x19,0x76,0xa9,0x14,0x6f,0x34,0xd3,0x81,0x1a,0xde,0xd1,0xdf,0x87,0x03,0x59,0xf3,0x11,0xc2,0xa1,0x1a,0x01,0x5e,0x94,0x53,0x88,0xac,0x00,0xe4,0x0b,0x54,0x02,0x00,0x00,0x00,0x19,0x76,0xa9,0x14,0x70,0xd6,0x73,0x4d,0xe6,0x9c,0x1a,0xc8,0x91,0x38,0x92,0xf2,0xdf,0x9b,0xe0,0xe7,0x38,0xd2,0x6c,0x2d,0x88,0xac,0x00,0x00,0x00,0x00]);

	let minified_txn = decode_txn(data.storage);

	println(minified_txn);
	//let COMP_TIME_22: CompConstant<22> = CompConstant::new();
	// assert(minified_txn.outputs.len() == 2);
	// assert(byte_lib::grab_bytes_be(COMP_TIME_22, minified_txn.outputs.get(0).txout_script, 0) == [0, 20, 104, 154, 104, 28, 70, 37, 54, 173, 125, 115, 91, 73, 117, 17, 229, 39, 233, 245, 146, 69]);
}


/*
#[test]

fn test_simple_segwit_txn_decode() {

	// txhash: f8c24461e0a08ede06539433affaba93e303ca9929c300cfc00a8929e8025a80
	let mut data: BoundedVec<u8, MAX_TXN_BYTES> = BoundedVec::new();
	data.extend_from_array([0x01,0x00,0x00,0x00,0x00,0x01,0x01,0x3c,0x73,0x5f,0x81,0xc1,0xa0,0x11,0x5a,0xf2,0xe7,0x35,0x55,0x4f,0xb2,0x71,0xac,0xe1,0x8c,0x32,0xa3,0xfa,0xf4,0x43,0xf9,0xdb,0x40,0xcb,0x9a,0x11,0xca,0x63,0x11,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0x02,0xb1,0x13,0x03,0x00,0x00,0x00,0x00,0x00,0x16,0x00,0x14,0x68,0x9a,0x68,0x1c,0x46,0x25,0x36,0xad,0x7d,0x73,0x5b,0x49,0x75,0x11,0xe5,0x27,0xe9,0xf5,0x92,0x45,0xcf,0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x16,0x00,0x14,0x88,0x59,0xf1,0xe9,0xef,0x3b,0xa4,0x38,0xe2,0xec,0x31,0x7f,0x85,0x24,0xed,0x41,0xf8,0xf0,0x6c,0x6a,0x02,0x47,0x30,0x44,0x02,0x20,0x42,0x47,0x72,0xd4,0xad,0x65,0x99,0x60,0xd4,0xf1,0xb5,0x41,0xfd,0x85,0x3f,0x7d,0xa6,0x2e,0x8c,0xf5,0x05,0xc2,0xf1,0x65,0x85,0xdc,0x7c,0x8c,0xf6,0x43,0xfe,0x9a,0x02,0x20,0x7f,0xbc,0x63,0xb9,0xcf,0x31,0x7f,0xc4,0x14,0x02,0xb2,0xe7,0xf6,0xfd,0xc1,0xb0,0x1f,0x1b,0x43,0xc5,0x45,0x6c,0xf9,0xb5,0x47,0xfe,0x96,0x45,0xa1,0x6d,0xcb,0x15,0x01,0x21,0x03,0x25,0x33,0xcb,0x19,0xcf,0x37,0x84,0x25,0x56,0xdd,0x21,0x68,0xb1,0xc7,0xb6,0xf3,0xa7,0x0c,0xff,0x25,0xa6,0xff,0x4d,0x4b,0x76,0xf2,0x88,0x9d,0x2c,0x88,0xa3,0xf2,0x00,0x00,0x00,0x00]);

	let minified_txn = decode_txn(data);

	let COMP_TIME_22: CompConstant<22> = CompConstant::new();
	assert(minified_txn.outputs.len() == 2);
	assert(byte_lib::grab_bytes_be(COMP_TIME_22, minified_txn.outputs.get(0).txout_script, 0) == [0, 20, 104, 154, 104, 28, 70, 37, 54, 173, 125, 115, 91, 73, 117, 17, 229, 39, 233, 245, 146, 69]);
}

#[test]
fn test_compint() {

	assert(0x01 == compint_to_u64(arr_to_bvec([0x01 as u8])));

    assert(0xFC == compint_to_u64(arr_to_bvec([0xFC as u8])));

    assert(0xF1 == compint_to_u64(arr_to_bvec([0xF1 as u8])));

    assert(0xCDAB == compint_to_u64(arr_to_bvec([0xFD, 0xAB, 0xCD])));

    assert(0x01EFCDAB == compint_to_u64(arr_to_bvec([0xFE, 0xAB, 0xCD, 0xEF, 0x01, 0x00])));

    assert(
        0x01EFCDAB01EFCDAB
        == compint_to_u64(arr_to_bvec([0xFF, 0xAB, 0xCD, 0xEF, 0x01, 0xAB, 0xCD, 0xEF, 0x01]))
    );

    assert(99999 == compint_to_u64(arr_to_bvec([0xFE, 0x9f, 0x86, 0x01, 0x00])));
}

*/
