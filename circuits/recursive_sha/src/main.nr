use dep::std;
use dep::rift_lib::constants::{MAX_ENCODED_CHUNKS};

// [VARIABLE] Amount of bytes this circuit will consume from encoded_data
global BYTELEN: u32 = 7000; 
// the amount of Field chunks needed to store BYTELEN amount of u8s should always be => ceil(BYTELEN/31)
global BYTELEN_CHUNK: u32 = (BYTELEN + 30) / 31;
// overflow, if bytelen mod 31 is equal to 0 then we set overflow equal to 31
global OVERFLOW: u32 = (BYTELEN % 31) + ((BYTELEN % 31 == 0) as u32 * 31);

#[recursive]
fn main(expected_hash_encoded: pub [Field; 2], encoded_data: pub [Field; MAX_ENCODED_CHUNKS]) {
	assert(MAX_ENCODED_CHUNKS >= (BYTELEN/BYTELEN_CHUNK));
	let mut data: [u8; BYTELEN] = [0; BYTELEN];
	for i in 0..BYTELEN_CHUNK-1 {
		let decoded_field = encoded_data[i].to_be_bytes(31);
		for j in 0..31 {
			data[(i*31)+j] = decoded_field[j];
		}
	}
	let decoded_field = encoded_data[BYTELEN_CHUNK-1].to_be_bytes(OVERFLOW);
	for i in 0..OVERFLOW {
		data[((BYTELEN_CHUNK-1)*31)+i] = decoded_field[i];
	}
	let expected_hash_l1: [u8] = expected_hash_encoded[0].to_be_bytes(31);
	let expected_hash_l2: [u8] = expected_hash_encoded[1].to_be_bytes(1);
	let mut expected_hash: [u8; 32] = [0; 32];
	for i in 0..31{
		expected_hash[i] = expected_hash_l1[i];	
	}
	expected_hash[31] = expected_hash_l2[0];
	assert(std::hash::sha256(data) == expected_hash);
}

#[test]
fn simple_test(){
	// using 63 as bytelen
	let mut encoded_data: [Field; MAX_ENCODED_CHUNKS] = [0; MAX_ENCODED_CHUNKS];
	encoded_data[0] = 0x11111111111111111111111111111111111111111111111111111111111111;
	encoded_data[1] = 0xddddddddddddddddddaddddddddddddddddddddddddddddddddddddddddddd;
	encoded_data[2] = 0xdd;
	main(
		[0x9f41fb1adcfc3bbe3f6b1df9f008c33eefeddcc7dcdd7266c5c5ddadda0398, 0xb5],
		encoded_data
	);
}
