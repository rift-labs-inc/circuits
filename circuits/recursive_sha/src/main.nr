use dep::std;
use dep::rift_lib::constants::{MAX_ENCODED_CHUNKS};

// [VARIABLE] Amount of bytes this circuit will hash
global BYTELEN: u32 = 7000; 

#[recursive]
fn main(expected_hash_encoded: pub [Field; 2], data: pub [u8; BYTELEN]) {
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
	let mut data: [u8; BYTELEN] = 0x11111111111111111111111111111111111111111111111111111111111111.to_be_bytes(31).append(0xddddddddddddddddddaddddddddddddddddddddddddddddddddddddddddddd.to_be_bytes(31)).append(0xdd.to_be_bytes(1)).as_array();
	main(
		[0x9f41fb1adcfc3bbe3f6b1df9f008c33eefeddcc7dcdd7266c5c5ddadda0398, 0xb5],
		data
	);
}
