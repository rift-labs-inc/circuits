use dep::std;
use dep::rift_lib;

global MAX_LIQUIDITY_PROVIDERS: u64 = 200;

// Solidity encodes all our lp data in 32 byte chunks, effectively do that here 
fn build_hashable_chunk(
	lp_data: [Field; 4], intermediate_vault_hash: [u8; 32]
) -> [u8; 128] {
	let mut solidity_encoded_lp_data : [u8; 128] = [0; 128];
	let slot_0: [u8; 31] = lp_data[0].to_be_bytes(31).as_array();
	let slot_1: [u8; 31] = lp_data[1].to_be_bytes(31).as_array();
	let slot_2: [u8; 31] = lp_data[2].to_be_bytes(31).as_array();
	let slot_3: [u8; 3] = lp_data[3].to_be_bytes(3).as_array();
	// slots 0,1,2 contain almost all data, so we can just copy them
	for i in 0..31 {
		solidity_encoded_lp_data[i] = slot_0[i];
		solidity_encoded_lp_data[i + 31] = slot_1[i];
		solidity_encoded_lp_data[i + 62] = slot_2[i];
	}
	// we only need 3 bytes from slot 3 -> 3*31 + 3 = 96
	for i in 0..3 {
		solidity_encoded_lp_data[i + 93] = slot_3[i];
	}
	// length at this point should be 96

	// now add the intermediate vault hash
	for i in 0..32 {
		solidity_encoded_lp_data[i + 96] = intermediate_vault_hash[i];
	}

	solidity_encoded_lp_data
}

#[recursive]
fn main(
	lp_reservation_hash_encoded: pub [Field; 2],
	lp_reservation_data_encoded: pub [[Field; 4]; MAX_LIQUIDITY_PROVIDERS],
	lp_count: pub u64
) {
	let mut intermediate_vault_hash: [u8; 32] = [0; 32];
	for i in 0..MAX_LIQUIDITY_PROVIDERS {
		if i < lp_count {
			let lp_data: [Field; 4] = lp_reservation_data_encoded[i];
			let hashable_chunk: [u8; 128] = build_hashable_chunk(lp_data, intermediate_vault_hash);
			intermediate_vault_hash = std::hash::sha256(hashable_chunk);
		}
	}
    assert(rift_lib::byte_lib::decode_field_encoded_hash(lp_reservation_hash_encoded) == intermediate_vault_hash);
}


#[test]
fn test_chunk_builder() {
	let lp_data: [Field; 4] = [
		0x0000000000000000000000000000000000000000000000000de0b6b3a76400,
		0x00000000000000000000000000000000000000000000000000000000000000,
		0x0037664749bc041993bf56b9e8b233b9ddcc8abc7742f5a82f015a0d2256e0,
		0x869a91,
	];
	let intermediate_vault_hash: [u8; 32] = [0; 32];
	let expected_vault_hash: [Field; 2] = [0xc17faeca6b477799acff09750a4ef4db523577227834164cb93b5afba22767, 0xb0];

	let hashable_chunk: [u8; 128] = build_hashable_chunk(lp_data, intermediate_vault_hash);
	let vault_hash: [u8; 32] = std::hash::sha256(hashable_chunk);
	assert(rift_lib::byte_lib::decode_field_encoded_hash(expected_vault_hash) == vault_hash);
}


#[test]
// comment out #[recursive] above main to run this test
fn test_main() {
	let mut lp_data: [[Field; 4]; MAX_LIQUIDITY_PROVIDERS] = [[0; 4]; MAX_LIQUIDITY_PROVIDERS];
	lp_data[0][0] = 0x0000000000000000000000000000000000000000000000000de0b6b3a76400;
	lp_data[0][1] = 0x00000000000000000000000000000000000000000000000000000000000000;
	lp_data[0][2] = 0x0037664749bc041993bf56b9e8b233b9ddcc8abc7742f5a82f015a0d2256e0;
	lp_data[0][3] = 0x869a91;

	let lp_count: u64 = 1;

	let expected_vault_hash: [Field; 2] = [
		0xc17faeca6b477799acff09750a4ef4db523577227834164cb93b5afba22767,
		0xb0
	];
	main(
		expected_vault_hash,
		lp_data,
		lp_count
	);
}
