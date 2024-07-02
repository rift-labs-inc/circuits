use dep::std;
use dep::rift_lib::constants;
use crate::sha256_vkhash_list;

pub fn assert_sha256_preimage(
	encoded_preimage: [Field; constants::MAX_ENCODED_CHUNKS],
	encoded_expected_hash: [Field; 2],
	circuit_key_index: u64,
	verification_key: [Field; 114],
	proof: [Field; 93]
) {
	let mut pub_input: [Field; 1035] = [0; 1035];
	pub_input[0] = encoded_expected_hash[0];
	pub_input[1] = encoded_expected_hash[1];

	for i in 0..constants::MAX_ENCODED_CHUNKS {
		pub_input[i+2] = encoded_preimage[i];
	}

	std::verify_proof(
        verification_key.as_slice(),
        proof.as_slice(),
        pub_input.as_slice(),
		sha256_vkhash_list::CIRCUIT_HASH_LIST[circuit_key_index] 
    );
}
