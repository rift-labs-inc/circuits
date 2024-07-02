use dep::std;
use dep::rift_lib::byte_lib;
use dep::rift_lib::constants;
mod sha256_vkhash_list;
mod sha256_merkle;
mod sha256_verify;
// mod txn_encoder;




fn main(
	// from contract
    merkle_root: pub [Field; 2],
	// from indexer:
    proposed_merkle_proof: [sha256_merkle::MerkleProofStep; 20], 
	encoded_txn_data: [Field; constants::MAX_ENCODED_CHUNKS],
	encoded_expected_hash: [Field; 2],
	recursive_sha256_circuit_key_index: u64,
	recursive_sha256_verification_key: [Field; 114],
	recursive_sha256_proof: [Field; 93],
	recursive_txn_decoder_vkey_hash: Field,
	recursive_txn_decoder_verification_key: [Field; 114],
	recursive_txn_decoder_proof: [Field; 93],
) {
    //------------------ MAIN CIRCUIT ------------------
    // [0] verify merkle proof
	sha256_merkle::assert_merkle_proof_equality(
		byte_lib::decode_field_encoded_hash(merkle_root),
		byte_lib::decode_field_encoded_hash(encoded_expected_hash),
		proposed_merkle_proof
	);

	// [1] verify txn data hashes to the expected txn hash
	sha256_verify::assert_sha256_preimage(
		encoded_txn_data,
		encoded_expected_hash,
		recursive_sha256_circuit_key_index,
		recursive_sha256_verification_key, 
		recursive_sha256_proof
	);

	// testing

}

