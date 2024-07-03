use dep::std;
use dep::rift_lib::byte_lib;
use dep::rift_lib::constants;

mod sha256_circuit_hashes;
mod sha256_merkle;

//  TODO: Make these real
global payment_verification_circuit_key_hash: Field = 0x0;
global block_verification_circuit_key_hash: Field = 0x2a06e0724cf3bf56203acdbd36591c0bdeff54eecbb4b4b73df0caff8a3ee02c;
global lp_hash_verification_key_hash: Field = 0x0;

// Verifies a rift payment utxo end-to-end 
fn main(
	// Transaction Hash Verification
	txn_hash_encoded: pub [Field; 2],
	intermediate_hash_encoded_and_txn_data: [Field; constants::MAX_ENCODED_CHUNKS + 2],
	// Transaction Inclusion Verification
	proposed_merkle_root_encoded: [Field; 2],
    proposed_merkle_proof: [sha256_merkle::MerkleProofStep; 20],
    // Payment Verification + Lp Hash Verification
    lp_reservation_hash_encoded: pub [Field; 2],
	order_nonce_encoded: pub [Field; 2],
	expected_payout: pub u64,
	lp_count: pub u64,
	liquidity_providers_flat_encoded: [Field; constants::MAX_LIQUIDITY_PROVIDERS*4],
    // Block Verification
	confirmation_block_hash_encoded: pub [Field; 2],
	proposed_block_hash_encoded: pub [Field; 2],
    safe_block_hash_encoded: pub [Field; 2],
    retarget_block_hash_encoded: pub [Field; 2],
    safe_block_height: pub u64,
    block_height_delta: pub u64,
    // Proof Data
	lp_hash_verification_key: [Field; 114],
	lp_hash_proof: [Field; 93],
	txn_hash_verification_key: [Field; 114],
	txn_hash_proof: [Field; 93],
	txn_hash_vk_hash_index: u64,
    payment_verification_key: [Field; 114],
    payment_proof: [Field; 93],
    block_verification_key: [Field; 114],
    block_proof: [Field; 93]
) {
	// Transaction Hash Verification
	let txn_hash = byte_lib::decode_field_encoded_hash(txn_hash_encoded);
	let intermediate_txn_hash = byte_lib::decode_field_encoded_hash([
		intermediate_hash_encoded_and_txn_data[0],
		intermediate_hash_encoded_and_txn_data[1]
	]);
	assert(std::hash::sha256(intermediate_txn_hash) == txn_hash);

	std::verify_proof(
		txn_hash_verification_key.as_slice(),
		txn_hash_proof.as_slice(),
		intermediate_hash_encoded_and_txn_data.as_slice(),
		sha256_circuit_hashes::CIRCUIT_HASH_LIST[txn_hash_vk_hash_index]
	);


	// Transaction Inclusion Verification
	sha256_merkle::assert_merkle_proof_equality(
		byte_lib::decode_field_encoded_hash(proposed_merkle_root_encoded),
		txn_hash,
		proposed_merkle_proof
	);

	// LP Hash Verification
	let mut lp_hash_pub_input: [Field; constants::MAX_LIQUIDITY_PROVIDERS*4 + 3] = [0 as Field; 703];

	lp_hash_pub_input[0] = lp_reservation_hash_encoded[0];
	lp_hash_pub_input[1] = lp_reservation_hash_encoded[1];
	for i in 0..constants::MAX_LIQUIDITY_PROVIDERS*4{
		lp_hash_pub_input[i+2] = liquidity_providers_flat_encoded[i];
	}
	lp_hash_pub_input[constants::MAX_LIQUIDITY_PROVIDERS*4 + 2] = lp_count as Field;

	std::verify_proof(
		lp_hash_verification_key.as_slice(),
		lp_hash_proof.as_slice(),
		lp_hash_pub_input.as_slice(),
		lp_hash_verification_key_hash
	);
	
    // Payment Verification

	let mut payment_pub_input: [Field; constants::MAX_ENCODED_CHUNKS + (constants::MAX_LIQUIDITY_PROVIDERS*4) + 2 + 1] = [0 as Field; 929];
	for i in 0..constants::MAX_ENCODED_CHUNKS {
		payment_pub_input[i] = intermediate_hash_encoded_and_txn_data[i+2];
	}
	for i in 0..(constants::MAX_LIQUIDITY_PROVIDERS*4) {
		payment_pub_input[i+constants::MAX_ENCODED_CHUNKS] = liquidity_providers_flat_encoded[i];
	}
	payment_pub_input[constants::MAX_ENCODED_CHUNKS + (constants::MAX_LIQUIDITY_PROVIDERS*4)] = order_nonce_encoded[0];
	payment_pub_input[constants::MAX_ENCODED_CHUNKS + (constants::MAX_LIQUIDITY_PROVIDERS*4) + 1] = order_nonce_encoded[1];
	payment_pub_input[constants::MAX_ENCODED_CHUNKS + (constants::MAX_LIQUIDITY_PROVIDERS*4) + 2] = expected_payout as Field;

	
    std::verify_proof(
        payment_verification_key.as_slice(),
        payment_proof.as_slice(),
		payment_pub_input.as_slice(),
        payment_verification_circuit_key_hash
    );

    // Block Verification
    let mut block_pub_input: [Field] = &[
		proposed_block_hash_encoded[0],
		proposed_block_hash_encoded[1],
		safe_block_hash_encoded[0],
		safe_block_hash_encoded[1],
		retarget_block_hash_encoded[0],
		retarget_block_hash_encoded[1],
		safe_block_height as Field,
		block_height_delta as Field,
		proposed_merkle_root_encoded[0],
		proposed_merkle_root_encoded[1]
	];

    std::verify_proof(
        block_verification_key.as_slice(),
        block_proof.as_slice(),
        block_pub_input,
        block_verification_circuit_key_hash
    );
}

