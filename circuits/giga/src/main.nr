use dep::std;
use dep::rift_lib::byte_lib;
use dep::rift_lib::constants;

mod sha256_circuit_hashes;
mod sha256_merkle;

//  TODO: Make these real
global payment_verification_circuit_key_hash: Field = 0x0;
global block_verification_circuit_key_hash: Field = 0x2a06e0724cf3bf56203acdbd36591c0bdeff54eecbb4b4b73df0caff8a3ee02c;

fn decode_txn_data(txn_data_encoded: [Field; constants::MAX_ENCODED_CHUNKS]) -> [u8; constants::MAX_TXN_BYTES] {
	let mut txn_data: [u8; constants::MAX_TXN_BYTES] = [0; constants::MAX_TXN_BYTES];
	for i in 0..constants::MAX_ENCODED_CHUNKS {
		let chunk = txn_data_encoded[i].to_be_bytes(31);
		for j in 0..31 {
			txn_data[(i*31)+j] = chunk[j];
		}
	}
	txn_data
}

// Verifies a rift payment utxo end-to-end 
fn main(
	// Transaction Hash Verification
	txn_hash_encoded: pub [Field; 2],
	intermidiate_hash_encoded_and_txn_data: [Field; constants::MAX_TXN_BYTES + 2],
	// Transaction Inclusion Verification
	merkle_root_encoded: [Field; 2],
    proposed_merkle_proof: [sha256_merkle::MerkleProofStep; 20],
    // Payment Verification + Lp Hash Verification
    lp_reservation_hash: pub [Field; 2],
	order_nonce_encoded: pub [Field; 2],
	expected_payout: pub u64,
	liquidity_providers_flat_encoded: [Field; constants::MAX_LIQUIDITY_PROVIDERS*4],
    // Block Verification
	proposed_block_hash_encoded: pub [Field; 2],
    safe_block_hash_encoded: pub [Field; 2],
    retarget_block_hash_encoded: pub [Field; 2],
    safe_block_height: pub u64,
    block_height_delta: pub u64,
    // Shared
	txn_block_hash_encoded: pub [Field; 2],
    // Proof Data
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
	let intermidiate_txn_hash = byte_lib::decode_field_encoded_hash([
		intermidiate_hash_encoded_and_txn_data[0],
		intermidiate_hash_encoded_and_txn_data[1]
	]);
	assert(std::hash::sha256(intermidiate_txn_hash) == txn_hash);

	std::verify_proof(
		txn_hash_verification_key.as_slice(),
		txn_hash_proof.as_slice(),
		intermidiate_hash_encoded_and_txn_data.as_slice(),
		sha256_circuit_hashes::CIRCUIT_HASH_LIST[txn_hash_vk_hash_index]
	);


	// Transaction Inclusion Verification
	sha256_merkle::assert_merkle_proof_equality(
		byte_lib::decode_field_encoded_hash(merkle_root_encoded),
		txn_hash,
		proposed_merkle_proof
	);
	
	// TODO_ALPINE: Add lp hash circuit verification 

	// TODO_ALPINE: Update this to support updated verification circuit
	
    // Payment Verification

	// Extract just the txn data bytes 
	let (_, temp_txn_data) = intermidiate_hash_encoded_and_txn_data.as_slice().pop_front();
	let (_, txn_data) = temp_txn_data.pop_front();
	
    std::verify_proof(
        payment_verification_key.as_slice(),
        payment_proof.as_slice(),
		txn_data
			.append(liquidity_providers_flat_encoded.as_slice())
			.append(order_nonce_encoded.as_slice())
			.append(&[expected_payout as Field]),
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
		block_height_delta as Field
	];

    std::verify_proof(
        block_verification_key.as_slice(),
        block_proof.as_slice(),
        block_pub_input,
        block_verification_circuit_key_hash
    );
}

