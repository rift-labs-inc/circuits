use dep::std;
use dep::rift_lib::byte_lib;

mod sha256_circuit_hashes;
mod sha256_merkle;

//  TODO: Make these real
global payment_verification_circuit_key_hash: Field = 0x0;
global block_verification_circuit_key_hash: Field = 0x2a06e0724cf3bf56203acdbd36591c0bdeff54eecbb4b4b73df0caff8a3ee02c;

// Verifies a rift payment utxo end-to-end 
fn main(
	// Transaction Hash Verification
	txn_hash_encoded: pub [Field; 2],
	intermidiate_hash_and_txn_data_encoded: [Field; 1035],
	// Transaction Inclusion Verification
	merkle_root_encoded: [Field; 2],
    proposed_merkle_proof: [sha256_merkle::MerkleProofStep; 20],
    // Payment Verification
    lp_reservation_hash: pub [Field; 2],
    swap_output: pub Field,
	order_nonce_encoded: pub [Field; 2],
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
		intermidiate_hash_and_txn_data_encoded[0],
		intermidiate_hash_and_txn_data_encoded[1]
	]);
	assert(std::hash::sha256(intermidiate_txn_hash) == txn_hash);

	std::verify_proof(
		txn_hash_verification_key.as_slice(),
		txn_hash_proof.as_slice(),
		intermidiate_hash_and_txn_data_encoded.as_slice(),
		sha256_circuit_hashes::CIRCUIT_HASH_LIST[txn_hash_vk_hash_index]
	);


	// Transaction Inclusion Verification
	sha256_merkle::assert_merkle_proof_equality(
		byte_lib::decode_field_encoded_hash(merkle_root_encoded),
		txn_hash,
		proposed_merkle_proof
	);

	
    // Payment Verification
    let mut payment_pub_input: [Field] = &[
        txn_block_hash_encoded[0],
        txn_block_hash_encoded[1],
        lp_reservation_hash[0],
        lp_reservation_hash[1],
		order_nonce_encoded[0],
		order_nonce_encoded[1],
        swap_output
    ];

    std::verify_proof(
        payment_verification_key.as_slice(),
        payment_proof.as_slice(),
        payment_pub_input,
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

