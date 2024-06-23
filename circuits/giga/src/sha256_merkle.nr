use dep::std;

struct MerkleProofStep {
    hash: [u8; 32],
    direction: bool, // false = left, true = right
}

fn hash_pairs(hash_1: [u8; 32], hash_2: [u8; 32]) -> [u8; 32] {
    // [0] convert hashes to little-endian
    let mut hash1: [u8; 32] = [0; 32];
    let mut hash2: [u8; 32] = [0; 32];
    for i in 0..32 {
        hash1[i] = (hash_1[31 - i] as u8);
        hash2[i] = (hash_2[31 - i] as u8);
    }

    // [1] combine hashes into one 64 byte array
    let mut combined_hashes: [u8; 64] = [0; 64];
    for i in 0..32 {
        combined_hashes[i] = hash1[i];
        combined_hashes[i+32] = hash2[i];
    }

    // [2] double sha256 combined hashes
    let first_hash = std::hash::sha256(combined_hashes);
    let new_hash_be = std::hash::sha256(first_hash);

    // [3] convert new hash to little-endian
    let mut new_hash: [u8; 32] = [0; 32];
    for i in 0..32 {
        new_hash[i] = (new_hash_be[31 - i] as u8);
    }

    new_hash
}

pub fn assert_merkle_proof_equality(
    merkle_root: [u8; 32],
    proposed_txn_hash: [u8; 32],
    proposed_merkle_proof: [MerkleProofStep; 20],
) {
    let mut current_hash = proposed_txn_hash;
    let zero_hash = [0; 32];
    let mut count = 0;
    for i in 0..20 {
        if proposed_merkle_proof[i].hash != zero_hash {
            let proof_step = proposed_merkle_proof[count];
            if proof_step.direction == true {
                current_hash = hash_pairs(current_hash, proof_step.hash);
            } else {
                current_hash = hash_pairs(proof_step.hash, current_hash);
            }
            count += 1;
        }
    }
    // [1] verify computed merkle root == expected merkle root
	assert(current_hash == merkle_root);
	/*
    print("\nExpected merkle root: ");
    for i in 0..32 {
        print(merkle_root[i] as Field);
        print(", ");
    }

    print("\nComputed merkle root: ");
    for i in 0..32 {
        print(current_hash[i] as Field);
        print(", ");
    }
	*/

    println("\n\nMerkle proof verified! 🎉🎉🎉");
}
