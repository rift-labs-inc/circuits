use dep::std;
use dep::rift_lib::byte_lib;
// MAX_BASE_BLOCK_PROOF_COUNT

global MAX_BASE_BLOCK_HASH_COUNT = 90;
global MAX_BLOCK_HASHES = 750;
global MAX_BLOCK_PROOFS = MAX_BLOCK_HASHES / MAX_BASE_BLOCK_HASH_COUNT;
global TARGET_PERIOD: u32 = 2016; // blocks between difficulty retargets
global TARGET_TIMESPAN: u32 = 1209600; // goal time of 10 minutes per block * 2016 blocks
global CONFIRMATION_BLOCK_DELTA: u64 = 5;

struct Block {
    height: u64,
    version: Field,
    prev_block_hash: [u8; 32],
    merkle_root: [u8; 32],
    timestamp: Field,
    bits: Field,
    nonce: Field,
}

pub fn verify_block(
    proposed_block_hash: [u8; 32],
    previous_block_hash: [u8; 32],
    proposed_block: Block,
    retarget_block: Block,
    previous_block_height: u64
) {
    // [1] verify proposed target is equal to real target
    let proposed_target = bits_to_target(proposed_block.bits);
    assert(retarget_block.bits == proposed_block.bits);

    // [2] verify the proposed block height is one greater than previous_block_height
    assert(proposed_block.height as u64 == previous_block_height + 1);

    // [3] verify the proposed prev_block_hash matches real previous_block_hash
    assert(proposed_block.prev_block_hash == previous_block_hash);

    // [4] verify PoW (double sha256(block_hash) <= target)
    verify_pow(proposed_block_hash, proposed_block, proposed_target);
}

pub fn bits_to_target(bits: Field) -> [u8; 32] {
    // [0] convert the given bits to target

    // [1] convert new target to byte array
    let mut target_array: [u8; 32] = [0; 32];
    let byte_bits: [u8; 4] = (bits as Field).to_be_bytes(4).as_array();
    let exponent = byte_bits[0] as u64;
    let coefficient_bytes: [u8; 3] = [byte_bits[1], byte_bits[2], byte_bits[3]];

    for i in 0..32 {
        if i == 32 - exponent {
            target_array[i] = coefficient_bytes[0];
        } else if i == 32 - exponent + 1 {
            target_array[i] = coefficient_bytes[1];
        } else if i == 32 - exponent + 2 {
            target_array[i] = coefficient_bytes[2];
        } else {
            target_array[i] = 0x00;
        }
    }

    // [2] convert maximum possible target to byte array
    let max_target = 0xFFFF0000000000000000000000000000000000000000000000000000;
    let mut max_target_array: [u8; 32] = [0; 32];
    let max_target_bytes: [u8; 32] = max_target.to_be_bytes(32).as_array();
    for i in 0..32 {
        max_target_array[i] = max_target_bytes[i];
    }

    let mut target: [u8; 32] = target_array;

    // [3] clamp target if above max 
    let comparison = larger_byte_array(target_array, max_target_array);
    if (comparison == 1) { // target > max_target
        println("\nProposed target > max, clamping...");
        target = max_target_bytes;
    }
    target
}

/*
pub fn calculate_real_target(retarget_block: Block, proposed_block: Block) -> [u8; 32] {
    // [0] calculate the actual time between blocks
    assert(proposed_block.timestamp as u64 >= retarget_block.timestamp as u64);
    let mut actual_time = proposed_block.timestamp as u64 - retarget_block.timestamp as u64;
    if actual_time < (TARGET_TIMESPAN / 4) as u64 {
        actual_time = (TARGET_TIMESPAN / 4) as u64;
    } else if actual_time > (TARGET_TIMESPAN * 4) as u64 {
        actual_time = (TARGET_TIMESPAN * 4) as u64;
    }

    // [1] decode old bits
    let old_exponent = retarget_block.bits as u32 >> 24;
    let old_coefficient = retarget_block.bits as u32 & 0x00ffffff;

    // [2] calculate new coefficient based on time ratio 
    let scale = 1_000_000;
    let mut new_coefficient = old_coefficient as u64 * (actual_time as u64 * scale) / (TARGET_TIMESPAN as u64 * scale);
    if new_coefficient > 0x00ffffff {
        new_coefficient = 0x00ffffff; // clamp to max if overflow
    }

    // [3] calculate new bits
    let new_bits = (old_exponent << 24) | new_coefficient as u32; // combine exponent and coefficient
    let new_target = bits_to_target(new_bits as Field);
    let old_target = bits_to_target(retarget_block.bits);

    // [4] return new target if 2016 blocks have passed since last retarget
    if (proposed_block.height as u32 >= retarget_block.height as u32 + TARGET_PERIOD) {
        new_target
    } else {
        old_target
    }
}
*/

pub fn build_block_hash(block: Block) -> [u8; 32] {
    // [0] build serialized header from proposed block data
    let mut serialized_header_array: [u8; 80] = [0; 80];
    let mut i = 0;

    // version
    let version_bytes = block.version.to_le_bytes(4);
    for j in 0..4 {
        serialized_header_array[i] = version_bytes[j];
        i += 1;
    }

    // previous block hash
    let len = block.prev_block_hash.len();
    for j in 0..len {
        serialized_header_array[i] = block.prev_block_hash[len - 1 - j];
        i += 1;
    }

    // merkle root
    let len = block.merkle_root.len();
    for j in 0..len {
        serialized_header_array[i] = block.merkle_root[len - 1 - j];
        i += 1;
    }

    // timestamp
    let timestamp_bytes = block.timestamp.to_le_bytes(4);
    for j in 0..4 {
        serialized_header_array[i] = timestamp_bytes[j];
        i += 1;
    }

    // bits
    let bits_bytes = block.bits.to_le_bytes(4);
    for j in 0..4 {
        serialized_header_array[i] = bits_bytes[j];
        i += 1;
    }

    // nonce
    let nonce_bytes = block.nonce.to_le_bytes(4);
    for j in 0..4 {
        serialized_header_array[i] = nonce_bytes[j];
        i += 1;
    }

    // [1] double sha256 the serialized block header
    let first_hash = std::hash::sha256(serialized_header_array);
    let second_hash = std::hash::sha256(first_hash);

    // convert block hash to little-endian
    let mut block_hash: [u8; 32] = [0; 32];
    for i in 0..32 {
        block_hash[i] = (second_hash[len - 1 - i] as u8);
    }
    block_hash
}

pub fn verify_pow(proposed_block_hash: [u8; 32], proposed_block: Block, proposed_target: [u8; 32]) {
    println("\nVerifying PoW...");
    let calculated_block_hash = build_block_hash(proposed_block);

    // [2] verify proposed block hash matches calculated block hash
    assert(calculated_block_hash == proposed_block_hash);

    // [3] verify PoW if block hash <= proposed target
    assert(is_block_hash_larger_than_target(proposed_block_hash, proposed_target));
    println("\nPoW verified!\n");
}

pub fn larger_byte_array(a: [u8; 32], b: [u8; 32]) -> u32 {
    // returns larger byte array (1: a > b, 2: a < b, 0: a == b)
    let mut result = 0;
    for i in 0..32 {
        if (a[i] != b[i]) {
            if (result == 0) {
                if a[i] > b[i] {
                    result = 1; // a > b
                } else {
                    result = 2; // a < b
                }
            }
        }
    }
    result // a == b
}

pub fn is_block_hash_larger_than_target(proposed_block_hash: [u8; 32], target: [u8; 32]) -> bool {
    1 != larger_byte_array(proposed_block_hash, target)
}


