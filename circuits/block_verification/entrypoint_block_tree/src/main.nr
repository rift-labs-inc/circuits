use dep::std;
use dep::block_lib::{build_tree_circuit_public_input, build_pair_public_input};
use dep::block_lib::bitcoin::{Block, build_block_hash};
use dep::block_lib::vk_hashes::{PAIR_BLOCK_VERIFICATION_CIRCUIT_KEY_HASH, BLOCK_TREE_CIRCUIT_KEY_HASHES};
use dep::rift_lib::byte_lib;

global MIN_CONFIRMATION_BLOCK_HEIGHT_DELTA: u64 = 5;

pub fn log2_floor(mut v: u32) -> u32 {
    let MULTIPLY_DE_BRUIJN_BIT_POSITION: [u8; 32] = [
        0, 9, 1, 10, 13, 21, 2, 29, 11, 14, 16, 18, 22, 25, 3, 30,
        8, 12, 20, 28, 15, 17, 24, 7, 19, 27, 23, 6, 26, 5, 4, 31
    ];
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;

    MULTIPLY_DE_BRUIJN_BIT_POSITION[((std::wrapping_mul(v, 0x07C4ACDD)) >> 27)] as u32
}

fn prove_blocks(
  first_block_height: u64,
  last_block_height: u64,
  first_block_hash: [u8; 32],
  last_block_hash: [u8; 32],
  last_retarget_block_hash: [u8; 32],
  last_retarget_block_height: u64,
  proof: [Field; 93],
  verification_key: [Field; 114],
  ) {

  let circuit_selector = log2_floor((last_block_height-first_block_height) as u32);
  assert(circuit_selector < BLOCK_TREE_CIRCUIT_KEY_HASHES.len() as u32);

  // if block delta is 1, then we are verifying a single pair of blocks (safe height + 1 == proposed height)
  let mut public_input: [Field] = [];
  let mut verification_key_hash: Field = 0;
  if circuit_selector != 0 {
    verification_key_hash = BLOCK_TREE_CIRCUIT_KEY_HASHES[circuit_selector-1]; 
    public_input = build_tree_circuit_public_input(
      first_block_hash,
      last_block_hash,
      first_block_height,
      last_block_height,
      false,
      false,
      last_retarget_block_hash,
      last_retarget_block_height,
      [0; 16] // TODO: This is a dummy value, need to pass actual aggregation object, and also
      // add another conditional to verify this is not an R1 tree at which point we should not pass 
      // this value
    );
  } else {
    verification_key_hash = PAIR_BLOCK_VERIFICATION_CIRCUIT_KEY_HASH;
    public_input = build_pair_public_input(
      first_block_hash,
      last_block_hash,
      last_retarget_block_hash,
      first_block_height,
      last_retarget_block_height,
      false
    );
  }
  std::verify_proof(
    verification_key.as_slice(),
    proof.as_slice(),
    public_input,
    verification_key_hash
  );

}

/*
Verifies:
 - safe -> proposed heights and hashes have chain of blocks between them
 - proposed -> confirmation heights and hashes have chain of blocks between them
 - merkle root of proposed block aligns with proposed block hash

Enforced at contract level:
* if proposed block height is greater than latest safe, then default +5 confirmation blocks will work
* if proposed block height is less than latest safe, then there needs to be n confirmation blocks
  that exist between the proposed and latest/next safe block
*/
#[recursive]
fn main(
  confirmation_block_hash_encoded: pub [Field; 2],
  proposed_block_hash_encoded: pub [Field; 2],
  safe_block_hash_encoded: pub [Field; 2],
  retarget_block_hash_encoded: pub [Field; 2],
  safe_block_height: pub u64,
  block_height_delta: pub u64,
  confirmation_block_height_delta: pub u64,
  proposed_merkle_root_encoded: pub [Field; 2],
  proposed_block: Block,
  safe_proposed_verification_key: [Field; 114],
  safe_proposed_proof: [Field; 93],
  proposed_confirmation_verification_key: [Field; 114],
  proposed_confirmation_proof: [Field; 93],
  ) {
  assert(confirmation_block_height_delta >= MIN_CONFIRMATION_BLOCK_HEIGHT_DELTA);
  
  let confirmation_block_hash = byte_lib::decode_field_encoded_hash(confirmation_block_hash_encoded);
  let proposed_block_hash = byte_lib::decode_field_encoded_hash(proposed_block_hash_encoded);
  let safe_block_hash = byte_lib::decode_field_encoded_hash(safe_block_hash_encoded);
  let retarget_block_hash = byte_lib::decode_field_encoded_hash(retarget_block_hash_encoded); 
  let proposed_merkle_root = byte_lib::decode_field_encoded_hash(proposed_merkle_root_encoded);

  // Verify a chain exists between safe block -> proposed block
  prove_blocks(
    safe_block_height,
    safe_block_height + block_height_delta,
    safe_block_hash,
    proposed_block_hash,
    retarget_block_hash,
    safe_block_height + block_height_delta,
    safe_proposed_proof,
    safe_proposed_verification_key
  );

  // Verify a chain exists between proposed block -> confirmation block
  prove_blocks(
    safe_block_height + block_height_delta,
    safe_block_height + block_height_delta + confirmation_block_height_delta,
    proposed_block_hash,
    confirmation_block_hash,
    retarget_block_hash,
    safe_block_height + block_height_delta,
    proposed_confirmation_proof,
    proposed_confirmation_verification_key
  );
  
  // Verify proposed block merkle root
  assert(proposed_block.merkle_root == proposed_merkle_root);
  assert(build_block_hash(proposed_block) == proposed_block_hash);
}


#[test]
fn test_log2_floor() {
    assert(log2_floor(1) == 0);
    assert(log2_floor(2) == 1);
    assert(log2_floor(3) == 1);
    assert(log2_floor(4) == 2);
    assert(log2_floor(7) == 2);
    assert(log2_floor(8) == 3);
    assert(log2_floor(15) == 3);
    assert(log2_floor(16) == 4);
    assert(log2_floor(31) == 4);
    assert(log2_floor(32) == 5);
    assert(log2_floor(63) == 5);
    assert(log2_floor(64) == 6);
    assert(log2_floor(127) == 6);
    assert(log2_floor(128) == 7);
    assert(log2_floor(255) == 7);
    assert(log2_floor(256) == 8);
    assert(log2_floor(511) == 8);
    assert(log2_floor(512) == 9);
    assert(log2_floor(1023) == 9);
    assert(log2_floor(1024) == 10);
    assert(log2_floor(2047) == 10);
    assert(log2_floor(2048) == 11);
    assert(log2_floor(4095) == 11);
    assert(log2_floor(4096) == 12);
    assert(log2_floor(8191) == 12);
    assert(log2_floor(8192) == 13);
    assert(log2_floor(16383) == 13);
    assert(log2_floor(16384) == 14);
    assert(log2_floor(32767) == 14);
    assert(log2_floor(32768) == 15);
    assert(log2_floor(65535) == 15);
    assert(log2_floor(65536) == 16);
    assert(log2_floor(131071) == 16);
    assert(log2_floor(131072) == 17);
    assert(log2_floor(262143) == 17);
    assert(log2_floor(262144) == 18);
    assert(log2_floor(524287) == 18);
    assert(log2_floor(524288) == 19);
    assert(log2_floor(1048575) == 19);
    assert(log2_floor(1048576) == 20);
}
