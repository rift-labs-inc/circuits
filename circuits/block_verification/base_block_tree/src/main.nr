use dep::std;
use dep::block_lib::vk_hashes::{PAIR_BLOCK_VERIFICATION_CIRCUIT_KEY_HASH};
use dep::block_lib::{build_pair_public_input};

#[recursive]
fn main(
  first_block_hash: pub [u8; 32],
  last_block_hash: pub [u8; 32],
  first_block_height: pub u64,
  last_block_height: pub u64,
  first_is_buffer: pub bool,
  last_is_buffer: pub bool,
  last_retarget_block_hash: pub [u8; 32],
  last_retarget_block_height: pub u64,
  link_block_hash: [u8; 32],
  first_pair_verification_key: [Field; 114],
  first_pair_proof: [Field; 93],
  last_pair_verification_key: [Field; 114],
  last_pair_proof: [Field; 93]
  ) {

  if !first_is_buffer & !last_is_buffer {
    assert(last_block_height == first_block_height + 2, "Ensure Balanced Tree");
	
  } else if first_is_buffer & last_is_buffer {
    assert(last_block_height == first_block_height, "Ensure Buffer Tree");
    assert(first_block_hash == last_block_hash);
  } else { // either first or last is buffer
    assert(last_block_height == first_block_height + 1, "Ensure Imbalanced Tree");
  }
  
  // Left Pair
  std::verify_proof(
    first_pair_verification_key.as_slice(),
    first_pair_proof.as_slice(),
    build_pair_public_input(
      first_block_hash,
      link_block_hash,
      last_retarget_block_hash,
      first_block_height,
      last_retarget_block_height,
      first_is_buffer
    ).as_slice(),
    PAIR_BLOCK_VERIFICATION_CIRCUIT_KEY_HASH
  );


  // Right Pair
  std::verify_proof(
    last_pair_verification_key.as_slice(),
    last_pair_proof.as_slice(),
    build_pair_public_input(
      link_block_hash,
      last_block_hash,
      last_retarget_block_hash,
      last_block_height,
      last_retarget_block_height,
      last_is_buffer
    ).as_slice(),
    PAIR_BLOCK_VERIFICATION_CIRCUIT_KEY_HASH
  );
}

