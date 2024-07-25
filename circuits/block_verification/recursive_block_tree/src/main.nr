// NOTE: This is a just a reference utilized to generate the actual circuits in generated_block_tree
use dep::std;
use dep::block_lib::{build_tree_circuit_public_input};

global BLOCK_TREE_CIRCUIT_KEY_HASH: Field = 0x0; // [REPLACE] 

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
  link_block_height: u64,
  link_block_is_buffer: bool,
  first_pair_verification_key: [Field; 114],
  first_pair_proof: [Field; 93],
  last_pair_verification_key: [Field; 114],
  last_pair_proof: [Field; 93]
  ) {
  
  // Left
  std::verify_proof(
    first_pair_verification_key.as_slice(),
    first_pair_proof.as_slice(),
    build_tree_circuit_public_input(
      first_block_hash,
      link_block_hash,
      first_block_height,
      link_block_height,
      first_is_buffer,
      link_block_is_buffer,
      last_retarget_block_hash,
      last_retarget_block_height
    ).as_slice(),
    BLOCK_TREE_CIRCUIT_KEY_HASH
  );


  // Right	
  std::verify_proof(
    last_pair_verification_key.as_slice(),
    last_pair_proof.as_slice(),
    build_tree_circuit_public_input(
      link_block_hash,
      last_block_hash,
      link_block_height,
      last_block_height,
      link_block_is_buffer,
      last_is_buffer,
      last_retarget_block_hash,
      last_retarget_block_height
    ).as_slice(),
    BLOCK_TREE_CIRCUIT_KEY_HASH
  );
}

