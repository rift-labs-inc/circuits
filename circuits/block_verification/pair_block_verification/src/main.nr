// TODO: handle retarget blocks properly 
use dep::std;
use dep::rift_lib::byte_lib;
mod bitcoin;
use bitcoin::{Block, build_block_hash, verify_block};
use dep::block_lib::{build_tree_circuit_public_input};


#[recursive]
fn main(
    block_hash_1: pub [u8; 32],
    block_hash_2: pub [u8; 32],
    last_retarget_block_hash: pub [u8; 32],
    block_height_1: pub u64,
    block_height_2: pub u64,
    last_retarget_block_height: pub u64,
    is_buffer: pub bool,
    block_header_1: Block,
    block_header_2: Block,
    last_retarget_block: Block,
    next_retarget_hash: [u8; 32],
    next_retarget_header: Block,
    next_retarget_verification_key: [Field; 114],
    next_retarget_proof: [Field; 93]
) {

  assert(build_block_hash(block_header_1) == block_hash_1);
  assert(build_block_hash(block_header_2) == block_hash_2);
  assert(build_block_hash(last_retarget_block) == last_retarget_block_hash);

  if is_buffer {
    assert(block_hash_1 == block_hash_2);
    assert(block_height_1 == block_height_2);
  } else {
    // can't prove blocks if they are the same
    assert(block_height_1 + 1 == block_height_2);

    // Handle retarget
    // TODO: Does retarget change on the old_retarget+2016 block?
    if ((block_height_1 - last_retarget_block_height) >= 2016) | ((block_height_2 - last_retarget_block_height) >= 2016) {
      assert(build_block_hash(next_retarget_header) == next_retarget_hash);
      assert(false, "Retarget not implemented yet");
      /*
      std::verify_proof(
        next_retarget_verification_key.as_slice(),
        next_retarget_proof.as_slice(),
        build_tree_circuit_public_input(
          last_retarget_block_hash,
          next_retarget_hash,
          last_retarget_block_height,
          last_retarget_block_height + 2016,
          // no buffers on the endcaps, arbitrary but nice standard to follow 
          false,
          false,
          last_retarget_block_hash,
          last_retarget_block_height
        ).as_slice(),
        RETARGET_CIRCUIT_KEY_HASH
      );
      */
    
      // TOOD: Ensure no edge case around the retarget block itself
      verify_block(
        block_hash_2,
        block_hash_1,
        block_header_2,
        next_retarget_header,
        block_height_1
      );

    } else {
      verify_block(
        block_hash_2,
        block_hash_1,
        block_header_2,
        last_retarget_block,
        block_height_1
      );
    }
  }
}

