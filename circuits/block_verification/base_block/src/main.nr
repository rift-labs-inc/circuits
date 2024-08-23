// TODO: handle retarget blocks properly 
use dep::std;
use dep::rift_lib::byte_lib;
use dep::block_lib::bitcoin::{Block, build_block_hash, verify_block, MAX_BASE_BLOCK_HASH_COUNT};
use dep::block_lib::{build_tree_circuit_public_input};


#[recursive]
fn main(
    block_hashes_encoded: pub [[Field; 2]; MAX_BASE_BLOCK_HASH_COUNT],
    first_block_height: pub u64,
    last_block_height: pub u64,
    last_retarget_block_hash: pub [u8; 32],
    last_retarget_block_height: pub u64,
    blocks: [Block; MAX_BASE_BLOCK_HASH_COUNT],
    last_retarget_block: Block
) {

  let utilized_blocks = last_block_height - first_block_height + 1;
  assert(utilized_blocks <= MAX_BASE_BLOCK_HASH_COUNT);

  if ((first_block_height - last_retarget_block_height) >= 2016) | ((last_block_height - last_retarget_block_height) >= 2016) {
    // TODO: allow this somehow 
    assert(false, "Can't prove blocks if retarget block changes mid proof");
  }

  assert(last_retarget_block_hash == build_block_hash(last_retarget_block));

  for i in 0..MAX_BASE_BLOCK_HASH_COUNT-1 {
    if i < utilized_blocks-1 {
      let block = blocks[i];
      let next_block = blocks[i+1];
      let block_hash = byte_lib::decode_field_encoded_hash([
        block_hashes_encoded[i][0],
        block_hashes_encoded[i][1]
      ]);
      assert(build_block_hash(block) == block_hash);
      let next_block_hash = byte_lib::decode_field_encoded_hash([
        block_hashes_encoded[i+1][0],
        block_hashes_encoded[i+1][1]
      ]);

      verify_block(
        next_block_hash,
        block_hash,
        next_block,
        last_retarget_block,
        first_block_height + i,
      );
    }
  }
  assert(
    byte_lib::decode_field_encoded_hash([
      block_hashes_encoded[utilized_blocks-1][0],
      block_hashes_encoded[utilized_blocks-1][1]
    ])
    == build_block_hash(blocks[utilized_blocks-1])
  );
}

