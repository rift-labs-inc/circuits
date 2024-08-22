use dep::std;
use dep::block_lib::{build_tree_circuit_public_input, build_pair_public_input, build_base_tree_circuit_public_input};
use dep::block_lib::bitcoin::{Block, build_block_hash, MAX_BASE_BLOCK_HASH_COUNT, MAX_BLOCK_HASHES, MAX_BLOCK_PROOFS};
use dep::block_lib::vk_hashes::{BASE_BLOCK_VERIFICATION_KEY_HASH};
use dep::rift_lib::byte_lib;

global MIN_CONFIRMATION_BLOCK_HEIGHT_DELTA: u64 = 5;
global INNER_PROOF_PUB_INPUT_LEN: u64 = (MAX_BASE_BLOCK_HASH_COUNT * 2) + 3 + 32;

fn prove_blocks(
  block_hashes_encoded: [[Field; 2]; MAX_BASE_BLOCK_HASH_COUNT],
  first_block_height: u64,
  last_block_height: u64,
  last_retarget_block_hash: [u8; 32],
  last_retarget_block_height: u64,
  verification_key: [Field; 114],
  proof: [Field; 93]
) {
  let mut public_input: [Field; MAX_BASE_BLOCK_HASH_COUNT] = [0 as Field; MAX_BASE_BLOCK_HASH_COUNT];
  for i in 0..MAX_BASE_BLOCK_HASH_COUNT {
      public_input[i * 2] = block_hashes_encoded[i][0];
      public_input[i * 2 + 1] = block_hashes_encoded[i][1];
  }
  public_input[MAX_BASE_BLOCK_HASH_COUNT * 2] = first_block_height as Field;
  public_input[MAX_BASE_BLOCK_HASH_COUNT * 2 + 1] = last_block_height as Field;
  public_input[MAX_BASE_BLOCK_HASH_COUNT * 2 + 2] = last_retarget_block_height as Field;
  for i in 0..32 {
      public_input[MAX_BASE_BLOCK_HASH_COUNT * 2 + 3 + i] = last_retarget_block_hash[i] as Field;
  }

  std::verify_proof(
    verification_key.as_slice(),
    proof.as_slice(),
    public_input.as_slice(),
    BASE_BLOCK_VERIFICATION_KEY_HASH
  );

}

#[recursive]
fn main(
  block_hashes_encoded: pub [[Field; 2]; MAX_BLOCK_HASHES], 
  retarget_block_hash_encoded: pub [Field; 2],
  safe_block_height: pub u64,
  safe_block_height_delta: pub u64,
  confirmation_block_height_delta: pub u64,
  proposed_merkle_root_encoded: pub [Field; 2],
  retarget_block_height: pub u64,
  proposed_block: pub Block,
  base_block_verification_key: [Field; 114],
  proofs: [[Field; 93]; MAX_BLOCK_PROOFS]
  ) {
  let utilized_blocks = confirmation_block_height_delta + safe_block_height_delta;
  assert(utilized_blocks <= MAX_BLOCK_HASHES);
  
  let retarget_block_hash = byte_lib::decode_field_encoded_hash(retarget_block_hash_encoded);

  let base_block_proof_count = utilized_blocks / MAX_BASE_BLOCK_HASH_COUNT;
  let remaining_blocks = utilized_blocks % MAX_BASE_BLOCK_HASH_COUNT;
  for i in 0..MAX_BLOCK_PROOFS {
    if i < base_block_proof_count {
      let mut block_hashes_encoded_chunk: [[Field; 2]; MAX_BASE_BLOCK_HASH_COUNT] = [[0, 2]; MAX_BASE_BLOCK_HASH_COUNT];
      for j in 0..MAX_BASE_BLOCK_HASH_COUNT {
        block_hashes_encoded_chunk[j] = block_hashes_encoded[i * MAX_BASE_BLOCK_HASH_COUNT + j];
      }
      /*

      block_hashes_encoded: [[Field; 2]; MAX_BASE_BLOCK_HASH_COUNT],
      first_block_height: u64,
      last_block_height: u64,
      last_retarget_block_hash: [u8; 32],
      last_retarget_block_height: u64,
      verification_key: [Field; 114],
      proof: [Field; 93]
      */
      print("Chunk");
      println(i);
      println("first block height");
      println(
        safe_block_height + (i * MAX_BASE_BLOCK_HASH_COUNT),
      );
      println("last block height");
      println(
        safe_block_height + (i * MAX_BASE_BLOCK_HASH_COUNT) + MAX_BASE_BLOCK_HASH_COUNT - 1,
      );

      prove_blocks(
        block_hashes_encoded_chunk,
        safe_block_height + (i * MAX_BASE_BLOCK_HASH_COUNT),
        safe_block_height + (i * MAX_BASE_BLOCK_HASH_COUNT) + MAX_BASE_BLOCK_HASH_COUNT - 1,
        retarget_block_hash,
        retarget_block_height,
        base_block_verification_key,
        proofs[i]
      );
    }
  }

  // prove last proof with remaining blocks
  if remaining_blocks != 0 {
    let mut block_hashes_encoded_chunk: [[Field; 2]; MAX_BASE_BLOCK_HASH_COUNT] = [[0, 2]; MAX_BASE_BLOCK_HASH_COUNT];
    for j in 0..MAX_BASE_BLOCK_HASH_COUNT {
      if j < remaining_blocks {
        block_hashes_encoded_chunk[j] = block_hashes_encoded[base_block_proof_count * MAX_BASE_BLOCK_HASH_COUNT + j];
      }
    }
    prove_blocks(
      block_hashes_encoded_chunk,
      safe_block_height + (base_block_proof_count * MAX_BASE_BLOCK_HASH_COUNT),
      safe_block_height + (base_block_proof_count * MAX_BASE_BLOCK_HASH_COUNT) + remaining_blocks - 1,
      retarget_block_hash,
      retarget_block_height,
      base_block_verification_key,
      proofs[base_block_proof_count]
    );
  }

  // Verify proposed block merkle root is the same as the one actually in the block
  let proposed_block_hash = byte_lib::decode_field_encoded_hash([
    block_hashes_encoded[safe_block_height_delta][0],
    block_hashes_encoded[safe_block_height_delta][1],
  ]);
  assert(proposed_block.merkle_root == byte_lib::decode_field_encoded_hash(proposed_merkle_root_encoded));
  assert(build_block_hash(proposed_block) == proposed_block_hash);
}
