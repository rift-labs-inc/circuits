use dep::block_lib::{build_pair_public_input};
use dep::block_lib::vk_hashes::{PAIR_BLOCK_VERIFICATION_CIRCUIT_KEY_HASH};
use dep::std;

#[recursive]
fn main(
  first_block_hash: pub [u8; 32],
  last_block_hash: pub [u8; 32],
  first_block_height: pub u64,
  last_block_height: pub u64,
  last_retarget_block_hash: pub [u8; 32],
  last_retarget_block_height: pub u64,
  // here so that the signature is the same
  pair_verification_key: [Field; 114],
  pair_proof: [Field; 93]
) {

  assert(first_block_height + 1 == last_block_height);
  std::verify_proof(
    pair_verification_key.as_slice(),
    pair_proof.as_slice(),
    build_pair_public_input(
      first_block_hash,
      last_block_hash,
      last_retarget_block_hash,
      first_block_height,
      last_retarget_block_height,
      false
    ).as_slice(),
    PAIR_BLOCK_VERIFICATION_CIRCUIT_KEY_HASH
  );
}
