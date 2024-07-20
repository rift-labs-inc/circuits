use dep::std;

global pair_block_verification_circuit_key_hash: Field = 0x14caa4f3a09635ca8407ee1642774588b3c70e0d689519b7683d2e20521d371f;

fn build_pair_public_input(
    block_hash_1:  [u8; 32],
    block_hash_2: [u8; 32],
    last_retarget_block_hash: [u8; 32],
    block_height_1: u64,
    last_retarget_block_height: u64,
    is_buffer: bool
)-> [Field; 100] {
  let mut block_height_2 = block_height_1;
  if !is_buffer {
    block_height_2 += 1;
  } 
  let mut public_input = [0 as Field; 100];
  for i in 0..32 {
    public_input[i] = block_hash_1[i] as Field;
    public_input[i+32] = block_hash_2[i] as Field;
    public_input[i+64] = last_retarget_block_hash[i] as Field;
  }
  public_input[96] = block_height_1 as Field;
  public_input[97] = block_height_2 as Field;
  public_input[98] = last_retarget_block_height as Field;
  public_input[99] = is_buffer as Field;
  public_input
}

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
    assert(last_block_height == first_block_height + 2, "Ensure Balanced Tree Delta");
  } else if first_is_buffer & last_is_buffer {
    assert(last_block_height == first_block_height, "Ensure Buffer Tree Delta");
    assert(first_block_hash == last_block_hash);
  } else { // either first or last is buffer
    assert(last_block_height == first_block_height + 1, "Ensure Impalanced Tree Delta");
  }
  
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
    pair_block_verification_circuit_key_hash
  );


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
    pair_block_verification_circuit_key_hash
  );
}

