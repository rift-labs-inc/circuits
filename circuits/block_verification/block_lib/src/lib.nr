mod vkey_hashes;

pub fn build_pair_public_input(
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

pub fn build_tree_circuit_public_input(
  first_block_hash:  [u8; 32],
  last_block_hash: [u8; 32],
  first_block_height: u64,
	last_block_height: u64,
	first_is_buffer: bool,
	last_is_buffer: bool,
  last_retarget_block_hash: [u8; 32],
  last_retarget_block_height: u64
)-> [Field; 101] {
  let mut public_input = [0 as Field; 101];

  for i in 0..32 {
    public_input[i] = first_block_hash[i] as Field;
    public_input[i+32] = last_block_hash[i] as Field;
  }
  public_input[64] = first_block_height as Field;
  public_input[65] = last_block_height as Field;
  public_input[66] = first_is_buffer as Field;
  public_input[67] = last_is_buffer as Field;
  for i in 0..32 {
	public_input[i+68] = last_retarget_block_hash[i] as Field;
  }
  public_input[100] = last_retarget_block_height as Field;


  public_input
}
