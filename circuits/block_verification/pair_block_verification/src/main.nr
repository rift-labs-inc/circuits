// TODO: handle retarget blocks properly 
use dep::std;
use dep::rift_lib::byte_lib;
mod bitcoin;
use bitcoin::{Block, build_block_hash, verify_block};

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
    last_retarget_block: Block
) {
    if is_buffer {
        assert(block_hash_1 == block_hash_2);
        assert(block_height_1 == block_height_2);
    } else {
        assert(block_height_1 + 1 == block_height_2);
        assert(block_height_1 >= last_retarget_block_height);

        assert(build_block_hash(block_header_1) == block_hash_1);
        assert(build_block_hash(block_header_2) == block_hash_2);
        assert(build_block_hash(last_retarget_block) == last_retarget_block_hash);

        verify_block(
            block_hash_2,
            block_hash_1,
            block_header_2,
            last_retarget_block,
            block_height_2
        );
    }
}

