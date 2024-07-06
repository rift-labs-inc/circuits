import os
import sys
import asyncio

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.fetch_block_data import fetch_block_data
from utils.rift_lib import create_block_verification_prover_toml_witness, Block, compute_block_hash, BB
from utils.noir_lib import (
    initialize_noir_project_folder,
    compile_project,
    create_witness,
    normalize_hex_str,
    pad_list,
    hex_string_to_byte_array,
    split_hex_into_31_byte_chunks,
    create_proof,
    build_raw_verification_key,
    extract_vk_as_fields,
    verify_proof
)

async def test_multiple_blocks(proposed_block_height: int, safe_block_height: int, retarget_height: int):
    num_inner_blocks = proposed_block_height - safe_block_height
    # [0] compile project folder
    BLOCK_VERIFICATION_DIR = "circuits/block_verification"
    print("Compiling block verification circuit...")
    await compile_project(BLOCK_VERIFICATION_DIR)

    # [1] fetch block data
    print(f"Fetching block data from height {safe_block_height + 1} to {safe_block_height + num_inner_blocks}...")
    inner_blocks = await asyncio.gather(*[
        fetch_block_data(height) for height in range(safe_block_height + 1, safe_block_height + num_inner_blocks)])

    print(f"Fetching block data from height {proposed_block_height+1} to {proposed_block_height + 7}...")
    confirmation_blocks = await asyncio.gather(*[
        fetch_block_data(height) for height in range(proposed_block_height+1, proposed_block_height+7)])
    print("RETARGET BLOCK", retarget_height)
    print("SAFE BLOCK", safe_block_height)
    print("INNER BLOCKS")
    [print(block.height) for block in inner_blocks]
    print("PROPOSED BLOCK", proposed_block_height)
    print("CONFIRMATION BLOCKS")
    [print(block.height) for block in confirmation_blocks]

    if not inner_blocks or not confirmation_blocks:
        print("No inner blocks to process.")
        return

    retarget_block = await fetch_block_data(retarget_height)
    safe_block = await fetch_block_data(safe_block_height)
    proposed_block = await fetch_block_data(proposed_block_height)
    print("Block height delta:", proposed_block.height - safe_block.height)

    # [2] create prover toml and witness
    print("Creating prover toml and witness...")
    await create_block_verification_prover_toml_witness(
        proposed_merkle_root_hex=proposed_block.merkle_root,
        confirmation_block_hash_hex=compute_block_hash(confirmation_blocks[-1]),
        proposed_block_hash_hex=compute_block_hash(proposed_block),
        safe_block_hash_hex=compute_block_hash(safe_block),
        retarget_block_hash_hex=compute_block_hash(retarget_block),
        safe_block_height=safe_block.height,
        block_height_delta=proposed_block.height - safe_block.height,
        proposed_block=proposed_block,
        safe_block=safe_block,
        retarget_block=retarget_block,
        inner_block_hashes_hex=[compute_block_hash(block) for block in inner_blocks],
        inner_blocks=inner_blocks,
        confirmation_block_hashes_hex=[compute_block_hash(block) for block in confirmation_blocks],
        confirmation_blocks=confirmation_blocks,
        compilation_build_folder=BLOCK_VERIFICATION_DIR
    )

    # [3] build verification key, create proof, and verify proof
    vk = "./target/vk"
    print("Building verification key...")
    await build_raw_verification_key(vk, BLOCK_VERIFICATION_DIR, BB)
    print("Creating proof...")
    await create_proof(pub_inputs=12, vk_path=vk, compilation_dir=BLOCK_VERIFICATION_DIR, bb_binary=BB)
    print("Verifying proof...")
    await verify_proof(vk_path=vk, compilation_dir=BLOCK_VERIFICATION_DIR, bb_binary=BB)
    print(f"Proof with {num_inner_blocks + 1} total blocks verified!")


def main():
    # test single block
    # asyncio.run(test_single_block_verification_hardcoded()) 
    
    # test multiple blocks
    safe_block_height = 848524
    proposed_block_height = 848534
    retarget_height = 846720
    asyncio.run(test_multiple_blocks(proposed_block_height, safe_block_height, retarget_height))


if __name__ == "__main__":
    main()
