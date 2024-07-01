import os
import sys
import asyncio

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.fetch_block_data import fetch_block_data
from utils.rift_lib import create_prover_toml_witness, Block, compute_block_hash
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

async def test_single_block_verification_hardcoded():
    # [0] compile project folder
    BLOCK_VERIFICATION_DIR = "circuits/block_verification"
    BB = "~/.nargo/backends/acvm-backend-barretenberg/backend_binary"
    print("Compiling block verification circuit...")
    await compile_project(BLOCK_VERIFICATION_DIR)

    # [1] create prover toml and witness
    proposed_block = Block(
        height=848525,
        version=536870912,
        prev_block_hash="0000000000000000000116072c747a36de1e104cef399dd388c36dd1cf7fd4ec",
        merkle_root="450a32c0f61ce7155893f9a6ba5d44db2c6124c3a11ff01c071a22b02ee96aa4",
        timestamp=1718745344,
        bits=386096312,
        nonce=1913798735
    )

    safe_block = Block(
        height=848524,
        version=768548864,
        prev_block_hash="000000000000000000002b338c518fa4970e11b7365915934bad79b0210b800e",
        merkle_root="c09758b50aa04c688b45d2284f100ec798fa3d8605af928093d9b84d046be1bc",
        timestamp=1718742499,
        bits=386096312,
        nonce=4279523078
    )

    retarget_block = Block(
        height=846720,
        version=538222592,
        prev_block_hash="0000000000000000000132f5df736574a143d1e41e1a0cdb9c7d1656a906124c",
        merkle_root="feac8899c7090cd12aaca0c5fb3f5f33ad1e5935934db150bd0f5a7e84aff439",
        timestamp=1717664663,
        bits=386096312,
        nonce=1595975252
    )
    
    await create_prover_toml_witness(
        proposed_block_hash_hex=compute_block_hash(proposed_block),
        safe_block_hash_hex=compute_block_hash(safe_block),
        retarget_block_hash_hex=compute_block_hash(retarget_block),
        safe_block_height=safe_block.height,
        block_height_delta=proposed_block.height - safe_block.height,
        proposed_block=proposed_block,
        safe_block=safe_block,
        retarget_block=retarget_block,
        inner_block_hashes_hex=[],
        inner_blocks=[],
        compilation_build_folder=BLOCK_VERIFICATION_DIR
    )

    # [2] build verification key, create proof, and verify proof
    vk = "./target/vk"
    print("Building verification key...")
    await build_raw_verification_key(vk, BLOCK_VERIFICATION_DIR, BB)
    print("Creating proof...")
    await create_proof(pub_inputs=8, vk_path=vk, compilation_dir=BLOCK_VERIFICATION_DIR, bb_binary=BB)
    print("Verifying proof...")
    await verify_proof(vk_path=vk, compilation_dir=BLOCK_VERIFICATION_DIR, bb_binary=BB)
    print("Verified proof!")


async def test_multiple_blocks(safe_block_height: int, retarget_height: int, num_inner_blocks: int):
    # [0] compile project folder
    BLOCK_VERIFICATION_DIR = "circuits/block_verification"
    BB = "~/.nargo/backends/acvm-backend-barretenberg/backend_binary"
    print("Compiling block verification circuit...")
    await compile_project(BLOCK_VERIFICATION_DIR)

    # [1] fetch block data
    print(f"Fetching block data from height {safe_block_height + 1} to {safe_block_height + 1 + num_inner_blocks}...")
    inner_blocks = []
    for height in range(safe_block_height + 1, safe_block_height + 1 + num_inner_blocks):
        block = await fetch_block_data(height)
        inner_blocks.append(block)

    if not inner_blocks:
        print("No inner blocks to process.")
        return

    retarget_block = await fetch_block_data(retarget_height)
    safe_block = await fetch_block_data(safe_block_height)
    proposed_block = await fetch_block_data(inner_blocks[-1].height + 1)

    # [2] create prover toml and witness
    print("Creating prover toml and witness...")
    await create_prover_toml_witness(
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
        compilation_build_folder=BLOCK_VERIFICATION_DIR
    )

    # [3] build verification key, create proof, and verify proof
    vk = "./target/vk"
    print("Building verification key...")
    await build_raw_verification_key(vk, BLOCK_VERIFICATION_DIR, BB)
    print("Creating proof...")
    await create_proof(pub_inputs=8, vk_path=vk, compilation_dir=BLOCK_VERIFICATION_DIR, bb_binary=BB)
    print("Verifying proof...")
    await verify_proof(vk_path=vk, compilation_dir=BLOCK_VERIFICATION_DIR, bb_binary=BB)
    print(f"Proof with {num_inner_blocks + 1} total blocks verified!")


def main():
    # test single block
    # asyncio.run(test_single_block_verification_hardcoded()) 
    
    # test multiple blocks
    safe_block_height = 848524
    retarget_height = 846720
    num_inner_blocks = 29
    asyncio.run(test_multiple_blocks(safe_block_height, retarget_height, num_inner_blocks))


if __name__ == "__main__":
    main()
