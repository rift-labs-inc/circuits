import os
import sys
import asyncio
import tempfile

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.noir_lib import build_raw_verification_key, compile_project, extract_vk_as_fields
from utils.rift_lib import BB, Block, build_block_entrypoint_proof_and_input, build_block_pair_proof_input, build_block_proof_and_input
from utils.btc_data import get_rift_btc_data, fetch_block_from_height

async def get_recursive_block_tree_circuit_verification_key():
    compilation_dir = "circuits/block_verification/recursive_block_tree"
    vk = tempfile.NamedTemporaryFile()
    await compile_project(compilation_dir)
    await build_raw_verification_key(vk.name, compilation_dir, BB)
    vk_data = await extract_vk_as_fields(vk.name, compilation_dir, BB)
    return vk_data[0], vk_data[1:]

async def test_single_pair():
    print("Test single pair...")
    proposed_height = 848534
    block_data = await get_rift_btc_data(
        proposed_block_height=proposed_height,
        safe_block_height=proposed_height - 1,
    )
    #print("Generating verification key...")
    #vkhash, vk = await get_recursive_block_tree_circuit_verification_key()
    
    await build_block_pair_proof_input(
        block_1=block_data.safe_block_header,
        block_2=block_data.proposed_block_header,
        last_retarget_block=block_data.retarget_block_header,
        verify=True
    )
    print("Single pair proof built")

async def create_simple_1_level_tree():
    print("Create Simple 1 Level Tree...")
    proposed_height = 848534
    safe_delta = 2
    print(f"{safe_delta} New Blocks")
    block_data = await get_rift_btc_data(
        proposed_block_height=proposed_height,
        safe_block_height=proposed_height - safe_delta,
    )
    blocks = [block_data.safe_block_header, *block_data.inner_block_headers, block_data.proposed_block_header]

    proof_data = await build_block_proof_and_input(
        blocks=blocks,
        last_retarget_block=block_data.retarget_block_header,
        verify=True
    )
    print("Height", f"R{proof_data.height}")
    print("Simple 1 Level Tree proof built")

async def create_imbalanced_2_level_tree():
    print("Create Imbalanced 2 Level Tree...")
    proposed_height = 848534
    safe_delta = 3
    print(f"{safe_delta} New Blocks")
    block_data = await get_rift_btc_data(
        proposed_block_height=proposed_height,
        safe_block_height=proposed_height - safe_delta,
    )
    blocks = [block_data.safe_block_header, *block_data.inner_block_headers, block_data.proposed_block_header]

    proof_data = await build_block_proof_and_input(
        blocks=blocks,
        last_retarget_block=block_data.retarget_block_header,
        verify=True
    )
    print("Height", f"R{proof_data.height}")
    print("Imbalanced 2 Level Tree proof built")

async def create_balanced_2_level_tree():
    print("Create Balanced 2 Level Tree...")
    proposed_height = 848534
    safe_delta = 4
    print(f"{safe_delta} New Blocks")
    block_data = await get_rift_btc_data(
        proposed_block_height=proposed_height,
        safe_block_height=proposed_height - safe_delta,
    )
    blocks = [block_data.safe_block_header, *block_data.inner_block_headers, block_data.proposed_block_header]

    proof_data = await build_block_proof_and_input(
        blocks=blocks,
        last_retarget_block=block_data.retarget_block_header,
        verify=True
    )
    print("Height", f"R{proof_data.height}")
    print("Balance 2 Level Tree proof built")

async def create_imbalanced_3_level_tree():
    print("Create Imbalanced 3 Level Tree...")
    proposed_height = 848534
    safe_delta = 5
    print(f"{safe_delta} New Blocks")
    block_data = await get_rift_btc_data(
        proposed_block_height=proposed_height,
        safe_block_height=proposed_height - safe_delta,
    )
    blocks = [block_data.safe_block_header, *block_data.inner_block_headers, block_data.proposed_block_header]

    proof_data = await build_block_proof_and_input(
        blocks=blocks,
        last_retarget_block=block_data.retarget_block_header,
        verify=True
    )
    print("Height", f"R{proof_data.height}")
    print("Imbalanced 3 Level Tree proof built")

async def prove_1_block_entrypoint():
    print("Prove [1] Block Entrypoint...")
    proposed_height = 848534
    safe_delta = 1
    confirmation_block_delta = 5
    print(f"{safe_delta} New Blocks")
    block_data = await get_rift_btc_data(
        proposed_block_height=proposed_height,
        safe_block_height=proposed_height - safe_delta,
    )
    blocks = [block_data.safe_block_header, *block_data.inner_block_headers, block_data.proposed_block_header, *block_data.confirmation_block_headers]
    print("Blocks", [print(Block(height=block.height, version=block.version, prev_block_hash=block.prev_block_hash, merkle_root=block.merkle_root, timestamp=block.timestamp, bits=block.bits, nonce=block.nonce, txns=[])) for block in blocks])
    await build_block_entrypoint_proof_and_input(
        safe_block_height=proposed_height - safe_delta,
        safe_block_height_delta=safe_delta,
        blocks=blocks,
        last_retarget_block=block_data.retarget_block_header,
        verify=True
    )
    print("1 Block Entrypoint proof built")


def main():
    #asyncio.run(test_single_pair())
    #asyncio.run(create_simple_1_level_tree())
    #asyncio.run(create_imbalanced_2_level_tree())
    #asyncio.run(create_balanced_2_level_tree())
    asyncio.run(create_imbalanced_3_level_tree())
    #asyncio.run(prove_1_block_entrypoint())


if __name__ == "__main__":
    main()
