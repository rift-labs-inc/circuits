import os
import sys
import asyncio
import tempfile

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.noir_lib import build_raw_verification_key, compile_project, extract_vk_as_fields
from utils.rift_lib import BB, build_block_pair_proof_input, build_block_proof_and_input
from utils.btc_data import fetch_initial_block_input_mainnet_public, get_rift_btc_data


"""
async def test_multiple_blocks():
    safe_block_height = 848524
    proposed_block_height = 848534
    retarget_height = 846720
    print("Test multiple blocks...")
    proposed_block, safe_block, retarget_block, inner_blocks, confirmation_blocks = await fetch_initial_block_input_mainnet_public(
        proposed_block_height,
        safe_block_height,
        retarget_height
    )
    print("Block height delta:", proposed_block.height - safe_block.height)
    await build_recursive_block_proof_and_input(
        proposed_block,
        safe_block,
        retarget_block,
        inner_blocks,
        confirmation_blocks
    )

async def test_multiple_testnet_blocks_real_rpc():
    print("Test multiple testnet blocks...")
    rift_bitcoin_data = await get_rift_btc_data(
        proposed_block_height=2867344,
        safe_block_height=2867340,
        txid="2b50e917cef06971ef9a4143367e38e320ca326bba593f1f5b8714bf0e657a38",
        mainnet=False
    )
    await build_recursive_block_proof_and_input(
        rift_bitcoin_data.proposed_block_header,
        rift_bitcoin_data.safe_block_header,
        rift_bitcoin_data.retarget_block_header,
        rift_bitcoin_data.inner_block_headers,
        rift_bitcoin_data.confirmation_block_headers
    )
"""

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
    blocks, retarget_block = await fetch_initial_block_input_mainnet_public(
        proposed_block_height=proposed_height,
        safe_block_height=proposed_height - 1,
    )
    #print("Generating verification key...")
    #vkhash, vk = await get_recursive_block_tree_circuit_verification_key()
    
    print(await build_block_pair_proof_input(
        block_1=blocks[0],
        block_2=blocks[1],
        last_retarget_block=retarget_block,
    ))

async def create_simple_1_level_tree():
    print("Create Simple 1 Level Tree...")
    proposed_height = 848534
    safe_delta = 3
    print(f"{safe_delta} New Blocks")
    blocks, retarget_block = await fetch_initial_block_input_mainnet_public(
        proposed_block_height=proposed_height,
        safe_block_height=proposed_height - safe_delta,
    )

    print("Final proof", await build_block_proof_and_input(
        blocks=blocks,
        last_retarget_block=retarget_block
    ))


def main():
    #asyncio.run(test_single_pair())
    asyncio.run(create_simple_1_level_tree())


if __name__ == "__main__":
    main()
