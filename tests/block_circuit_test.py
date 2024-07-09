import os
import sys
import asyncio

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.rift_lib import build_recursive_block_proof_and_input
from utils.btc_data import fetch_initial_block_input_mainnet_public

async def test_multiple_blocks(proposed_block_height: int, safe_block_height: int, retarget_height: int):
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


def main():
    safe_block_height = 848524
    proposed_block_height = 848534
    retarget_height = 846720
    asyncio.run(test_multiple_blocks(proposed_block_height,
                safe_block_height, retarget_height))


if __name__ == "__main__":
    main()
