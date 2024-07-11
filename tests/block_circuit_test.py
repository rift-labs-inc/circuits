import os
import sys
import asyncio

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.rift_lib import build_recursive_block_proof_and_input
from utils.btc_data import fetch_initial_block_input_mainnet_public, get_rift_btc_data

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



def main():
    asyncio.run(test_multiple_blocks())
    asyncio.run(test_multiple_testnet_blocks_real_rpc())


if __name__ == "__main__":
    main()
