import os
import time
import sys
import asyncio
import tempfile

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.noir_lib import build_raw_verification_key, compile_project, ensure_cache_is_current, extract_vk_as_fields
from utils.rift_lib import BB, Block, build_block_base_proof_and_input, build_block_proof_and_input
from utils.btc_data import get_rift_btc_data, fetch_block_from_height


async def _test_base_block_proof(proposed_height: int, safe_delta: int, test_name: str):
    print(f"Creating {test_name}...")
    print(f"{safe_delta} New Blocks")
    assert proposed_height - (proposed_height % 2016) == (proposed_height - safe_delta) - ((proposed_height - safe_delta) % 2016), "Safe + Proposed Retarget heights do not match"

    block_data = await get_rift_btc_data(
        proposed_block_height=proposed_height,
        safe_block_height=proposed_height - safe_delta,
    )
    

    blocks = [block_data.safe_block_header, *block_data.inner_block_headers, block_data.proposed_block_header]

    proof_start = time.time()
    proof_data = await build_block_base_proof_and_input(
        blocks=blocks,
        last_retarget_block=block_data.retarget_block_header,
        verify=True
    )
    proof_time = time.time() - proof_start
    
    print(f"{test_name} proof built in {proof_time:.2f} seconds")


async def test_entrypoint_proof():
    safe_delta = 100
    proposed_height = 848500
    block_data = await get_rift_btc_data(
        proposed_block_height=proposed_height,
        safe_block_height=proposed_height - safe_delta,
    )

    blocks = [
        block_data.safe_block_header,
        *block_data.inner_block_headers,
        block_data.proposed_block_header,
        *block_data.confirmation_block_headers,
    ]
    print("Total Blocks", len(blocks))

    await build_block_proof_and_input(
        blocks=blocks,
        safe_block_height_delta=safe_delta,
        last_retarget_block=block_data.retarget_block_header,
        verify=True
    )

    print("Entrypoint proof built")


async def test_base_block_proof_cases():
    await _test_base_block_proof(
        proposed_height=848500,
        safe_delta=89,
        test_name="Case 1"
    )


def main():
    #asyncio.run(ensure_cache_is_current())
    asyncio.run(test_entrypoint_proof())

if __name__ == "__main__":
    main()
