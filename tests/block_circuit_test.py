import os
import time
import sys
import asyncio
import tempfile

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.noir_lib import build_raw_verification_key, compile_project, ensure_cache_is_current, extract_vk_as_fields
from utils.rift_lib import BB, Block, build_block_entrypoint_proof_and_input, build_block_pair_proof_input, build_block_proof_and_input
from utils.btc_data import get_rift_btc_data, fetch_block_from_height


async def build_and_verify_tree(proposed_height: int, safe_delta: int, test_name: str):
    print(f"Creating {test_name}...")
    print(f"{safe_delta} New Blocks")
    assert proposed_height - (proposed_height % 2016) == (proposed_height - safe_delta) - ((proposed_height - safe_delta) % 2016), "Safe + Proposed Retarget heights do not match"

    block_data = await get_rift_btc_data(
        proposed_block_height=proposed_height,
        safe_block_height=proposed_height - safe_delta,
    )
    


    blocks = [block_data.safe_block_header, *block_data.inner_block_headers, block_data.proposed_block_header]

    proof_start = time.time()
    proof_data = await build_block_proof_and_input(
        blocks=blocks,
        last_retarget_block=block_data.retarget_block_header,
        verify=True
    )
    proof_time = time.time() - proof_start
    
    print("Height", f"R{proof_data.height}")
    print(f"{test_name} proof built in {proof_time:.2f} seconds")

async def test_single_pair():
    proposed_height = 848534
    await build_block_pair_proof_input(
        block_1=(await get_rift_btc_data(proposed_block_height=proposed_height, safe_block_height=proposed_height - 1)).safe_block_header,
        block_2=(await get_rift_btc_data(proposed_block_height=proposed_height, safe_block_height=proposed_height - 1)).proposed_block_header,
        last_retarget_block=(await get_rift_btc_data(proposed_block_height=proposed_height, safe_block_height=proposed_height - 1)).retarget_block_header,
        verify=True
    )
    print("Single pair proof built")


async def run_exhaustive_test():
    target_delta = 90
    for i in range(1, target_delta + 1):
        await build_and_verify_tree(847000, i, f"{i} Block Delta Tree")


async def test_specific_tree(delta: int):
    await build_and_verify_tree(846000, delta, f"{delta} Block Delta Tree")

async def run_tests():
    tests = [
        (848534, 2),
        (848534, 3),
        (848534, 4),
        (848534, 5),
        (847000, 90),
    ]
    
    for proposed_height, safe_delta in tests:
        await build_and_verify_tree(proposed_height, safe_delta, f"{safe_delta} Block Delta Tree")

    #await test_single_pair()

def main():
    asyncio.run(ensure_cache_is_current())
    asyncio.run(test_specific_tree(400))

if __name__ == "__main__":
    main()
