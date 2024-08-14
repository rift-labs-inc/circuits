import os
import sys
import asyncio
import json

import aiofiles

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.noir_lib import ensure_cache_is_current
from utils.rift_lib import (
    Block,
    build_giga_circuit_proof_and_input,
    LiquidityProvider,
)

async def test_historical_simple_payment_mainnet():
    print("Testing real triple payment on mainnet...")
    async with aiofiles.open("tests/mainnet_test_data.json", "r") as f:
        data = json.loads(await f.read())
    await build_giga_circuit_proof_and_input(
        txn_data_no_segwit_hex=data["txn_data_no_segwit_hex"],
        lp_reservations=list(map(lambda reservation: LiquidityProvider(**reservation),data["lp_reservations"])),
        proposed_block_header=Block(**data["proposed_block_header"]),
        safe_block_header=Block(**data["safe_block_header"]),
        retarget_block_header=Block(**data["retarget_block_header"]),
        inner_block_headers=list(map(lambda block: Block(**block), data["inner_block_headers"])),
        confirmation_block_headers=list(map(lambda block: Block(**block), data["confirmation_block_headers"])),
        order_nonce_hex=data["order_nonce"],
        expected_payout=data["expected_payout"],
        safe_block_height=data["safe_block_height"],
        block_height_delta=data["block_height_delta"],
        verify=True,
    )
        
    

def main():
    asyncio.run(ensure_cache_is_current())
    asyncio.run(test_historical_simple_payment_mainnet())


if __name__ == "__main__":
    main()
