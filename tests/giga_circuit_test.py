import os
import sys
import asyncio
import json

import aiofiles

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.btc_data import get_rift_btc_data
from utils.noir_lib import ensure_cache_is_current
from utils.rift_lib import (
    Block,
    build_giga_circuit_proof_and_input,
    LiquidityProvider,
)

async def test_historical_simple_payment_mainnet():
    print("Testing real triple payment on mainnet...")
    txn_data_no_segwit_hex = "01000000017e731f6f6b8bebb0aee8857518cd83ec6b5edd96bf9bd52012c4615d66a535452600000000fdffffff05e70100000000000016001463dff5f8da08ca226ba01f59722c62ad9b9b3eaae701000000000000160014aa86191235be8883693452cf30daf854035b085be7010000000000001600146ab8f6c80b8a7dc1b90f7deb80e9b59ae16b7a5a0000000000000000226a20e9dda4b8016dc1e3e5ec7a19be6b2cdaaa8b50eef550c6c7343724849bf772a454fa0000000000001600148832d5cbd2c2b8d7600d93dfb1830853e5143e6d00000000"
    lp_reservations = [
        LiquidityProvider(**{"amount": 100000000000000, "btc_exchange_rate": 205000000000, "locking_script_hex": "001463dff5f8da08ca226ba01f59722c62ad9b9b3eaa"}),
        LiquidityProvider(**{"amount": 100000000000000, "btc_exchange_rate": 205000000000, "locking_script_hex": "0014aa86191235be8883693452cf30daf854035b085b"}),
        LiquidityProvider(**{"amount": 100000000000000, "btc_exchange_rate": 205000000000, "locking_script_hex": "00146ab8f6c80b8a7dc1b90f7deb80e9b59ae16b7a5a"})
    ]
    order_nonce = "e9dda4b8016dc1e3e5ec7a19be6b2cdaaa8b50eef550c6c7343724849bf772a4"
    expected_payout = 299505000000000
    proposed_block_height = 854136
    safe_block_height = 854133
    block_data = await get_rift_btc_data(
        proposed_block_height=proposed_block_height,
        safe_block_height=safe_block_height,
    )

    blocks = [block_data.safe_block_header, *block_data.inner_block_headers, block_data.proposed_block_header, *block_data.confirmation_block_headers]

    await build_giga_circuit_proof_and_input(
        txn_data_no_segwit_hex=txn_data_no_segwit_hex,
        lp_reservations=lp_reservations,
        retarget_block_header=block_data.retarget_block_header,
        blocks=blocks,
        safe_block_height=block_data.safe_block_header.height,
        safe_block_height_delta=block_data.block_height_delta,
        order_nonce_hex=order_nonce,
        expected_payout=expected_payout,
        verify=True,
    )
        

def main():
    asyncio.run(ensure_cache_is_current())
    asyncio.run(test_historical_simple_payment_mainnet())


if __name__ == "__main__":
    main()
