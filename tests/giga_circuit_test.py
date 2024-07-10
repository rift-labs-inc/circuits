import os
import sys
import asyncio

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.rift_lib import (
    build_giga_circuit_proof_and_input,
    LiquidityProvider,
)
from utils.btc_data import fetch_block_data_mainnet_public



"""
funnction that takes proposed_block_height: int, safe_block_height: int, txn_hash: str, as input
returns:
    - txn_data_no_segwit_hex: str
    - proposed_block_txn_hashes: List[str]
    - proposed_block_header: Block
    - safe_block_header: Block
    - retarget_block_header: Block
    - inner_block_headers: List[Block]
    - confirmation_block_headers: List[Block]
    - block_height_delta: int


"""

async def test_real_simple_payment_testnet():
    print("Testing real simple payment on testnet...")
    lp = LiquidityProvider(amount=100, btc_exchange_rate=1000, locking_script_hex="0x0014841b80d2cc75f5345c482af96294d04fdd66b2b7")
    # create empty parameters with no values for now
    await build_giga_circuit_proof_and_input(
        txn_data_no_segwit_hex=,
        lp_reservations=,
        proposed_block_txn_hashes=,
        proposed_block_header=,
        safe_block_header=,
        retarget_block_header=,
        inner_block_headers=,
        confirmation_block_headers=,
        order_nonce_hex=,
        expected_payout=,
        safe_block_height=,
        block_height_delta=
    )

def main():
    asyncio.run(test_real_simple_payment_testnet())


if __name__ == "__main__":
    main()
