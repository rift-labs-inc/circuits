import os
import sys
import asyncio

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.rift_lib import (
    build_recursive_lp_hash_proof_and_input,
    LiquidityProvider,
)
from utils.fetch_block_data import fetch_block_data


async def test_single_lp():
    print("Testing Single LP...")
    lp = LiquidityProvider(amount=100, btc_exchange_rate=1000,
                           locking_script_hex="0x0014841b80d2cc75f5345c482af96294d04fdd66b2b7")
    await build_recursive_lp_hash_proof_and_input([lp])


# write a function that will test multiple lps
async def test_multiple_lps():
    print("Testing multiple liquidity providers...")
    print("Creating prover toml and witness...")
    liquidity_providers = [
        LiquidityProvider(amount=100, btc_exchange_rate=1000,
                          locking_script_hex="0x0014841b80d2cc75f5345c48baf96294d04fdd66b2b7"),
        LiquidityProvider(amount=200, btc_exchange_rate=1000,
                          locking_script_hex="0x0014841b80d2cc75f5345cd82af96294d04fdd66b2b1"),
        LiquidityProvider(amount=300, btc_exchange_rate=2020,
                          locking_script_hex="0x0014841b80d2cc75c5345c482af96294d04fdd66b2b1"),
        LiquidityProvider(amount=200, btc_exchange_rate=2200,
                          locking_script_hex="0x0014841b80d2ca75f5345c482af96294d04fdd66b2b1"),
        LiquidityProvider(amount=100, btc_exchange_rate=2004,
                          locking_script_hex="0x0024841b80d2cc75f5345c482af96294d04fdd66b2b1")
    ]

    await build_recursive_lp_hash_proof_and_input(liquidity_providers)


def main():
    asyncio.run(test_single_lp())
    asyncio.run(test_multiple_lps())


if __name__ == "__main__":
    main()
