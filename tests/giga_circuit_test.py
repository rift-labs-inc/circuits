import os
import hashlib
import sys
import asyncio

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.proxy_wallet import get_secondary_testnet_wallets
from utils.rift_lib import (
    build_giga_circuit_proof_and_input,
    LiquidityProvider,
)
from utils.btc_data import fetch_block_data_mainnet_public, get_rift_btc_data



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

async def test_historical_simple_payment_testnet():
    print("Testing real simple payment on testnet...")
    order_nonce = hashlib.sha256(b"rift").hexdigest()

    lps = [
        LiquidityProvider(amount=1000000, btc_exchange_rate=1, locking_script_hex='00145a56436f3106b12a7e25df0b2facbc334ea6de5f'),
        LiquidityProvider(amount=1000000, btc_exchange_rate=1, locking_script_hex='00140e9e91b8531fceb498204d17ef8d088ee0fa8d7a'),
        LiquidityProvider(amount=1000000, btc_exchange_rate=1, locking_script_hex='00140c2eed55791ba08075baa9203dc89a12da2e0b3d'),
        LiquidityProvider(amount=1000000, btc_exchange_rate=1, locking_script_hex='001441d5b79bf267c92aa387b99f4aa71cd88cb72a44'),
        LiquidityProvider(amount=1000000, btc_exchange_rate=1, locking_script_hex='0014911a98c4e8ffc4f9f306402ac180ccbf4eba9d94'),
        LiquidityProvider(amount=1000000, btc_exchange_rate=1, locking_script_hex='0014193f1ba0362901bd02fe7f750af4b71c4c07dbd8'),
        LiquidityProvider(amount=1000000, btc_exchange_rate=1, locking_script_hex='00140aa437977cb2d9992342ffa445dd08c216e6dee2'),
        LiquidityProvider(amount=1000000, btc_exchange_rate=1, locking_script_hex='0014f9f3a59d86bfc7849d1bcff2ecea69c4820fa047'),
        LiquidityProvider(amount=1000000, btc_exchange_rate=1, locking_script_hex='0014c3198a9fddf935a49ff80bae5229d5dba079cae3'),
        LiquidityProvider(amount=1000000, btc_exchange_rate=1, locking_script_hex='0014802903cc08b1df3f445c11c7f19c2cd92f907e81')
    ]

    safe_block_height = 2867340

    rift_bitcoin_data = await get_rift_btc_data(
        proposed_block_height=2867341,
        safe_block_height=2867340,
        txid="6718c0391fc4cc0d2170bc99bdcfc6e57deafe08acc1f2ba6387371b85982a02",
        mainnet=False
    )

    await build_giga_circuit_proof_and_input(
        txn_data_no_segwit_hex=rift_bitcoin_data.txn_data_no_segwit_hex,
        lp_reservations=lps,
        proposed_block_header=rift_bitcoin_data.proposed_block_header,
        safe_block_header=rift_bitcoin_data.safe_block_header,
        retarget_block_header=rift_bitcoin_data.retarget_block_header,
        inner_block_headers=rift_bitcoin_data.inner_block_headers,
        confirmation_block_headers=rift_bitcoin_data.confirmation_block_headers,
        order_nonce_hex=order_nonce,
        expected_payout=sum(lp.amount for lp in lps),
        safe_block_height=safe_block_height,
        block_height_delta=rift_bitcoin_data.block_height_delta
    )

def main():
    asyncio.run(test_historical_simple_payment_testnet())


if __name__ == "__main__":
    main()
