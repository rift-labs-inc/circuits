import os
import asyncio
import json
import sys
from typing import Optional
import time


from dotenv import load_dotenv
from bitcoin.wallet import CBitcoinSecret, P2WPKHBitcoinAddress
from bitcoin.core.script import CScript, OP_0, CScriptOp, SignatureHash, SIGHASH_ALL, SIGVERSION_WITNESS_V0
from bitcoin.core import b2x, b2lx, lx, COIN, COutPoint, CTxOut, CTxIn, CTxInWitness, CTxWitness, CScriptWitness, CMutableTransaction, Hash160, CTransaction
from bitcoin import SelectParams
from pydantic import BaseModel
import httpx


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from .rift_lib import CONFIRMATION_BLOCK_DELTA, Block, file_cache
from .noir_lib import normalize_hex_str

load_dotenv()

MAX_REQUESTS_PER_SECOND = 5

class RateLimiter:
    def __init__(self, rate_limit):
        self.rate_limit = rate_limit
        self.tokens = rate_limit
        self.updated_at = time.monotonic()

    async def acquire(self):
        while True:
            now = time.monotonic()
            time_passed = now - self.updated_at
            self.tokens += time_passed * self.rate_limit
            if self.tokens > self.rate_limit:
                self.tokens = self.rate_limit
            self.updated_at = now

            if self.tokens >= 1:
                self.tokens -= 1
                return
            
            wait_time = (1 - self.tokens) / self.rate_limit
            await asyncio.sleep(wait_time)

class RiftBitcoinData(BaseModel):
    txn_data_no_segwit_hex: str | None 
    proposed_block_header: Block
    safe_block_header: Block
    retarget_block_header: Block
    inner_block_headers: list[Block]
    confirmation_block_headers: list[Block]
    block_height_delta: int

async def fetch_block_from_height(height: int, rpc_url: str):
    payload = json.dumps({
        "jsonrpc": "1.0",
        "id": "curltext",
        "method": "getblockhash",
        "params": [height]
    })

    headers = {
        'content-type': 'text/plain;',
    }

    async with httpx.AsyncClient() as client:
        # type:ignore
        response = await client.post(rpc_url, data=payload, headers=headers) #type:ignore
        if response.status_code == 200:
            block_hash = response.json()['result']
            return await fetch_block_data(block_hash, height, rpc_url)
        else:
            raise Exception(
                f"Failed to fetch block data: HTTP {response.status_code}, Response: {response.text}")


async def fetch_block_data(block_hash: str, height: int, rpc_url: str):
    payload = json.dumps({
        "jsonrpc": "1.0",
        "id": "curltext",
        "method": "getblock",
        "params": [block_hash, 1]
    })

    headers = {
        'content-type': 'text/plain;',
    }

    async with httpx.AsyncClient() as client:
        # type:ignore
        response = await client.post(rpc_url, data=payload, headers=headers) #type:ignore
        if response.status_code == 200:
            block_data = response.json()['result']
            return Block(
                height=height,
                version=block_data['version'],
                prev_block_hash=block_data['previousblockhash'],
                merkle_root=block_data['merkleroot'],
                timestamp=block_data['time'],
                bits=int.from_bytes(bytes.fromhex(normalize_hex_str(block_data['bits']))),
                nonce=block_data['nonce'],
                txns=block_data['tx']
            )
        else:
            raise Exception(
                f"Failed to fetch block data: HTTP {response.status_code}, Response: {response.text}")


async def fetch_block_hash(height: int, rpc_url: str) -> str:
    payload = json.dumps({
        "jsonrpc": "2.0",
        "id": "curltext",
        "method": "getblockhash",
        "params": [height]
    })

    headers = {
        'content-type': 'text/plain;',
    }

    async with httpx.AsyncClient() as client:
        # type:ignore
        response = await client.post(rpc_url, data=payload, headers=headers) #type:ignore
        if response.status_code == 200:
            block_hash = response.json()['result']
            return block_hash
        else:
            raise Exception(
                f"Failed to fetch block hash: HTTP {response.status_code}, Response: {response.text}")


async def fetch_transaction_data_in_block(txid: str, block_hash: str, rpc_url: str, verbose: bool = False):
    payload = json.dumps({
        "jsonrpc": "1.0",
        "id": "curltext",
        "method": "getrawtransaction",
        "params": [txid, verbose, block_hash]
    })

    headers = {
        'content-type': 'text/plain;',
    }

    async with httpx.AsyncClient() as client:
        # type:ignore
        response = await client.post(rpc_url, data=payload, headers=headers) #type:ignore
        if response.status_code == 200:
            txn_data = response.json()['result']
            return txn_data
        else:
            raise Exception(
                f"Failed to fetch txn data: HTTP {response.status_code}, Response: {response.text}")

async def fetch_utxo_status(txid: str, vout: int, rpc_url: str):
    payload = json.dumps({
        "jsonrpc": "1.0",
        "id": "curltext",
        "method": "gettxout",
        "params": [txid, vout]
    })

    headers = {
        'content-type': 'text/plain;',
    }

    async with httpx.AsyncClient() as client:
        # type:ignore
        response = await client.post(rpc_url, data=payload, headers=headers) #type:ignore
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(
                f"Failed to fetch utxo status: HTTP {response.status_code}, Response: {response.text}")


async def broadcast_transaction(tx_hex: str, rpc_url: str):
    payload = json.dumps({
        "jsonrpc": "1.0",
        "id": "curltext",
        "method": "sendrawtransaction",
        "params": [tx_hex]
    })

    headers = {
        'content-type': 'text/plain;',
    }

    async with httpx.AsyncClient() as client:
        # type:ignore
        response = await client.post(rpc_url, data=payload, headers=headers) #type:ignore
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(
                f"Failed to broadcast txn: HTTP {response.status_code}, Response: {response.text}")


def get_rpc(mainnet: bool = True):
    return os.environ["MAINNET_BITCOIN_RPC"] if mainnet else os.environ["TESTNET_BITCOIN_RPC"]



# Uses an bitcoin rpc client to fetch block data, close to prod impl

@file_cache
async def get_rift_btc_data(proposed_block_height: int, safe_block_height: int, confirmation_block_delta: int = 5, txid: Optional[str] = None, mainnet: bool = True) -> RiftBitcoinData:
    SelectParams("mainnet" if mainnet else "testnet")
    rpc_url = get_rpc(mainnet)
    retarget_height = proposed_block_height - (proposed_block_height % 2016)
    num_inner_blocks = proposed_block_height - safe_block_height

    # Create a rate limiter
    rate_limiter = RateLimiter(MAX_REQUESTS_PER_SECOND)

    async def fetch_with_rate_limit(coro):
        await rate_limiter.acquire()
        return await coro

    proposed_block_hash, safe_block_hash, retarget_block_hash = await asyncio.gather(*[
        fetch_with_rate_limit(fetch_block_hash(height, rpc_url))
        for height in [proposed_block_height, safe_block_height, retarget_height]
    ])

    async def fetch_blocks(start_height, count):
        height_list = range(start_height, start_height + count)
        block_hashes = await asyncio.gather(*[
            fetch_with_rate_limit(fetch_block_hash(height, rpc_url))
            for height in height_list
        ])
        return await asyncio.gather(*[
            fetch_with_rate_limit(fetch_block_data(block_hash, height, rpc_url))
            for height, block_hash in zip(height_list, block_hashes)
        ])

    coros = [
        fetch_with_rate_limit(fetch_block_data(proposed_block_hash, proposed_block_height, rpc_url)),
        fetch_with_rate_limit(fetch_block_data(safe_block_hash, safe_block_height, rpc_url)),
        fetch_with_rate_limit(fetch_block_data(retarget_block_hash, retarget_height, rpc_url)),
    ]

    if txid:
        coros.append(fetch_with_rate_limit(fetch_transaction_data_in_block(txid, proposed_block_hash, rpc_url)))

    data = await asyncio.gather(*coros)

    if txid:
        proposed_block, safe_block, retarget_block, serialized_txn = data
        deserialized_txn = CTransaction.deserialize(bytes.fromhex(str(serialized_txn)))
        txn_data_no_segwit_hex = CTransaction(deserialized_txn.vin, deserialized_txn.vout, deserialized_txn.nLockTime, deserialized_txn.nVersion).serialize().hex()
    else:
        proposed_block, safe_block, retarget_block = data
        txn_data_no_segwit_hex = None

    inner_blocks = await fetch_blocks(safe_block_height + 1, num_inner_blocks - 1)
    confirmation_blocks = await fetch_blocks(proposed_block_height + 1, confirmation_block_delta)

    return RiftBitcoinData(
        txn_data_no_segwit_hex=txn_data_no_segwit_hex,
        proposed_block_header=proposed_block,
        safe_block_header=safe_block,
        retarget_block_header=retarget_block,
        inner_block_headers=inner_blocks,
        confirmation_block_headers=confirmation_blocks,
        block_height_delta=num_inner_blocks
    )


if __name__ == "__main__":
    with open("demo_file.json", "w") as f:
        f.write(asyncio.run(get_rift_btc_data(
            proposed_block_height=2867121,
            safe_block_height=2867120,
            txid="cb1ed6a0f714d858325d139431a5b9ffd48d0402107f4ce41d00db34df473036",
            mainnet=False
        )).model_dump_json())

