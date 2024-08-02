import os
import asyncio
import json
import sys


from dotenv import load_dotenv
from bitcoin.wallet import CBitcoinSecret, P2WPKHBitcoinAddress
from bitcoin.core.script import CScript, OP_0, CScriptOp, SignatureHash, SIGHASH_ALL, SIGVERSION_WITNESS_V0
from bitcoin.core import b2x, b2lx, lx, COIN, COutPoint, CTxOut, CTxIn, CTxInWitness, CTxWitness, CScriptWitness, CMutableTransaction, Hash160, CTransaction
from bitcoin import SelectParams
from pydantic import BaseModel
import httpx


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from .rift_lib import CONFIRMATION_BLOCK_DELTA, Block
from .noir_lib import normalize_hex_str



load_dotenv()

# DEPRECATE


async def fetch_block_data_mainnet_public(height: int):
    url = f"https://chain.api.btc.com/v3/block/{height}"
    timeout = httpx.Timeout(10.0, read=20.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.get(url)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success' and 'data' in data:
                block_data = data['data']
                return Block(
                    height=block_data['height'],
                    version=block_data['version'],
                    prev_block_hash=block_data['prev_block_hash'],
                    merkle_root=block_data['mrkl_root'],
                    timestamp=block_data['timestamp'],
                    bits=block_data['bits'],
                    nonce=block_data['nonce'],
                    txns=[]
                )
            else:
                raise Exception(
                    f"API returned an error for height {height}: {data.get('message', 'No message')}")
        else:
            raise Exception(
                f"Failed to fetch block data for height {height}, HTTP status {response.status_code}")


# DEPRECATE
async def fetch_initial_block_input_mainnet_public(proposed_block_height: int, safe_block_height: int):
    retarget_height = proposed_block_height - (proposed_block_height % 2016)
    print(
        f"Fetching {proposed_block_height - safe_block_height + 1} block(s) from height {safe_block_height} to {proposed_block_height}...")
    blocks = await asyncio.gather(*[
        fetch_block_data_mainnet_public(height) for height in range(safe_block_height, proposed_block_height+1)
    ])

    retarget_block = await fetch_block_data_mainnet_public(retarget_height)

    return blocks, retarget_block


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

class RiftBitcoinData(BaseModel):
    txn_data_no_segwit_hex: str
    proposed_block_header: Block
    safe_block_header: Block
    retarget_block_header: Block
    inner_block_headers: list[Block]
    confirmation_block_headers: list[Block]
    block_height_delta: int

# Uses an bitcoin rpc client to fetch block data, close to prod impl


async def get_rift_btc_data(proposed_block_height: int, safe_block_height: int, txid: str, mainnet: bool = True) -> RiftBitcoinData:
    # use bitcoin lib to fetch block Data
    SelectParams("mainnet" if mainnet else "testnet")
    rpc_url = get_rpc(mainnet)
    retarget_height = proposed_block_height - (proposed_block_height % 2016)
    num_inner_blocks = proposed_block_height - safe_block_height

    proposed_block_hash, safe_block_hash, retarget_block_hash = await asyncio.gather(*[
        fetch_block_hash(proposed_block_height, rpc_url),
        fetch_block_hash(safe_block_height, rpc_url),
        fetch_block_hash(retarget_height, rpc_url)
    ])

    async def fetch_confirmation_blocks():
        height_list = [height for height in range(proposed_block_height+1, proposed_block_height+CONFIRMATION_BLOCK_DELTA+1)]
        block_hashes = await asyncio.gather(*[
            fetch_block_hash(height, rpc_url)
            for height in height_list
        ])
        return await asyncio.gather(*[
            fetch_block_data(block_hash, height_list[i], rpc_url) for i, block_hash in enumerate(block_hashes)])

    async def fetch_inner_blocks():
        height_list = [height for height in range(safe_block_height + 1, safe_block_height + num_inner_blocks)]
        block_hashes = await asyncio.gather(*[
            fetch_block_hash(height, rpc_url)
            for height in height_list
        ])
        return await asyncio.gather(*[
            fetch_block_data(block_hash, height_list[i], rpc_url) for i, block_hash in enumerate(block_hashes)])

    # TODO: Use semaphore to limit the number of requests made at once, or use self hosted btc node
    # quicknode rate limit prevents us from throwing all requests in this gather, also why we have sleeps
    proposed_block, safe_block, retarget_block, serialized_txn = await asyncio.gather(*[
        fetch_block_data(proposed_block_hash, proposed_block_height, rpc_url),
        fetch_block_data(safe_block_hash, safe_block_height, rpc_url),
        fetch_block_data(retarget_block_hash, retarget_height, rpc_url),
        fetch_transaction_data_in_block(txid, proposed_block_hash, rpc_url)
    ])
    await asyncio.sleep(1)
    inner_blocks = await fetch_inner_blocks()
    await asyncio.sleep(1)
    confirmation_blocks = await fetch_confirmation_blocks()

    deserialized_txn = CTransaction.deserialize(bytes.fromhex(serialized_txn))
    txn_data_no_segwit_hex = CTransaction(deserialized_txn.vin, deserialized_txn.vout, deserialized_txn.nLockTime, deserialized_txn.nVersion).serialize().hex()

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

