import httpx
import asyncio

from pydantic import BaseModel
from utils.rift_lib import Block

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
                    nonce=block_data['nonce']
                )
            else:
                raise Exception(f"API returned an error for height {height}: {data.get('message', 'No message')}")
        else:
            raise Exception(f"Failed to fetch block data for height {height}, HTTP status {response.status_code}")


# DEPRECATE
async def fetch_initial_block_input_mainnet_public(proposed_block_height: int, safe_block_height: int, retarget_height: int):
    num_inner_blocks = proposed_block_height - safe_block_height
    print(f"Fetching block data from height {safe_block_height + 1} to {safe_block_height + num_inner_blocks}...")
    inner_blocks = await asyncio.gather(*[
        fetch_block_data_mainnet_public(height) for height in range(safe_block_height + 1, safe_block_height + num_inner_blocks)])

    print(f"Fetching block data from height {proposed_block_height+1} to {proposed_block_height + 7}...")
    confirmation_blocks = await asyncio.gather(*[
        fetch_block_data_mainnet_public(height) for height in range(proposed_block_height+1, proposed_block_height+7)])
    if not inner_blocks or not confirmation_blocks:
        raise Exception("No inner blocks to process.")

    retarget_block = await fetch_block_data_mainnet_public(retarget_height)
    safe_block = await fetch_block_data_mainnet_public(safe_block_height)
    proposed_block = await fetch_block_data_mainnet_public(proposed_block_height)

    return proposed_block, safe_block, retarget_block, inner_blocks, confirmation_blocks



class RiftBlockData(BaseModel):
    txn_data_no_segwit_hex: str
    proposed_block_txn_hashes: list[str]
    proposed_block_header: Block
    safe_block_header: Block
    retarget_block_header: Block
    inner_block_headers: list[Block]
    confirmation_block_headers: list[Block]
    block_height_delta: int


# Uses an bitcoin rpc client to fetch block data, close to prod impl
async def fetch_rift_btc_data(proposed_block_height: int, safe_block_height: int, txn_hash: str, rpc_url: str):
    proposed_block, safe_block, retarget_block, inner_blocks, confirmation_blocks = await fetch_initial_block_input(
        proposed_block_height,
        safe_block_height,
        safe_block_height - 2016
    )
    proposed_block_txn_hashes = [txn_hash]
    return proposed_block, safe_block, retarget_block, inner_blocks, confirmation_blocks, proposed_block_txn_hashes
