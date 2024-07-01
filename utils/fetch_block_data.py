import httpx
from utils.rift_lib import Block

async def fetch_block_data(height: int):
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
