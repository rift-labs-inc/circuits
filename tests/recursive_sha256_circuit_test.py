import os
import sys
import traceback
import asyncio
import math
import hashlib
import time
import multiprocessing
import psutil
from typing import Any
import aiofiles
import json


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.fetch_block_data import fetch_block_data
from utils.rift_lib import (
    MAX_ENCODED_CHUNKS,
    Block,
    build_recursive_sha256_proof_and_input,
    compute_block_hash,
    BB,
    create_recursive_sha_witness,
    extract_cached_recursive_sha_vkey_data,
    initialize_recursive_sha_build_folder,
    load_recursive_sha_circuit
)
from utils.noir_lib import (
    initialize_noir_project_folder,
    compile_project,
    create_witness,
    normalize_hex_str,
    pad_list,
    hex_string_to_byte_array,
    split_hex_into_31_byte_chunks,
    create_proof,
    build_raw_verification_key,
    extract_vk_as_fields,
    verify_proof
)



async def test_recursive_sha():
    # [0] compile project folder
    print("Test recursive sha...")
    data = "deadeadeadeaddeadeadeadbeefbefbebfbefbefbeefbeeeeeeeeeeeeeeeeeeeeeeeeeeeef"
    await build_recursive_sha256_proof_and_input(data)
    print("done!")

async def test_recursive_sha_too_big():
    # [0] compile project folder
    print("Test recursive sha data too big...")
    data = "de" * 7100
    try:
        await build_recursive_sha256_proof_and_input(data)
        raise Exception("Should have failed")
    except Exception as e:
        if "Invalid bytelength" not in traceback.format_exc():
            raise e
    print("done!")


def main():
    asyncio.run(test_recursive_sha())
    asyncio.run(test_recursive_sha_too_big())


if __name__ == "__main__":
    main()
