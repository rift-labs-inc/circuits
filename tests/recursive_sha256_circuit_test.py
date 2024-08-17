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

from utils.noir_lib import ensure_cache_is_current
from utils.rift_lib import (
    build_recursive_sha256_proof_and_input
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
    asyncio.run(ensure_cache_is_current())
    asyncio.run(test_recursive_sha())
    asyncio.run(test_recursive_sha_too_big())


if __name__ == "__main__":
    main()
