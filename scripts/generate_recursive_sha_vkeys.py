import asyncio
import math
import hashlib
import time
import multiprocessing
import sys
import os
import psutil
from typing import Any
import json
import tempfile
import subprocess

import aiofiles

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.rift_lib import BB, load_recursive_sha_circuit


def initiate_nargo_dir(sha_circuit_fs: dict[str, str]) -> tempfile.TemporaryDirectory:
    temp_dir = tempfile.TemporaryDirectory()
    command = "nargo init --bin --name dynamic_sha_lib"
    process = subprocess.run(
        command,
        shell=True,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=temp_dir.name,
    )
    if process.stderr:
        raise Exception(process.stderr)
    for file_path, file_content in sha_circuit_fs.items():
        file_full_path = os.path.join(temp_dir.name, file_path)
        os.makedirs(os.path.dirname(file_full_path), exist_ok=True)
        with open(file_full_path, "w+") as file:
            file.write(file_content)
    return temp_dir


async def extract_vkey_hash(
    bb_binary: str,
    compilation_dir: str,
    profile_write_vk: bool = False,
    log_mem_func=None,
) -> tuple[str, str]:
    command = f"{bb_binary} write_vk -o ./target/vk"
    process = await asyncio.create_subprocess_shell(
        command,
        shell=True,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=compilation_dir,
    )

    stdout, stderr = await process.communicate()

    if process.returncode != 0:
        print("Errors:\n", stderr.decode())
        raise Exception(stderr.decode())

    async with aiofiles.open(f"{compilation_dir}/target/vk", "rb") as f:
        vk_bytes = (await f.read()).hex()

    command = f"{bb_binary} vk_as_fields -k ./target/vk -o -"
    process = await asyncio.create_subprocess_shell(
        command,
        shell=True,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=compilation_dir,
    )

    # Wait for the process to complete and collect output
    stdout, stderr = await process.communicate()

    if process.returncode != 0:
        print("Errors:\n", stderr.decode())
        raise Exception(stderr.decode())

    return json.loads(stdout), vk_bytes


async def create_new_circuit(
    bb_binary: str,
    compilation_dir: str,
    byte_len: int,
    sha_circuit_fs: dict[str, str],
    profile_write_vk: bool = False,
    log_mem_func=None,
    write_vk: bool = True,
) -> tuple[str, str] | None:
    file_name = f"{compilation_dir}/src/main.nr"

    # find the line where [REPLACE] is then replace the entire line with 
    # the new byte_len
    lines = sha_circuit_fs['src/main.nr'].split("\n")
    for i, line in enumerate(lines):
        if "[REPLACE]" in line:
            #global BYTELEN: u32 = 7000; // [REPLACE]
            lines[i] = f"global BYTELEN: u32 = {byte_len};"
            break
    subcircuit_source = "\n".join(lines)

    # Asynchronously write to the file
    async with aiofiles.open(file_name, "w") as file:
        await file.write(subcircuit_source)

    # Prepare the command and execute it asynchronously
    command = "nargo compile --only-acir"
    process = await asyncio.create_subprocess_shell(
        command,
        shell=True,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=compilation_dir,
    )

    # Wait for the process to complete and collect output
    stdout, stderr = await process.communicate()

    if process.returncode != 0:
        print("Errors:\n", stderr.decode())
        raise Exception(stderr.decode())
    if write_vk:
        return await extract_vkey_hash(
            bb_binary, compilation_dir, profile_write_vk, log_mem_func
        )


def hex_string_to_byte_array(hex_string: str) -> list[int]:
    # Check for and remove the '0x' prefix
    if hex_string.startswith("0x"):
        hex_string = hex_string[2:]
    # Ensure the string has an even length by prepending a '0' if necessary
    if len(hex_string) % 2 != 0:
        hex_string = "0" + hex_string
    # Convert the hexadecimal string to a bytearray
    byte_array = []
    for i in range(0, len(hex_string), 2):
        byte_array.append(int(hex_string[i : i + 2], 16))
    return byte_array




async def mine_batch(start_chunk: int):
    assert start_chunk >= 0
    BB_BINARY = BB
    CIRCUIT_GEN_CONCURRENCY_LIM = 5 
    VERIFICATION_KEY_HASH_PREFIX = "generated_sha_circuits/vk_chunk_"
    SHA_CIRCUIT_FS = await load_recursive_sha_circuit("circuits/recursive_sha/src/main.nr")
    # this shouldn't change:
    BATCH_CHUNK_SIZE = 1000
    CHUNK_SIZE = 1000

    get_vkey_chunk_file = (
        lambda x: f"{VERIFICATION_KEY_HASH_PREFIX}{x:04d}.json"
    )

    total_bytes = ((start_chunk + 1) * BATCH_CHUNK_SIZE) - (
        start_chunk * BATCH_CHUNK_SIZE
    )


    semaphore = asyncio.Semaphore(CIRCUIT_GEN_CONCURRENCY_LIM)
    temp_dir_handles = [
        initiate_nargo_dir(SHA_CIRCUIT_FS) for _ in range(CIRCUIT_GEN_CONCURRENCY_LIM * 2)
    ]

    async def guarded_circuit_creation(byte_len, dir_handle):
        async with semaphore:
            start_time = time.time()
            result = await create_new_circuit(BB_BINARY, dir_handle, byte_len, SHA_CIRCUIT_FS)
            elapsed_time = time.time() - start_time
            remaining = (
                total_bytes - (byte_len - (start_chunk * BATCH_CHUNK_SIZE))
            ) * elapsed_time
            if remaining != 0:
                print(
                    f"Completed circuit {byte_len} in {elapsed_time:.2f} sec. Estimated time remaining: {remaining/60/CIRCUIT_GEN_CONCURRENCY_LIM:.2f} minutes"
                )
            return byte_len, result

    output = {}

    async def process_chunk(tasks):
        nonlocal output
        results = await asyncio.gather(*tasks)
        highest_bytelen = 1
        for byte_len, vk_data in results:
            output[byte_len] = {"vk_as_fields": vk_data[0], "vk_bytes": vk_data[1]}
            highest_bytelen = max(highest_bytelen, byte_len)

    all_tasks = []
    start_time = time.time()
    for byte_len in range(
        (start_chunk * BATCH_CHUNK_SIZE) + 1, ((start_chunk + 1) * BATCH_CHUNK_SIZE) + 1
    ):
        selected_dir = temp_dir_handles[byte_len % len(temp_dir_handles)]
        task = guarded_circuit_creation(byte_len, selected_dir.name)
        all_tasks.append(task)

        if len(all_tasks) == CHUNK_SIZE or byte_len == (
            (start_chunk + 1) * BATCH_CHUNK_SIZE
        ):
            await process_chunk(all_tasks)
            all_tasks = []
    if len(all_tasks) > 0:
        await process_chunk(all_tasks)

    async with aiofiles.open(
        get_vkey_chunk_file(math.floor(start_chunk)), "w+"
    ) as file:
        await file.write(json.dumps(output, indent=2))

    elapse = time.time() - start_time
    print("Total runtime", elapse)

    for dir_handle in temp_dir_handles:
        dir_handle.cleanup()


async def run_batched_gen():
    try:
        start = int(
            sys.argv[1]
        )  # Convert the first command-line argument to an integer
    except IndexError:
        print("Error: The start chunk must be an integer/exist.")
        sys.exit(1)  # Exit the program with an error code

    await mine_batch(start)

if __name__ == "__main__":
    asyncio.run(run_batched_gen())
