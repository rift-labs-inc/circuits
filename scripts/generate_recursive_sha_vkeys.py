import asyncio
import math
import hashlib
import time
import multiprocessing
import sys
import psutil
from typing import Any
import aiofiles
import json
import os
import tempfile
import subprocess


SHA_CIRCUIT_FS = {
    "src/main.nr": """
use dep::std;
// use dep::rift_lib::constants::{MAX_ENCODED_CHUNKS};

// [VARIABLE] Amount of bytes this circuit will consume from encoded_data
global BYTELEN: u32 = __PLACEHOLDER__; 
// the amount of Field chunks needed to store BYTELEN amount of u8s should always be => ceil(BYTELEN/31)
global BYTELEN_CHUNK: u32 = (BYTELEN + 30) / 31;
// overflow, if bytelen mod 31 is equal to 0 then we set overflow equal to 31
global OVERFLOW: u32 = (BYTELEN % 31) + ((BYTELEN % 31 == 0) as u32 * 31);
global MAX_ENCODED_CHUNKS: u32 = 226;

#[recursive]
fn main(expected_hash_encoded: pub [Field; 2], encoded_data: pub [Field; MAX_ENCODED_CHUNKS]) {
	assert(MAX_ENCODED_CHUNKS >= (BYTELEN/BYTELEN_CHUNK));
	let mut data: [u8; BYTELEN] = [0; BYTELEN];
	for i in 0..BYTELEN_CHUNK-1 {
		let decoded_field = encoded_data[i].to_be_bytes(31);
		for j in 0..31 {
			data[(i*31)+j] = decoded_field[j];
		}
	}
	let decoded_field = encoded_data[BYTELEN_CHUNK-1].to_be_bytes(OVERFLOW);
	for i in 0..OVERFLOW {
		data[((BYTELEN_CHUNK-1)*31)+i] = decoded_field[i];
	}
	let expected_hash_l1: [u8] = expected_hash_encoded[0].to_be_bytes(31);
	let expected_hash_l2: [u8] = expected_hash_encoded[1].to_be_bytes(1);
	let mut expected_hash: [u8; 32] = [0; 32];
	for i in 0..31{
		expected_hash[i] = expected_hash_l1[i];	
	}
	expected_hash[31] = expected_hash_l2[0];
	assert(std::hash::sha256(data) == expected_hash);
}
"""
}


def initiate_nargo_dir() -> tempfile.TemporaryDirectory:
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
    for file_path, file_content in SHA_CIRCUIT_FS.items():
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
    profile_write_vk: bool = False,
    log_mem_func=None,
    write_vk: bool = True,
) -> tuple[str, str] | None:
    file_name = f"{compilation_dir}/src/main.nr"

    # Asynchronously write to the file
    async with aiofiles.open(file_name, "w") as file:
        await file.write(
            SHA_CIRCUIT_FS['src/main.nr'].replace("__PLACEHOLDER__", str(byte_len))
        )

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


async def create_demo_proof(bb_binary: str, compilation_dir: str, byte_len: int):
    # Repeating the hex string "dd"  times
    data = "dd" * byte_len

    # Creating a SHA-256 hash of the byte data
    data_hash = hashlib.sha256(bytes.fromhex(data)).hexdigest()

    output = f"data={json.dumps(hex_string_to_byte_array(data))}\nexpected_hash={json.dumps(hex_string_to_byte_array(data_hash))}"

    async with aiofiles.open(
        os.path.join(compilation_dir, "Prover.toml"), "w+"
    ) as file:
        await file.write(output)

    command = "nargo execute witness"

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
        raise Exception()

    command = f"{bb_binary} prove -o ./target/proof"

    process = await asyncio.create_subprocess_shell(
        command,
        shell=True,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=compilation_dir,
    )

    stdout, stderr = await process.communicate()
    print("Proof built")

    if process.returncode != 0:
        print("Errors:\n", stderr.decode())
        raise Exception()


async def mine_batch(start_chunk: int):
    # TODO_ALPINE: Remove constants json, hard code constants
    assert start_chunk >= 0
    constants = json.load(open("scripts/constants.json", "r"))
    CIRCUIT_GEN_CONCURRENCY_LIM = constants["CIRCUIT_GEN_CONCURRENCY_LIM"]
    BB_BINARY = constants["BB_BINARY"]
    get_vkey_chunk_file = (
        lambda x: f"{constants['VERIFICATION_KEY_HASH_PREFIX']}{x:04d}.json"
    )
    # this shouldn't change:
    BATCH_CHUNK_SIZE = 1000
    CHUNK_SIZE = 1000

    total_bytes = ((start_chunk + 1) * BATCH_CHUNK_SIZE) - (
        start_chunk * BATCH_CHUNK_SIZE
    )

    semaphore = asyncio.Semaphore(CIRCUIT_GEN_CONCURRENCY_LIM)
    temp_dir_handles = [
        initiate_nargo_dir() for _ in range(CIRCUIT_GEN_CONCURRENCY_LIM * 2)
    ]

    async def guarded_circuit_creation(byte_len, dir_handle):
        async with semaphore:
            start_time = time.time()
            result = await create_new_circuit(BB_BINARY, dir_handle, byte_len)
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
    except ValueError:
        print("Error: The start chunk must be an integer/exist.")
        sys.exit(1)  # Exit the program with an error code

    await mine_batch(start)


if __name__ == "__main__":
    asyncio.run(run_batched_gen())
