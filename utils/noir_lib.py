import asyncio
import tempfile
import subprocess
import json
import os
import time
import traceback
from typing import Tuple, List

from pydantic import BaseModel
import xxhash
import aiofiles

from .constants import BB

class CircuitCache(BaseModel):
    circuit: str
    vk: List[str]
    vk_hash: str
    vk_bytes: str

# UTILS
DISABLE_CACHE = False 

async def run_command(command: str, cwd: str, strict_failure = True) -> bytes:
    process = await asyncio.create_subprocess_shell(
        command,
        shell=True,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
    )
    stdout, stderr = await process.communicate()
    if strict_failure:
        if process.returncode != 0 or stderr:
            raise Exception(f"`{command}` failed with {stderr.decode().strip()}")
    else:
        if process.returncode != 0:
            raise Exception(f"`{command}` failed with {stderr.decode().strip()}")
    return stdout

def split_hex_into_31_byte_chunks(hexstr: str):
    return ["0x" + hexstr[i:i+62] for i in range(0, len(hexstr), 62)]

def split_hex_into_31_byte_chunks_padded(hexstr: str):
    hexstr = hexstr[2:] if hexstr.startswith("0x") else hexstr
    chunks = [hexstr[i:i+62] for i in range(0, len(hexstr), 62)]
    
    if chunks and len(chunks[-1]) < 62:
        chunks[-1] = chunks[-1].ljust(62, '0')
    
    return ['0x' + chunk for chunk in chunks]

    

def pad_list(input_list, target_length, pad_item):
    return input_list + [pad_item] * (target_length - len(input_list))

def hex_string_to_byte_array(hex_string: str) -> list[int]:
    if hex_string.startswith("0x"):
        hex_string = hex_string[2:]
    if len(hex_string) % 2 != 0:
        hex_string = "0" + hex_string
    byte_array = []
    for i in range(0, len(hex_string), 2):
        byte_array.append(int(hex_string[i : i + 2], 16))
    return byte_array

def normalize_hex_str(hex_str: str) -> str:
    mod_str = hex_str
    if hex_str.startswith("0x"):
        mod_str = hex_str[2:]
    if len(hex_str) % 2 != 0:
        mod_str = f"0{mod_str}"
    return mod_str

# NOIR WRAPPERS

async def initialize_noir_project_folder(
    circuit_filesystem: dict, name: str
) -> tempfile.TemporaryDirectory:
    temp_dir = tempfile.TemporaryDirectory()
    command = f"nargo init --bin --name {name}"
    stdout = await run_command(command, temp_dir.name)
    for file_path, file_content in circuit_filesystem.items():
        file_full_path = os.path.join(temp_dir.name, file_path)
        os.makedirs(os.path.dirname(file_full_path), exist_ok=True)
        async with aiofiles.open(file_full_path, "w+") as file:
            await file.write(file_content)

    return temp_dir

async def compile_project(compilation_dir: str, return_binary = False, no_cache = False):
    try:
        if not no_cache and not DISABLE_CACHE:
            circuit_data = await get_cached_circuit_data(compilation_dir)
            circuit_bytes = bytes.fromhex(normalize_hex_str(circuit_data.circuit))
            async with aiofiles.open(os.path.join(compilation_dir, "target/acir.gz"), "wb") as file:
                await file.write(circuit_bytes)
            if return_binary:
                return circuit_bytes
    except Exception:
        print(f"Cache miss on [{compilation_dir}]...")

    command = "nargo compile --only-acir"
    await run_command(command, compilation_dir, strict_failure=False)
    if return_binary:
        async with aiofiles.open(os.path.join(compilation_dir, "target/acir.gz"), "rb") as file:
            return await file.read()

async def create_witness(prover_toml_string: str, compilation_dir: str, return_output: bool = False):
    async with aiofiles.open(
        os.path.join(compilation_dir, "Prover.toml"), "w+"
    ) as file:
        await file.write(prover_toml_string)

    command = "nargo execute witness"
    stdout = await run_command(command, compilation_dir, strict_failure=False)
    if return_output:
        return stdout.decode()


# Project name is name of noir project
async def create_solidity_proof(project_name: str, compilation_dir: str):
    command = "nargo prove"
    await run_command(command, compilation_dir, strict_failure=False)
    async with aiofiles.open(
        os.path.join(compilation_dir, "proofs", (project_name + ".proof")), "r"
    ) as file:
        return await file.read()

# BB WRAPPERS

async def build_raw_verification_key(
    vk_file: str,  compilation_dir: str, bb_binary: str, no_cache = False 
):
    try:
        if not no_cache and not DISABLE_CACHE:
            circuit_data = await get_cached_circuit_data(compilation_dir)
            async with aiofiles.open(os.path.join(compilation_dir, vk_file), "wb") as f:
                await f.write(bytes.fromhex(normalize_hex_str(circuit_data.vk_bytes)))
            return
    except Exception:
        print(f"Cache miss on [{compilation_dir}]...")

    command = f"{bb_binary} write_vk -o {vk_file}"
    await run_command(command, compilation_dir)

async def extract_vk_as_fields(vk_file: str, compilation_dir: str, bb_binary: str, no_cache = False) -> list:
    try:
        if not no_cache and not DISABLE_CACHE:
            circuit_data = await get_cached_circuit_data(compilation_dir)
            return [circuit_data.vk_hash] + circuit_data.vk
    except Exception:
        print(f"Cache miss on [{compilation_dir}]...")

    command = f"{bb_binary} vk_as_fields -k {vk_file} -o -"
    stdout = await run_command(command, compilation_dir)
    return json.loads(stdout)

async def verify_proof(vk_path: str, compilation_dir: str, bb_binary: str):
    command = f"{bb_binary} verify -p ./target/proof -k {vk_path}"
    await run_command(command, compilation_dir)

async def create_proof(
    vk_path: str, compilation_dir: str, bb_binary: str
):
    command = f"{bb_binary} prove -o ./target/proof"
    # Build the proof
    await run_command(command, compilation_dir)

    command = f"{bb_binary} proof_as_fields -p ./target/proof -k {vk_path} -o -"
    # Extract generated proof fields
    stdout = await run_command(command, compilation_dir) 
    proof_output = json.loads(stdout)
    return proof_output[:len(proof_output)-93], proof_output[-93:]


# CACHE UTILS 

async def hash_noir_circuit_directory(directory: str):
    """
    Determinstically hash a directory of noir circuits
    """
    nr_files: List[str] = []
    for root, _, files in os.walk(directory):
        nr_files.extend(
            os.path.join(root, file)
            for file in files
            if file.endswith('.nr') or file == 'Nargo.toml'
        )
    
    # Sort the files
    nr_files.sort()

    async def read_file(file_path: str):
        async with aiofiles.open(file_path, 'r') as f:
            return await f.read()

    nr_contents = await asyncio.gather(*[read_file(file) for file in nr_files])

    file_hashes = [xxhash.xxh64_hexdigest(file + contents) for file, contents in zip(nr_files, nr_contents)]

    final_hasher = xxhash.xxh3_64()
    for file_hash in file_hashes:
        final_hasher.update(file_hash)
    
    return final_hasher.hexdigest()


async def validate_cache(cache_directory: str, noir_circuit_directory: str):
    """
    If a cache exists, hash the circuits directory and compare it to the cache hash
    if the same, exit  early
    if different, recompile the circuits and update the cache
    """
    if not os.path.exists(cache_directory):
        os.makedirs(cache_directory)
        return False
    cache_file = os.path.join(cache_directory, "hash_cache.json")
    if os.path.exists(cache_file):
        async with aiofiles.open(cache_file, "r") as f:
            cache_data = json.loads((await f.read()))
        circuit_hash = await hash_noir_circuit_directory(noir_circuit_directory)
        if cache_data["circuit_hash"] == circuit_hash:
            return True
    return False

async def recompile_noir_circuits(desired_circuits: List[str], BB: str = BB):
    """
    compile all desired circuits to an acir binary and create verification keys
    store all of this in a json file located at the subdirectory level in the project cache in a cache.json
    """
    circuit_data = {}
    for circuit_dir in desired_circuits:
        circuit_binary = await compile_project(circuit_dir, return_binary=True, no_cache=True)
        assert circuit_binary is not None
        vk_file = "./target/vk"
        await build_raw_verification_key(vk_file, circuit_dir, BB, no_cache=True)
        vk_as_fields = await extract_vk_as_fields(vk_file, circuit_dir, BB, no_cache=True)
        async with aiofiles.open(f"{circuit_dir}/target/vk", "rb") as f:
            vk_bytes = (await f.read())

        circuit_data[circuit_dir] = {
            "circuit": circuit_binary.hex(),
            "vk": vk_as_fields[1:],
            "vk_hash": vk_as_fields[0],
            "vk_bytes": vk_bytes.hex()
        }

    return circuit_data

async def ensure_cache_is_current(
    cache_directory: str = ".noir_cache",
    noir_circuit_directory: str = "circuits",
    desired_circuits: List[str] = [
        "circuits/block_verification/base_block",
        "circuits/block_verification/entrypoint_block_tree",
        "circuits/giga",
        "circuits/lp_hash_verification",
        "circuits/payment_verification"
    ],
    start = time.time() 
):
    cache_up_to_date = await validate_cache(cache_directory, noir_circuit_directory)
    if cache_up_to_date:
        print("Noir cache validated in", round(time.time() - start, 2), "seconds")
        return
    
    print("Populating noir cache...")

    circuit_hash = await hash_noir_circuit_directory(noir_circuit_directory)
    cache_data = {
        "circuit_hash": circuit_hash
    }
    cache_file = os.path.join(cache_directory, "hash_cache.json")
    async with aiofiles.open(cache_file, "w+") as f:
        await f.write(json.dumps(cache_data, indent=2))

    circuits = await recompile_noir_circuits(desired_circuits)
    for circuit_dir, circuit_data in circuits.items():
        circuit_cache_file = os.path.join(cache_directory, circuit_dir, "cache.json")
        os.makedirs(os.path.dirname(circuit_cache_file), exist_ok=True)
        async with aiofiles.open(circuit_cache_file, "w+") as f:
            await f.write(json.dumps(circuit_data, indent=2))

    print("Noir cache populated in", round(time.time() - start, 2), "seconds")

async def get_cached_circuit_data(circuit_dir: str, cache_directory: str = ".noir_cache") -> CircuitCache: 
    if circuit_dir.startswith("/tmp/"):
        circuit_dir = "/".join(circuit_dir.split("/")[3:])
    cache_file = os.path.join(cache_directory, circuit_dir, "cache.json")
    async with aiofiles.open(cache_file, "r") as f:
        return CircuitCache(**json.loads(await f.read()))

async def test_noir_cache():
    await ensure_cache_is_current()

if __name__ == "__main__":
    asyncio.run(test_noir_cache())

