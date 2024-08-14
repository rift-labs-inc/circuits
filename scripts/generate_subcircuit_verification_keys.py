import asyncio
import json
import aiofiles
from textwrap import dedent
import tempfile
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.rift_lib import BB

from utils.noir_lib import (
    ensure_cache_is_current,
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

async def create_temp_dir(dir: str):
    temp_dir = tempfile.TemporaryDirectory()
    command = f"cp -r {dir} {temp_dir.name}"
    process = await asyncio.create_subprocess_shell(
        command,
        shell=True,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    if process.returncode != 0:
        print("Errors:\n", stderr.decode())
        raise Exception(stderr.decode())
    return temp_dir


async def get_lp_hash_verification_vk_hash():
    compilation_dir = "circuits/lp_hash_verification"
    vk = tempfile.NamedTemporaryFile()
    await compile_project(compilation_dir, no_cache=True)
    await build_raw_verification_key(vk.name, compilation_dir, BB, no_cache=True)
    vk_data = await extract_vk_as_fields(vk.name, compilation_dir, BB, no_cache=True)
    return vk_data[0]

async def get_payment_verification_vk_hash():
    compilation_dir = "circuits/payment_verification"
    vk = tempfile.NamedTemporaryFile()
    await compile_project(compilation_dir, no_cache=True)
    await build_raw_verification_key(vk.name, compilation_dir, BB, no_cache=True)
    vk_data = await extract_vk_as_fields(vk.name, compilation_dir, BB, no_cache=True)
    return vk_data[0]


# this will generate each layer needed for the full block tree except for the base layer, b/c
# the base layer is the base_tree_circuit itself
async def gen_block_tree_circuit(base_tree_circuit_hash_hex: str, n: int = 20) -> tuple[list[str], dict]:
    # using temp dir, cp the entire circuits dir to a temp dir and then modify the main.nr file there
    circuit_dir = await create_temp_dir("circuits")
    compilation_dir = os.path.join(circuit_dir.name, "circuits/block_verification/recursive_block_tree")
    circuit_hash_list = [base_tree_circuit_hash_hex] 
    tree_height_to_circuit_data = {}
    for i in range(n):
        # out of n
        print("Generating circuit for tree height", f"{i+1}/{n}")
        async with aiofiles.open("circuits/block_verification/recursive_block_tree/src/main.nr") as f:
            circuit_str = await f.read()
        lines = circuit_str.split("\n")
        for j, line in enumerate(lines):
            if "[REPLACE]" in line:
                lines[j] = f"global BLOCK_TREE_CIRCUIT_KEY_HASH: Field = {circuit_hash_list[-1]};"
                break
        subcircuit_source = "\n".join(lines)

        async with aiofiles.open(os.path.join(compilation_dir, "src/main.nr"), "w+") as f:
            await f.write(subcircuit_source)
        circuit_binary = await compile_project(compilation_dir, return_binary=True, no_cache=True)
        assert circuit_binary is not None
        vk = tempfile.NamedTemporaryFile()
        await build_raw_verification_key(vk.name, compilation_dir, BB, no_cache=True)
        vk_data = await extract_vk_as_fields(vk.name, compilation_dir, BB, no_cache=True)
        
        async with aiofiles.open(vk.name, "rb") as f:
            vk_bytes = await f.read()

        tree_height_to_circuit_data[i+1] = {
            "circuit": circuit_binary.hex(),
            "vk": vk_data[1:],
            "vk_hash": vk_data[0],
            "vk_bytes": vk_bytes.hex()
        }
        circuit_hash_list.append(vk_data[0])
    return circuit_hash_list, tree_height_to_circuit_data

async def get_base_tree_circuit_verification_hash():
    compilation_dir = "circuits/block_verification/base_block_tree"
    vk = tempfile.NamedTemporaryFile()
    await compile_project(compilation_dir, no_cache=True)
    await build_raw_verification_key(vk.name, compilation_dir, BB, no_cache=True)
    vk_data = await extract_vk_as_fields(vk.name, compilation_dir, BB, no_cache=True)
    return vk_data[0]

async def get_pair_circuit_verification_hash():
    compilation_dir = "circuits/block_verification/pair_block_verification"
    vk = tempfile.NamedTemporaryFile()
    await compile_project(compilation_dir, no_cache=True)
    await build_raw_verification_key(vk.name, compilation_dir, BB, no_cache=True)
    vk_data = await extract_vk_as_fields(vk.name, compilation_dir, BB, no_cache=True)
    return vk_data[0]

async def get_entrypoint_block_tree_vk_hash():
    compilation_dir = "circuits/block_verification/entrypoint_block_tree"
    vk = tempfile.NamedTemporaryFile()
    await compile_project(compilation_dir, no_cache=True)
    await build_raw_verification_key(vk.name, compilation_dir, BB, no_cache=True)
    vk_data = await extract_vk_as_fields(vk.name, compilation_dir, BB, no_cache=True)
    return vk_data[0]

async def print_pair_circuit_verification_hash():
    pair_circuit_hash = await get_pair_circuit_verification_hash()
    print(dedent(f"""    global pair_block_verification_circuit_key_hash: Field = {pair_circuit_hash};"""
    ))

async def main():
    BLOCK_TREE_VKEY_HASHES_FILE = "circuits/block_verification/block_lib/src/vk_hashes.nr"
    GIGA_RECURSIVE_VKEY_HASHES_FILE = "circuits/giga/src/recursive_circuit_hashes.nr"
    GENERATED_CIRCUITS_DIR = "generated_block_tree_circuits/"
    BLOCK_TREE_HEIGHT = 11 
    print("Generating pair verification key hash...")
    pair_vk_hash = await get_pair_circuit_verification_hash()
    async with aiofiles.open(BLOCK_TREE_VKEY_HASHES_FILE, "w+") as f:
        await f.write(dedent(f"""
        global PAIR_BLOCK_VERIFICATION_CIRCUIT_KEY_HASH: Field = {pair_vk_hash};
        """))

    # base tree verification key hash
    print("Generating base tree verification key hash...")
    base_key_hash = await get_base_tree_circuit_verification_hash()

    circuit_hash_list, tree_height_to_circuit_data = await gen_block_tree_circuit(base_key_hash, BLOCK_TREE_HEIGHT)
    async with aiofiles.open(BLOCK_TREE_VKEY_HASHES_FILE, "a") as f:
        await f.write(f"global BLOCK_TREE_CIRCUIT_KEY_HASHES: [Field; {len(circuit_hash_list)}] = [")
        [await f.write(f"  {hash}{',' if i != len(circuit_hash_list) - 1 else ''}") for i, hash in enumerate(circuit_hash_list)]
        await f.write("];\n")

    for height, data in tree_height_to_circuit_data.items():
        async with aiofiles.open(os.path.join(GENERATED_CIRCUITS_DIR, f"block_tree_height_{height}.json"), "w+") as f:
            await f.write(json.dumps(data, indent=2))


    print("Generating entrypoint block tree verification key hash...")
    entrypoint_vk_hash = await get_entrypoint_block_tree_vk_hash()
    print("Generating lp hash verification key hash...")
    lp_hash = await get_lp_hash_verification_vk_hash()
    print("Generating payment verification key hash...")
    payment_hash = await get_payment_verification_vk_hash()

    async with aiofiles.open(GIGA_RECURSIVE_VKEY_HASHES_FILE, "w+") as f:
        await f.write(dedent(f"""global payment_verification_circuit_key_hash: Field = {payment_hash};
    global block_verification_circuit_key_hash: Field = {entrypoint_vk_hash};
    global lp_hash_verification_key_hash: Field = {lp_hash};"""
    ))

    # this can only happen after everything is generated 
    await ensure_cache_is_current() 
    print("Done!")

    
if __name__ == "__main__":
    asyncio.run(main())

