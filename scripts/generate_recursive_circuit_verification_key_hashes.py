import asyncio
from textwrap import dedent
import tempfile
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.rift_lib import BB

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


async def get_block_vk_hash():
    compilation_dir = "circuits/block_verification"
    vk = tempfile.NamedTemporaryFile()
    await compile_project(compilation_dir)
    await build_raw_verification_key(vk.name, compilation_dir, BB)
    vk_data = await extract_vk_as_fields(vk.name, compilation_dir, BB)
    return vk_data[0]


async def get_lp_hash_verification_vk_hash():
    compilation_dir = "circuits/lp_hash_verification"
    vk = tempfile.NamedTemporaryFile()
    await compile_project(compilation_dir)
    await build_raw_verification_key(vk.name, compilation_dir, BB)
    vk_data = await extract_vk_as_fields(vk.name, compilation_dir, BB)
    return vk_data[0]

async def get_payment_verification_vk_hash():
    compilation_dir = "circuits/payment_verification"
    vk = tempfile.NamedTemporaryFile()
    await compile_project(compilation_dir)
    await build_raw_verification_key(vk.name, compilation_dir, BB)
    vk_data = await extract_vk_as_fields(vk.name, compilation_dir, BB)
    return vk_data[0]

async def main():
    block_hash = await get_block_vk_hash()
    lp_hash = await get_lp_hash_verification_vk_hash()
    payment_hash = await get_payment_verification_vk_hash()

    print(dedent(f"""    global payment_verification_circuit_key_hash: Field = {payment_hash};
    global block_verification_circuit_key_hash: Field = {block_hash};
    global lp_hash_verification_key_hash: Field = {lp_hash};"""
    ))

if __name__ == "__main__":
    asyncio.run(main())
