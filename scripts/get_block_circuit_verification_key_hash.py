import asyncio
import tempfile
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

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


async def main():
    compilation_dir = "circuits/block_verification"
    BB = "~/.nargo/backends/acvm-backend-barretenberg/backend_binary"
    vk = tempfile.NamedTemporaryFile()
    print("Compiling block verification circuit...")
    await compile_project(compilation_dir)
    print("Building verification key...")
    await build_raw_verification_key(vk.name, compilation_dir, BB)
    vk_data = await extract_vk_as_fields(vk.name, compilation_dir, BB)
    print("Verification Key Data", vk_data)

if __name__ == "__main__":
    asyncio.run(main())
