import os
import sys
import asyncio

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.fetch_block_data import fetch_block_data
from utils.rift_lib import (
    create_block_verification_prover_toml_witness,
    Block,
    compute_block_hash,
    LiquidityProvider,
    create_lp_hash_verification_prover_toml
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

async def test_single_lp():
    # [0] compile project folder
    COMPILATION_DIR = "circuits/lp_hash_verification"
    BB = "~/.nargo/backends/acvm-backend-barretenberg/backend_binary"
    print("Compiling lp hash verification circuit...")
    await compile_project(COMPILATION_DIR)
    # [1] create prover toml and witness
    print("Creating prover toml and witness...")
    lp = LiquidityProvider(amount=100, btc_exchange_rate=1000, locking_script_hex="0x0014841b80d2cc75f5345c482af96294d04fdd66b2b7")
    await create_lp_hash_verification_prover_toml(
        lp_reservation_data=[lp],
        compilation_build_folder=COMPILATION_DIR
    )
    # [3] build verification key, create proof, and verify proof
    vk = "./target/vk"
    print("Building verification key...")
    await build_raw_verification_key(vk, COMPILATION_DIR, BB)
    print("Creating proof...")
    await create_proof(pub_inputs=703, vk_path=vk, compilation_dir=COMPILATION_DIR, bb_binary=BB)
    print("Verifying proof...")
    await verify_proof(vk_path=vk, compilation_dir=COMPILATION_DIR, bb_binary=BB)
    print("lp hash verification successful!")


def main():
    asyncio.run(test_single_lp())


if __name__ == "__main__":
    main()
