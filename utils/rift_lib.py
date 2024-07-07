# utils to create witness data and verify proofs in python 
import hashlib
import os
import math
import json

from pydantic import BaseModel
from eth_abi.abi import encode as eth_abi_encode
import aiofiles


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

BB = "~/.nargo/backends/acvm-backend-barretenberg/backend_binary"
MAX_ENCODED_CHUNKS = 226
MAX_LIQUIDITY_PROVIDERS = 175

class LiquidityProvider(BaseModel):
    amount: int
    btc_exchange_rate: int
    locking_script_hex: str

class Block(BaseModel):
    height: int
    version: int
    prev_block_hash: str
    merkle_root: str
    timestamp: int
    bits: int
    nonce: int

def compute_block_hash(block: Block) -> str:
    """
    Computes the double SHA-256 hash of a block header.

    Args:
    block (Block): The block for which to compute the hash.

    Returns:
    str: The hexadecimal representation of the hash.
    """
    # Convert block header information into a single bytes object.
    # Note: Bitcoin serializes these values in little-endian format.
    header_hex = (
        block.version.to_bytes(4, 'little') +
        bytes.fromhex(block.prev_block_hash)[::-1] +  # Reverse to little-endian
        bytes.fromhex(block.merkle_root)[::-1] +      # Reverse to little-endian
        block.timestamp.to_bytes(4, 'little') +
        block.bits.to_bytes(4, 'little') +
        block.nonce.to_bytes(4, 'little')
    )
    
    # Perform double SHA-256 hashing.
    hash1 = hashlib.sha256(header_hex).digest()
    hash2 = hashlib.sha256(hash1).digest()

    # Bitcoin presents hashes in little-endian format, so we reverse before returning.
    return hash2[::-1].hex()

async def block_toml_encoder(block: Block) -> list[str]:
    return [
        f"bits={block.bits}",
        f"height={block.height}",
        f"merkle_root={json.dumps(hex_string_to_byte_array(block.merkle_root))}",
        f"nonce={block.nonce}",
        f"prev_block_hash={json.dumps(hex_string_to_byte_array(block.prev_block_hash))}",
        f"timestamp={block.timestamp}",
        f"version={block.version}",
    ]



async def create_block_verification_prover_toml_witness(
    proposed_merkle_root_hex: str,
    confirmation_block_hash_hex: str,
    proposed_block_hash_hex: str,
    safe_block_hash_hex: str,
    retarget_block_hash_hex: str,
    safe_block_height: int,
    block_height_delta: int,
    proposed_block: Block,
    safe_block: Block,
    retarget_block: Block,
    inner_block_hashes_hex: list[str],
    inner_blocks: list[Block],
    confirmation_block_hashes_hex: list[str],
    confirmation_blocks: list[Block],
    compilation_build_folder: str
):
    print("Generating prover toml...")
    MAX_INNER_BLOCKS = 24
    CONFIRMATION_BLOCK_DELTA = 6
    NULL_BLOCK = Block(
        height=0,
        version=0,
        prev_block_hash='0' * 64,
        merkle_root='0' * 64,
        timestamp=0,
        bits=0,
        nonce=0
    )

    if len(inner_block_hashes_hex) > MAX_INNER_BLOCKS:
        raise ValueError(f"Too many inner blocks. Max is {MAX_INNER_BLOCKS}")
    
    padded_inner_blocks = pad_list(inner_blocks, MAX_INNER_BLOCKS, NULL_BLOCK)

    padded_confirmation_blocks = pad_list(confirmation_blocks, CONFIRMATION_BLOCK_DELTA, NULL_BLOCK)

    proposed_merkle_root_encoded = split_hex_into_31_byte_chunks(proposed_merkle_root_hex)
    confirmation_block_hash_encoded = split_hex_into_31_byte_chunks(confirmation_block_hash_hex)
    proposed_block_hash_encoded = split_hex_into_31_byte_chunks(proposed_block_hash_hex)
    safe_block_hash_encoded = split_hex_into_31_byte_chunks(safe_block_hash_hex)
    retarget_block_hash_encoded = split_hex_into_31_byte_chunks(retarget_block_hash_hex)
    inner_block_hashes_encoded = [split_hex_into_31_byte_chunks(inner_block_hash) for inner_block_hash in inner_block_hashes_hex]

    confirmation_block_hashes_encoded = [split_hex_into_31_byte_chunks(confirmation_block_hash) for confirmation_block_hash in confirmation_block_hashes_hex]

    padded_inner_block_hashes_encoded = pad_list(inner_block_hashes_encoded, MAX_INNER_BLOCKS, ["0x0", "0x0"])
    padded_confirmation_block_hashes_encoded = pad_list(confirmation_block_hashes_encoded, 6, ["0x0", "0x0"])


    prover_toml_string = "\n".join(
        [
            f"confirmation_block_hash_encoded={json.dumps(confirmation_block_hash_encoded)}",
            f"proposed_block_hash_encoded={json.dumps(proposed_block_hash_encoded)}",
            f"safe_block_hash_encoded={json.dumps(safe_block_hash_encoded)}",
            f"retarget_block_hash_encoded={json.dumps(retarget_block_hash_encoded)}",
            f"safe_block_height={safe_block_height}",
            f"block_height_delta={block_height_delta}",
            f"proposed_merkle_root_encoded={json.dumps(proposed_merkle_root_encoded)}",

            f"inner_block_hashes_encoded={json.dumps(padded_inner_block_hashes_encoded)}",
            "",

            f"confirmation_block_hashes_encoded={json.dumps(padded_confirmation_block_hashes_encoded)}",
            "",

            
            "[proposed_block]",
            *await block_toml_encoder(proposed_block),
            "",

            "[safe_block]",
            *await block_toml_encoder(safe_block),
            "",

            "[retarget_block]",
            *await block_toml_encoder(retarget_block),
            "",


            *[
                "\n".join(
                    ["[[confirmation_blocks]]"] + await block_toml_encoder(block)
                ) for block in padded_confirmation_blocks
            ],
            "",
            
            *[
                "\n".join(
                    ["[[inner_blocks]]"] + await block_toml_encoder(block)
                ) for block in padded_inner_blocks
            ],
        ]
    )

    print("Creating witness...")
    await create_witness(prover_toml_string, compilation_build_folder)


async def create_lp_hash_verification_prover_toml(
    lp_reservation_data: list[LiquidityProvider],
    compilation_build_folder: str
):
    """
    #[recursive]
    fn main(
        lp_reservation_hash_encoded: pub [Field; 2],
        lp_reservation_data_encoded: pub [[Field; 4]; rift_lib::constants::MAX_LIQUIDITY_PROVIDERS],
        lp_count: pub u32
    ) {
    """
    # 4 Fields = 4 * 31 bytes = 124 bytes
    # 3 bytes32 = 3 * 32 bytes = 96 bytes
    # 124 - 96 = 28 bytes
    padded_lp_reservation_data_encoded = pad_list(
        list(map(lambda lp: split_hex_into_31_byte_chunks(
            eth_abi_encode(
                ["uint192", "uint64", "bytes32"],
                [lp.amount, lp.btc_exchange_rate, bytes.fromhex(normalize_hex_str(lp.locking_script_hex))]
            ).hex()
        ), lp_reservation_data)),
        MAX_LIQUIDITY_PROVIDERS,
        ["0x0"] * 4
    )

    vault_hash_hex = "00"*32
    for i in range(len(lp_reservation_data)):
        vault_hash_hex = hashlib.sha256(
            eth_abi_encode(
                ["uint192", "uint64", "bytes32", "bytes32"],
                [
                    lp_reservation_data[i].amount,
                    lp_reservation_data[i].btc_exchange_rate,
                    bytes.fromhex(normalize_hex_str(lp_reservation_data[i].locking_script_hex)),
                    bytes.fromhex(vault_hash_hex)
                ]
            )
        ).hexdigest()

    vault_hash_encoded = split_hex_into_31_byte_chunks(vault_hash_hex)

    prover_toml_string = "\n".join(
        [
            f"lp_reservation_hash_encoded={json.dumps(vault_hash_encoded)}",
            f"lp_reservation_data_encoded={json.dumps(padded_lp_reservation_data_encoded)}",
            f"lp_count={len(lp_reservation_data)}",
        ]
    )
    
    print("Creating witness...")
    await create_witness(prover_toml_string, compilation_build_folder)




async def create_payment_verification_prover_toml(
    txn_data_no_segwit_hex: str,
    lp_reservation_data: list[LiquidityProvider],
    lp_count: int,
    order_nonce_hex: str,
    expected_payout: int,
    compilation_build_folder: str
):
    """
    fn main(
        txn_data_encoded: pub [Field; constants::MAX_ENCODED_CHUNKS],
        lp_reservation_data_encoded: pub [[Field; 4]; constants::MAX_LIQUIDITY_PROVIDERS],
        order_nonce_encoded: pub [Field; 2],
        expected_payout: pub u64,
        txn_data: [u8; constants::MAX_TXN_BYTES]
    ) {
    """
    # 4 Fields = 4 * 31 bytes = 124 bytes
    # 3 bytes32 = 3 * 32 bytes = 96 bytes
    # 124 - 96 = 28 bytes
    padded_lp_reservation_data_encoded = pad_list(
        list(map(lambda lp: split_hex_into_31_byte_chunks(
            eth_abi_encode(
                ["uint192", "uint64", "bytes32"],
                [lp.amount, lp.btc_exchange_rate, bytes.fromhex(normalize_hex_str(lp.locking_script_hex))]
            ).hex()
        ), lp_reservation_data)),
        MAX_LIQUIDITY_PROVIDERS,
        ["0x0"] * 4
    )


    txn_data_encoded = pad_list(split_hex_into_31_byte_chunks(normalize_hex_str(txn_data_no_segwit_hex)), MAX_ENCODED_CHUNKS, "0x0")
    # turns this into a list of 1 byte chunks
    txn_data = pad_list(list(bytes.fromhex(normalize_hex_str(txn_data_no_segwit_hex))), 31*MAX_ENCODED_CHUNKS, 0)

    order_nonce_encoded = split_hex_into_31_byte_chunks(normalize_hex_str(order_nonce_hex))

    prover_toml_string = "\n".join(
        [
            f"txn_data_encoded={json.dumps(txn_data_encoded)}",
            f"lp_reservation_data_encoded={json.dumps(padded_lp_reservation_data_encoded)}",
            f"order_nonce_encoded={json.dumps(order_nonce_encoded)}",
            f"expected_payout={expected_payout}",
            f"lp_count={lp_count}",
            f"txn_data={json.dumps(txn_data)}",
        ]
    )
    
    print("Creating witness...")
    await create_witness(prover_toml_string, compilation_build_folder)





async def load_recursive_sha_circuit(circuit_path: str):
    # Load the circuit file
    async with aiofiles.open(circuit_path, "r") as file:
        return {
            "src/main.nr": await file.read()
        }

async def initialize_recursive_sha_build_folder(bytelen: int, circuit_path: str):
    NAME = "dynamic_sha_lib"
    sha_circuit_fs = await load_recursive_sha_circuit(circuit_path)
    lines = sha_circuit_fs['src/main.nr'].split("\n")
    for i, line in enumerate(lines):
        if "[REPLACE]" in line:
            #global BYTELEN: u32 = 7000; // [REPLACE]
            lines[i] = f"global BYTELEN: u32 = {bytelen};"
            break
    subcircuit_source = "\n".join(lines)
    return await initialize_noir_project_folder({
        'src/main.nr': subcircuit_source,
    }, NAME)


async def create_recursive_sha_witness(normalized_hex_str: str, max_chunks: int, compilation_dir: str):
    data_hash = hashlib.sha256(bytes.fromhex(normalized_hex_str)).hexdigest()
    encoded_data = pad_list(
        split_hex_into_31_byte_chunks(normalized_hex_str), max_chunks, "0x00"
    )
    expected_hash_encoded = split_hex_into_31_byte_chunks(data_hash)

    output = f"encoded_data={json.dumps(encoded_data)}\nexpected_hash_encoded={json.dumps(expected_hash_encoded)}"
    await create_witness(output, compilation_dir)

async def extract_cached_recursive_sha_vkey_data(
    bytelen: int, chunk_file: str
) -> tuple[str, list[str], str]:
    async with aiofiles.open(chunk_file, "r") as file:
        blob = json.loads(await file.read())[str(bytelen)]
        return (blob["vk_as_fields"][0], blob["vk_as_fields"][1:], blob["vk_bytes"])


def validate_bytelen(bytelen: int, max_bytes: int):
    if bytelen > MAX_ENCODED_CHUNKS*31 or bytelen < 1:
        raise Exception("Invalid bytelength")


def get_chunk_file_name(chunk_id: int):
    return f"vk_hash_{chunk_id:04d}.json"


async def build_recursive_sha256_proof_and_input(
    data_hex_str: str,
    circuit_path: str = "circuits/recursive_sha/src/main.nr",
    chunk_folder: str = "generated_sha_circuits/",
    max_bytes: int = 7000,
    max_chunks: int = 226
) -> dict:
    data = normalize_hex_str(data_hex_str)

    bytelen = len(data) // 2

    validate_bytelen(bytelen, max_bytes)

    vkey_hash, vkey_as_fields, vk_hexstr_bytes = await extract_cached_recursive_sha_vkey_data(
        bytelen,
        os.path.join(
            chunk_folder, get_chunk_file_name(math.floor((bytelen - 1) / 1000))
        ),
    )
    build_folder = await initialize_recursive_sha_build_folder(bytelen, circuit_path)

    vk_file = "public_input_proxy_vk"
    async with aiofiles.open(os.path.join(build_folder.name, vk_file), "wb+") as f:
        await f.write(bytes.fromhex(vk_hexstr_bytes))

    await compile_project(build_folder.name)
    await create_recursive_sha_witness(data, max_chunks, build_folder.name)
    public_inputs_as_fields, proof_as_fields = await create_proof(
        vk_file,
        int.from_bytes(bytes.fromhex(normalize_hex_str(vkey_as_fields[4])), "big"),
        build_folder.name,
        BB,
    )
    build_folder.cleanup()
    return {
        "verification_key": vkey_as_fields,
        "proof": proof_as_fields,
        "public_inputs": public_inputs_as_fields,
        "key_hash_index": bytelen - 1,
        "key_hash": vkey_hash,
    }
