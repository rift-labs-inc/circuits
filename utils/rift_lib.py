# utils to create witness data and verify proofs in python
import asyncio
import functools
import pickle
from typing import Any, Callable, Dict, Tuple
import tempfile
import hashlib
from functools import reduce, cache, wraps
import os
import math
import json
import traceback
from typing import Union, TypeVar, Any, Coroutine
from pathlib import Path
import shutil

from pydantic import BaseModel
import aiofiles
from eth_abi.abi import encode as eth_abi_encode
from cache import AsyncLRU

from .noir_lib import (
    CircuitCache,
    create_solidity_proof,
    get_cached_circuit_data,
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
    split_hex_into_31_byte_chunks_padded,
    validate_cache,
    verify_proof
)

from .constants import (
    BB,
    MAX_BLOCK_HASHES_PER_BASE_PROOF,
    MAX_BLOCK_HASHES_PER_ENTRYPOINT_PROOF,
    MAX_BLOCK_PROOFS,
    MAX_ENCODED_CHUNKS,
    MAX_LIQUIDITY_PROVIDERS,
    MAX_INNER_BLOCKS,
    CONFIRMATION_BLOCK_DELTA
)
CACHE_DIR = "artifact_cache"

def file_cache(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        # Create cache directory if it doesn't exist
        os.makedirs(CACHE_DIR, exist_ok=True)

        # Create a unique cache key based on function name and arguments
        key = f"{func.__name__}_{hashlib.md5(str(args).encode() + str(kwargs).encode()).hexdigest()}"
        cache_file = os.path.join(CACHE_DIR, f"{key}.pickle")

        # Check if cached result exists
        if os.path.exists(cache_file):
            with open(cache_file, "rb") as f:
                print(f"Loading cached result for {func.__name__}")
                return pickle.load(f)

        # If not cached, call the original function
        result = await func(*args, **kwargs)

        # Cache the result
        with open(cache_file, "wb") as f:
            print(f"Caching result for {func.__name__}")
            pickle.dump(result, f)

        return result

    return wrapper


T = TypeVar('T')

class SolidityProofArtifact(BaseModel):
    proof: str 
    aggregation_object: list[str]
    full_public_inputs: list[str]


class RecursiveProofArtifact(BaseModel):
    verification_key: list[str]
    proof: list[str]
    public_inputs: list[str]
    key_hash: str


class RecursiveSha256ProofArtifact(RecursiveProofArtifact):
    key_hash_index: int


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
    txns: list[str]

class BaseBlockArtifact(BaseModel):
    proof_artifact: RecursiveProofArtifact

class BlockTreeArtifact(BaseModel):
    height: int
    proof_artifact: RecursiveProofArtifact
    first_block: Block
    last_block: Block



NULL_BLOCK = Block(
    height=0,
    version=0,
    prev_block_hash='0' * 64,
    merkle_root='0' * 64,
    timestamp=0,
    bits=0,
    nonce=0,
    txns=[]
)

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
        # Reverse to little-endian
        bytes.fromhex(block.prev_block_hash)[::-1] +
        # Reverse to little-endian
        bytes.fromhex(block.merkle_root)[::-1] +
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



def compute_lp_reservation_hash(lp_reservation_data: list[LiquidityProvider]) -> str:
    vault_hash_hex = "00"*32
    for i in range(len(lp_reservation_data)):
        vault_hash_hex = hashlib.sha256(
            eth_abi_encode(
                ["uint192", "uint64", "bytes32", "bytes32"],
                [
                    lp_reservation_data[i].amount,
                    lp_reservation_data[i].btc_exchange_rate,
                    bytes.fromhex(normalize_hex_str(
                        lp_reservation_data[i].locking_script_hex)),
                    bytes.fromhex(vault_hash_hex)
                ]
            )
        ).hexdigest()
    return normalize_hex_str(vault_hash_hex)

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
                [lp.amount, lp.btc_exchange_rate, bytes.fromhex(
                    normalize_hex_str(lp.locking_script_hex))]
            ).hex()
        ), lp_reservation_data)),
        MAX_LIQUIDITY_PROVIDERS,
        ["0x0"] * 4
    )

    vault_hash_hex = compute_lp_reservation_hash(lp_reservation_data)
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
                [lp.amount, lp.btc_exchange_rate, bytes.fromhex(
                    normalize_hex_str(lp.locking_script_hex))]
            ).hex()
        ), lp_reservation_data)),
        MAX_LIQUIDITY_PROVIDERS,
        ["0x0"] * 4
    )

    txn_data_encoded = pad_list(split_hex_into_31_byte_chunks_padded(
        normalize_hex_str(txn_data_no_segwit_hex)), MAX_ENCODED_CHUNKS, "0x0")
    # turns this into a list of 1 byte chunks
    txn_data = pad_list(list(bytes.fromhex(normalize_hex_str(
        txn_data_no_segwit_hex))), 31*MAX_ENCODED_CHUNKS, 0)

    order_nonce_encoded = split_hex_into_31_byte_chunks(
        normalize_hex_str(order_nonce_hex))

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


def hash_pairs(hex_str1, hex_str2):
    """Hash two hex strings together using double SHA-256 and return the hex result."""
    # Convert hex strings to binary, in little-endian format
    bin1 = bytes.fromhex(hex_str1)[::-1]
    bin2 = bytes.fromhex(hex_str2)[::-1]
    
    # Combine the binary data
    combined = bin1 + bin2
    
    # Double SHA-256 hashing
    hash_once = hashlib.sha256(combined).digest()
    hash_twice = hashlib.sha256(hash_once).digest()
    
    # Return the result as a hex string, in little-endian format
    return hash_twice[::-1].hex()

def generate_merkle_proof(txn_hashes: list, target_hash: str):
    """Generate a Merkle proof for the target hash."""
    proof = []
    target_index = txn_hashes.index(target_hash)
    depth = 0
    while len(txn_hashes) > 1:
        new_level = []
        if len(txn_hashes) % 2 == 1:
            txn_hashes.append(txn_hashes[-1])
        for i in range(0, len(txn_hashes), 2):
            left, right = txn_hashes[i], txn_hashes[i+1]
            if i <= target_index < i+2:
                if target_index == i:
                    proof.append((right, 'right'))
                else:
                    proof.append((left, 'left'))
                target_hash = hash_pairs(left, right)
            new_level.append(hash_pairs(left, right))
        txn_hashes = new_level
        target_index //= 2
        depth += 1
    
    return proof

def create_merkle_proof_toml(proof: list):
    toml_str = ""
    for i, (hash, direction) in enumerate(proof):
        flag = "true" if direction == 'right' else "false"
        toml_str += (f"[[proposed_merkle_proof]] # {i+1}\nhash = {list(bytes.fromhex(normalize_hex_str(hash)))}\ndirection = {flag}\n\n")
    
    # Determine how many padding entries are needed
    num_padding_entries = 20 - len(proof)
    
    # Padding with 0 u8 32-byte arrays if needed
    for j in range(num_padding_entries):
        toml_str += (f"[[proposed_merkle_proof]] # {len(proof) + j + 1}\nhash = {list(bytes.fromhex('00'*32))}\ndirection = false\n\n")

    return toml_str




"""
fn main(
    // Transaction Hash Verification
    txn_hash_encoded: pub [Field; 2],
    intermediate_hash_encoded_and_txn_data: [Field; constants::MAX_ENCODED_CHUNKS + 2],
    // Transaction Inclusion Verification
    proposed_merkle_root_encoded: [Field; 2],
    proposed_merkle_proof: [sha256_merkle::MerkleProofStep; 20],
    // Payment Verification + Lp Hash Verification
    lp_reservation_hash_encoded: pub [Field; 2],
    order_nonce_encoded: pub [Field; 2],
    expected_payout: pub u64,
    lp_count: pub u64,
    lp_reservation_data_flat_encoded: [Field; constants::MAX_LIQUIDITY_PROVIDERS*4],
    // Block Verification
    confirmation_block_hash_encoded: pub [Field; 2],
    proposed_block_hash_encoded: pub [Field; 2],
    safe_block_hash_encoded: pub [Field; 2],
    retarget_block_hash_encoded: pub [Field; 2],
    safe_block_height: pub u64,
    block_height_delta: pub u64,
    // Proof Data
    lp_hash_verification_key: [Field; 114],
    lp_hash_proof: [Field; 93],
    txn_hash_verification_key: [Field; 114],
    txn_hash_proof: [Field; 93],
    txn_hash_vk_hash_index: u64,
    payment_verification_key: [Field; 114],
    payment_proof: [Field; 93],
    block_verification_key: [Field; 114],
    block_proof: [Field; 93]
) {
"""

async def create_giga_circuit_prover_toml(
    txn_hash_hex: str,
    intermediate_hash_hex: str,
    txn_data_no_segwit_hex: str,
    proposed_merkle_root_hex: str,
    proposed_merkle_proof: list,
    lp_reservation_hash_hex: str,
    order_nonce_hex: str,
    expected_payout: int,
    lp_reservation_data: list[LiquidityProvider],
    confirmation_block_hash_hex: str,
    proposed_block_hash_hex: str,
    safe_block_hash_hex: str,
    retarget_block_hash_hex: str,
    safe_block_height: int,
    safe_block_height_delta: int,
    confirmation_block_height_delta: int,
    retarget_block_height: int,
    lp_hash_verification_key: list[str],
    lp_hash_proof: list[str],
    txn_hash_verification_key: list[str],
    txn_hash_proof: list[str],
    txn_hash_vk_hash_index: int,
    payment_verification_key: list[str],
    payment_proof: list[str],
    block_verification_key: list[str],
    block_proof: list[str],
    block_recursive_aggregation_object: list[str],
    compilation_build_folder: str
):
    txn_hash_encoded = split_hex_into_31_byte_chunks(normalize_hex_str(txn_hash_hex))
    intermediate_hash_encoded_and_txn_data = split_hex_into_31_byte_chunks(normalize_hex_str(intermediate_hash_hex)) + pad_list(split_hex_into_31_byte_chunks(normalize_hex_str(txn_data_no_segwit_hex)), MAX_ENCODED_CHUNKS, "0x0")
    proposed_merkle_root_encoded = split_hex_into_31_byte_chunks(normalize_hex_str(proposed_merkle_root_hex))

    lp_reservation_hash_encoded = split_hex_into_31_byte_chunks(normalize_hex_str(lp_reservation_hash_hex))
    order_nonce_encoded = split_hex_into_31_byte_chunks(normalize_hex_str(order_nonce_hex))
    lp_reservation_data_flat_encoded = sum(pad_list(
        list(map(lambda lp: split_hex_into_31_byte_chunks(
            eth_abi_encode(
                ["uint192", "uint64", "bytes32"],
                [lp.amount, lp.btc_exchange_rate, bytes.fromhex(
                    normalize_hex_str(lp.locking_script_hex))]
            ).hex()
        ), lp_reservation_data)),
        MAX_LIQUIDITY_PROVIDERS,
        ["0x0"] * 4
    ), [])
    prover_toml_string = "\n".join(
        [
            f"txn_hash_encoded={json.dumps(txn_hash_encoded)}",
            "",
            f"intermediate_hash_encoded_and_txn_data={json.dumps(intermediate_hash_encoded_and_txn_data)}",
            "",
            f"proposed_merkle_root_encoded={json.dumps(proposed_merkle_root_encoded)}",
            "",
            f"lp_reservation_hash_encoded={json.dumps(lp_reservation_hash_encoded)}",
            "",
            f"order_nonce_encoded={json.dumps(order_nonce_encoded)}",
            "",
            f"expected_payout={expected_payout}",
            "",
            f"lp_count={len(lp_reservation_data)}",
            "",
            f"lp_reservation_data_flat_encoded={json.dumps(lp_reservation_data_flat_encoded)}",
            "",
            f"confirmation_block_hash_encoded={json.dumps(split_hex_into_31_byte_chunks(normalize_hex_str(confirmation_block_hash_hex)))}",
            "",
            f"proposed_block_hash_encoded={json.dumps(split_hex_into_31_byte_chunks(normalize_hex_str(proposed_block_hash_hex)))}",
            "",
            f"safe_block_hash_encoded={json.dumps(split_hex_into_31_byte_chunks(normalize_hex_str(safe_block_hash_hex)))}",
            "",
            f"retarget_block_hash_encoded={json.dumps(split_hex_into_31_byte_chunks(normalize_hex_str(retarget_block_hash_hex)))}",
            "",
            f"safe_block_height={safe_block_height}",
            "",
            f"safe_block_height_delta={safe_block_height_delta}",
            "",
            f"confirmation_block_height_delta={confirmation_block_height_delta}",
            "",
            f"retarget_block_height={retarget_block_height}",
            "",
            f"lp_hash_verification_key={json.dumps(lp_hash_verification_key)}",
            "",
            f"lp_hash_proof={json.dumps(lp_hash_proof)}",
            "",
            f"txn_hash_verification_key={json.dumps(txn_hash_verification_key)}",
            "",
            f"txn_hash_proof={json.dumps(txn_hash_proof)}",
            "",
            f"txn_hash_vk_hash_index={txn_hash_vk_hash_index}",
            "",
            f"payment_verification_key={json.dumps(payment_verification_key)}",
            "",
            f"payment_proof={json.dumps(payment_proof)}",
            "",
            f"block_verification_key={json.dumps(block_verification_key)}",
            "",
            f"block_proof={json.dumps(block_proof)}",
            "",
            f"block_recursive_aggregation_object={json.dumps(block_recursive_aggregation_object)}",
            "",
            "",
            create_merkle_proof_toml(proposed_merkle_proof),
            "",
        ]
    )

    print("Creating witness...")
    print("Giga Witness", await create_witness(prover_toml_string, compilation_build_folder, return_output=True))


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
            # global BYTELEN: u32 = 7000; // [REPLACE]
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
    return f"vk_chunk_{chunk_id:04d}.json"


async def build_recursive_sha256_proof_and_input(
    data_hex_str: str,
    circuit_path: str = "circuits/recursive_sha/src/main.nr",
    chunk_folder: str = "generated_sha_circuits/",
    max_bytes: int = 7000,
    max_chunks: int = 226,
    verify: bool = False
) -> RecursiveSha256ProofArtifact:
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

    print("Compiling recursive sha256 circuit...")
    await compile_project(build_folder.name, no_cache=True)
    print("Creating witness...")
    await create_recursive_sha_witness(data, max_chunks, build_folder.name)
    public_inputs_as_fields, proof_as_fields = await create_proof(
        vk_file,
        build_folder.name,
        BB,
    )

    print("SHA256 proof created!")

    if verify:
        print("Verifying proof...")
        await verify_proof(vk_file, build_folder.name, BB)
        print("SHA256 proof verified!")


    build_folder.cleanup()
    return RecursiveSha256ProofArtifact(
        verification_key=vkey_as_fields,
        proof=proof_as_fields,
        public_inputs=public_inputs_as_fields,
        key_hash_index=bytelen - 1,
        key_hash=vkey_hash,
    )

async def build_recursive_lp_hash_proof_and_input(
    lps: list[LiquidityProvider],
    circuit_path: str = "circuits/lp_hash_verification",
    verify: bool = False
):
    print("Compiling lp hash verification circuit...")
    await compile_project(circuit_path)
    # [1] create prover toml and witness
    print("Creating prover toml and witness...")
    await create_lp_hash_verification_prover_toml(
        lp_reservation_data=lps,
        compilation_build_folder=circuit_path
    )
    # [3] build verification key, create proof, and verify proof
    vk_file = "./target/vk"
    print("Building verification key...")
    await build_raw_verification_key(vk_file, circuit_path, BB)
    print("Creating proof...")
    public_inputs_as_fields, proof_as_fields = await create_proof(
        vk_path=vk_file,
        compilation_dir=circuit_path,
        bb_binary=BB
    )
    print("LP Hash proof gen successful!")
    encoded_vkey = await extract_vk_as_fields(vk_file, circuit_path, BB)
    vkey_hash, vkey_as_fields = encoded_vkey[0], encoded_vkey[1:]
    if verify:
        print("Verifying proof...")
        await verify_proof(vk_path=vk_file, compilation_dir=circuit_path, bb_binary=BB)
        print("LP Hash proof verified!")


    return RecursiveProofArtifact(
        verification_key=vkey_as_fields,
        proof=proof_as_fields,
        public_inputs=public_inputs_as_fields,
        key_hash=vkey_hash
    )


async def build_recursive_payment_proof_and_input(
    lps: list[LiquidityProvider],
    txn_data_no_segwit_hex: str,
    order_nonce_hex: str,
    expected_payout: int,
    circuit_path: str = "circuits/payment_verification",
    verify: bool = False
    ):
    print("Compiling payment verification circuit...")
    await compile_project(circuit_path)
    # [1] create prover toml and witnesses
    print("Creating prover toml and witness...")
    await create_payment_verification_prover_toml(
        txn_data_no_segwit_hex=txn_data_no_segwit_hex,
        lp_reservation_data=lps,
        lp_count=len(lps),
        order_nonce_hex=order_nonce_hex,
        expected_payout=expected_payout,
        compilation_build_folder=circuit_path
    )
    # [3] build verification key, create proof, and verify Proof
    vk = "./target/vk"
    print("Building verification key...")
    await build_raw_verification_key(vk, circuit_path, BB)
    print("Creating proof...")
    public_inputs_as_fields, proof_as_fields = await create_proof(vk_path=vk, compilation_dir=circuit_path, bb_binary=BB)
    if verify:
        print("Verifying proof...")
        await verify_proof(vk_path=vk, compilation_dir=circuit_path, bb_binary=BB)
        print("Payment verification proof verified!")
    print("Payment verification proof gen successful!")
    encoded_vkey = await extract_vk_as_fields(vk, circuit_path, BB)
    vkey_hash, vkey_as_fields = encoded_vkey[0], encoded_vkey[1:]

    return RecursiveProofArtifact(
        verification_key=vkey_as_fields,
        proof=proof_as_fields,
        public_inputs=public_inputs_as_fields,
        key_hash=vkey_hash
    )

"""
    block_hashes_encoded: pub [[Field; 2]; MAX_BASE_BLOCK_HASH_COUNT],
    first_block_height: pub u64,
    last_block_height: pub u64,
    last_retarget_block_hash: pub [u8; 32],
    last_retarget_block_height: pub u64,
    blocks: [Block; MAX_BASE_BLOCK_HASH_COUNT],
    last_retarget_block: Block
"""

async def create_block_base_prover_toml(
    blocks: list[Block],
    last_retarget_block: Block,
    circuit_path: str = "circuits/block_verification/base_block"
):
    block_hashes_encoded = pad_list(list(map(lambda block: split_hex_into_31_byte_chunks(normalize_hex_str(compute_block_hash(block))), blocks)), MAX_BLOCK_HASHES_PER_BASE_PROOF, ["0x00", "0x00"])
    first_block_height = blocks[0].height
    last_block_height = blocks[-1].height
    last_retarget_block_hash = hex_string_to_byte_array(normalize_hex_str(compute_block_hash(last_retarget_block)))
    last_retarget_block_height = last_retarget_block.height
    padded_blocks = pad_list(blocks, MAX_BLOCK_HASHES_PER_BASE_PROOF, NULL_BLOCK)
    print("Generating prover toml...")
    prover_toml_string = "\n".join([
        f"block_hashes_encoded={json.dumps(block_hashes_encoded)}",
        f"first_block_height={first_block_height}",
        f"last_block_height={last_block_height}",
        f"last_retarget_block_hash={json.dumps(last_retarget_block_hash)}",
        f"last_retarget_block_height={last_retarget_block_height}",
        "",
        "[last_retarget_block]",
        *await block_toml_encoder(last_retarget_block),
        "",
        *["[[blocks]]\n" + "\n".join(await block_toml_encoder(block)) + "\n\n" for block in padded_blocks]

    ])
    print("Creating witness...")
    print("Block Base Witness STDOUT", await create_witness(prover_toml_string, circuit_path, return_output=True))

@file_cache
async def build_block_base_proof_and_input(
    blocks: list[Block],
    last_retarget_block: Block,
    circuit_path: str = "circuits/block_verification/base_block",
    verify: bool = False,
):
    assert len(blocks) <= MAX_BLOCK_HASHES_PER_BASE_PROOF, "Too many blocks to generate proofs for"
    original_circuit_path = circuit_path
    temp_dir = tempfile.TemporaryDirectory()
    shutil.copytree("circuits", os.path.join(temp_dir.name, "circuits"))
    circuit_path = os.path.join(temp_dir.name, original_circuit_path)
    os.makedirs(circuit_path, exist_ok=True) 

    print("Compiling base block verification circuit...")
    await compile_project(circuit_path)
    
    print("Creating prover toml and witness...")
    await create_block_base_prover_toml(
        blocks=blocks,
        last_retarget_block=last_retarget_block,
        circuit_path=circuit_path
    )
    
    vk = "./target/vk"
    print("Building verification key...")
    await build_raw_verification_key(vk, circuit_path, BB)
    
    print("Creating proof...")
    public_inputs_as_fields, proof_as_fields = await create_proof(vk_path=vk, compilation_dir=circuit_path, bb_binary=BB)
    
    print("Base block proof gen successful!")
    encoded_vkey = await extract_vk_as_fields(vk, circuit_path, BB)
    vkey_hash, vkey_as_fields = encoded_vkey[0], encoded_vkey[1:]
    if verify: 
        print("Verifying proof...")
        await verify_proof(vk_path=vk, compilation_dir=circuit_path, bb_binary=BB)
        print("Base block proof verified!")

    return BaseBlockArtifact(
        proof_artifact=RecursiveProofArtifact(
            verification_key=vkey_as_fields,
            proof=proof_as_fields,
            public_inputs=public_inputs_as_fields,
            key_hash=vkey_hash
        )
    )



async def proof_gen_semaphore_wrapper(semaphore: asyncio.BoundedSemaphore, coro: Coroutine[Any, Any, T], id: Any) -> T:
    async with semaphore:
        print(f"Generating proof {id}")
        return await coro




# entry point for building block proofs
async def build_block_proof_and_input(
    blocks: list[Block],
    safe_block_height_delta: int,
    last_retarget_block: Block,
    max_concurrent_proof_gen: int = 1,
    verify: bool = False,
    circuit_path: str = "circuits/block_verification/entrypoint_block_tree"
):
    for block in blocks:
        assert block.height - (block.height % 2016) == last_retarget_block.height

    assert len(blocks) < MAX_BLOCK_HASHES_PER_ENTRYPOINT_PROOF, "Too many blocks to generate proofs for"


    block_chunk_count = len(blocks) // MAX_BLOCK_HASHES_PER_BASE_PROOF
    block_chunk_overflow = len(blocks) % MAX_BLOCK_HASHES_PER_BASE_PROOF
    total_proofs = block_chunk_count + (1 if block_chunk_overflow != 0 else 0)

    proof_coros = []
    bounded_semaphore = asyncio.BoundedSemaphore(max_concurrent_proof_gen)
    

    for i in range(block_chunk_count):
        coro = build_block_base_proof_and_input(
            blocks[i*MAX_BLOCK_HASHES_PER_BASE_PROOF:i*MAX_BLOCK_HASHES_PER_BASE_PROOF+MAX_BLOCK_HASHES_PER_BASE_PROOF],
            last_retarget_block,
            verify=verify
        )
        proof_coros.append(proof_gen_semaphore_wrapper(bounded_semaphore, coro, f"{i+1}/{total_proofs}"))

    if block_chunk_overflow != 0:
        coro = build_block_base_proof_and_input(
            blocks[block_chunk_count*MAX_BLOCK_HASHES_PER_BASE_PROOF:],
            last_retarget_block,
            verify=verify
        )
        proof_coros.append(proof_gen_semaphore_wrapper(bounded_semaphore, coro, f"{block_chunk_count+1}/{total_proofs}"))
    
    print("Base Block Proof Count: ", len(proof_coros))
    base_blocks = await asyncio.gather(*proof_coros)
    print("Base Blocks", [print(f"Block {i}", "\nVK Hash", base_block.proof_artifact.key_hash, "\nVerification Key", base_block.proof_artifact.verification_key, "\nPublic Inputs:", base_block.proof_artifact.public_inputs) for i, base_block in enumerate(base_blocks)])


    print("Compiling block entrypoint verification circuit...")
    await compile_project(circuit_path)

    print("Creating prover toml and witness...")
    await create_block_entrypoint_verification_prover_toml(
        blocks=blocks,
        last_retarget_block=last_retarget_block,
        safe_block_height=blocks[0].height,
        safe_block_height_delta=safe_block_height_delta,
        confirmation_block_height_delta=len(blocks) - safe_block_height_delta - 1,
        base_block_artifacts=base_blocks,
        circuit_path=circuit_path
    )

    vk = "./target/vk"
    print("Building verification key...")
    await build_raw_verification_key(vk, circuit_path, BB)
    
    print("Creating proof...")
    public_inputs_as_fields, proof_as_fields = await create_proof(vk_path=vk, compilation_dir=circuit_path, bb_binary=BB)
    
    print("Entrypoint block proof gen successful!")
    encoded_vkey = await extract_vk_as_fields(vk, circuit_path, BB)
    vkey_hash, vkey_as_fields = encoded_vkey[0], encoded_vkey[1:]
    if verify: 
        print("Verifying proof...")
        await verify_proof(vk_path=vk, compilation_dir=circuit_path, bb_binary=BB)
        print("Entrypoint block proof verified!")

    return BaseBlockArtifact(
        proof_artifact=RecursiveProofArtifact(
            verification_key=vkey_as_fields,
            proof=proof_as_fields,
            public_inputs=public_inputs_as_fields,
            key_hash=vkey_hash
        )
    )
    



"""

  block_hashes_encoded: pub [[Field; 2]; MAX_BLOCK_HASHES], 
  retarget_block_hash_encoded: pub [Field; 2],
  safe_block_height: pub u64,
  safe_block_height_delta: pub u64,
  confirmation_block_height_delta: pub u64,
  proposed_merkle_root_encoded: pub [Field; 2],
  retarget_block_height: pub u64,
  proposed_block: pub Block,
  base_block_verification_key: [Field; 114],
  proofs: [[Field; 93]; MAX_BLOCK_PROOFS]
"""

async def create_block_entrypoint_verification_prover_toml(
    blocks: list[Block],
    last_retarget_block: Block,
    safe_block_height: int,
    safe_block_height_delta: int,
    confirmation_block_height_delta: int,
    base_block_artifacts: list[BaseBlockArtifact],
    circuit_path: str = "circuits/block_verification/entrypoint_block_tree"
):

    block_hashes_encoded = pad_list(list(map(lambda block: split_hex_into_31_byte_chunks(normalize_hex_str(compute_block_hash(block))), blocks)), MAX_BLOCK_HASHES_PER_ENTRYPOINT_PROOF, ["0x00", "0x00"])
    retarget_block_hash_encoded = split_hex_into_31_byte_chunks(normalize_hex_str(compute_block_hash(last_retarget_block)))
    proposed_block = blocks[safe_block_height_delta]
    proposed_merkle_root_encoded = split_hex_into_31_byte_chunks(normalize_hex_str(proposed_block.merkle_root))
    retarget_block_height = last_retarget_block.height
    base_block_verification_key = base_block_artifacts[0].proof_artifact.verification_key
    for block_proof in base_block_artifacts:
        assert block_proof.proof_artifact.verification_key == base_block_verification_key

    #proofs_padded = pad_list([block_proof.proof_artifact.proof for block_proof in base_block_artifacts], 1, base_block_artifacts[0].proof_artifact.proof)
    proofs_padded = [base_block_artifacts[0].proof_artifact.proof]

    
    print("Compiling block entrypoint verification circuit...")
    await compile_project(circuit_path)

    print("Generating prover toml...")
    prover_toml_string = "\n".join(
        [
            f"block_hashes_encoded={json.dumps(block_hashes_encoded)}",
            f"retarget_block_hash_encoded={json.dumps(retarget_block_hash_encoded)}",
            f"safe_block_height={safe_block_height}",
            f"safe_block_height_delta={safe_block_height_delta}",
            f"confirmation_block_height_delta={confirmation_block_height_delta}",
            f"proposed_merkle_root_encoded={json.dumps(proposed_merkle_root_encoded)}",
            f"retarget_block_height={retarget_block_height}",
            f"base_block_verification_key={json.dumps(base_block_verification_key)}",
            f"proofs={json.dumps(proofs_padded)}",
            "",
            "[proposed_block]",
            *await block_toml_encoder(proposed_block),
        ]
    )
    print("Creating witness...")
    print(await create_witness(prover_toml_string, circuit_path, return_output=True))



async def build_giga_circuit_proof_and_input(
    txn_data_no_segwit_hex: str,
    lp_reservations: list[LiquidityProvider],
    retarget_block_header: Block,
    blocks: list[Block],
    order_nonce_hex: str,
    expected_payout: int,
    safe_block_height: int,
    safe_block_height_delta: int,
    circuit_path: str = "circuits/giga",
    verify: bool = False
    ):
    
    proposed_block_header = blocks[safe_block_height_delta]
    safe_block_header = blocks[0]
    print("Safe Block Height", safe_block_height)
    print("Proposed Block Height", proposed_block_header.height)
    assert safe_block_height == proposed_block_header.height - safe_block_height_delta
    # [1] build recursive proofs and inputs 
    sha_recursive_artifact = await build_recursive_sha256_proof_and_input(
        data_hex_str=txn_data_no_segwit_hex,
        verify=verify
    )
    print()
    lp_hash_recursive_artifact = await build_recursive_lp_hash_proof_and_input(
        lps=lp_reservations,
        verify=verify
    )
    print()
    block_recursive_artifact = await build_block_entrypoint_proof_and_input(
        safe_block_height=safe_block_height,
        safe_block_height_delta=safe_block_height_delta,
        blocks=blocks,
        last_retarget_block=retarget_block_header,
        verify=verify
    )
    print("block recursive public inputs")
    print(block_recursive_artifact.public_inputs)
    print("Block recursive key hash")
    print(block_recursive_artifact.key_hash)
    print()
    payment_recursive_artifact = await build_recursive_payment_proof_and_input(
        lps=lp_reservations,
        txn_data_no_segwit_hex=txn_data_no_segwit_hex,
        order_nonce_hex=order_nonce_hex,
        expected_payout=expected_payout,
        verify=verify
    )
    print()


    # [3] create prover toml and witnesses
    intermediate_hash_hex = hashlib.sha256(bytes.fromhex(normalize_hex_str(txn_data_no_segwit_hex))).hexdigest()
    txn_hash_hex = hashlib.sha256(bytes.fromhex(intermediate_hash_hex)).hexdigest()

    print("Generating merkle proof...")
    merkle_proof = generate_merkle_proof(
        txn_hashes=list(map(lambda hash: normalize_hex_str(hash), proposed_block_header.txns)),
        target_hash=bytes.fromhex(normalize_hex_str(txn_hash_hex))[::-1].hex()
    )
    print()

    confirmation_block_hash_hex = compute_block_hash(blocks[-1])
    proposed_block_hash_hex = compute_block_hash(proposed_block_header)
    safe_block_hash_hex = compute_block_hash(safe_block_header)
    retarget_block_hash_hex = compute_block_hash(retarget_block_header)
    

    print("Compiling giga circuit...")
    await compile_project(circuit_path)
    print("Creating prover toml and witness...")
    await create_giga_circuit_prover_toml(
        txn_hash_hex=txn_hash_hex,
        intermediate_hash_hex=intermediate_hash_hex,
        txn_data_no_segwit_hex=txn_data_no_segwit_hex,
        proposed_merkle_root_hex=proposed_block_header.merkle_root,
        proposed_merkle_proof=merkle_proof,
        lp_reservation_hash_hex=compute_lp_reservation_hash(lp_reservations),
        order_nonce_hex=order_nonce_hex,
        expected_payout=expected_payout,
        lp_reservation_data=lp_reservations,
        confirmation_block_hash_hex=confirmation_block_hash_hex,
        proposed_block_hash_hex=proposed_block_hash_hex,
        safe_block_hash_hex=safe_block_hash_hex,
        retarget_block_hash_hex=retarget_block_hash_hex,
        safe_block_height=safe_block_height,
        safe_block_height_delta=safe_block_height_delta,
        confirmation_block_height_delta=len(blocks) - safe_block_height_delta - 1,
        retarget_block_height=retarget_block_header.height,
        lp_hash_verification_key=lp_hash_recursive_artifact.verification_key,
        lp_hash_proof=lp_hash_recursive_artifact.proof,
        txn_hash_verification_key=sha_recursive_artifact.verification_key,
        txn_hash_proof=sha_recursive_artifact.proof,
        txn_hash_vk_hash_index=sha_recursive_artifact.key_hash_index,
        payment_verification_key=payment_recursive_artifact.verification_key,
        payment_proof=payment_recursive_artifact.proof,
        block_verification_key=block_recursive_artifact.verification_key,
        block_proof=block_recursive_artifact.proof,
        block_recursive_aggregation_object=block_recursive_artifact.public_inputs[-16:],
        compilation_build_folder=circuit_path
    )

    vk = "./target/vk"
    print("Building verification key...")
    await build_raw_verification_key(vk, circuit_path, BB)

    print("Creating proof...")
    public_inputs, proof = await create_proof(vk, circuit_path, BB)
    print("Giga circuit proof gen successful!")

    if verify:
        print("Verifying proof...")
        await verify_proof(vk, circuit_path, BB)
        print("Giga circuit proof verified!")

    print("Creating solidity proof...")
    proof_hex = normalize_hex_str(await create_solidity_proof(project_name="giga", compilation_dir=circuit_path))
    print("Giga circuit proof gen successful!")
    return SolidityProofArtifact(
        proof=proof_hex[1024:], # noir encodes the aggregation object into the first 512 bytes of the proof
        aggregation_object=public_inputs[-16:],
        full_public_inputs=public_inputs
    )

