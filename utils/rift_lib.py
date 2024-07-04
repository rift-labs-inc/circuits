# utils to create witness data and verify proofs in python 
import hashlib
from pydantic import BaseModel
import json

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

"""
struct Block {
    height: u64,
    version: Field,
    prev_block_hash: [u8; 32],
    merkle_root: [u8; 32],
    timestamp: Field,
    bits: Field,
    nonce: Field,
}

[proposed_block]
bits = ""
height = ""
merkle_root = ["", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", ""]
nonce = ""
prev_block_hash = ["", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", ""]
timestamp = ""
version = ""



proposed_block_hash_encoded: pub [Field; 2],
safe_block_hash_encoded: pub [Field; 2],
retarget_block_hash_encoded: pub [Field; 2],
safe_block_height: pub u64,
block_height_delta: pub u64,
proposed_block: Block,
safe_block: Block,
retarget_block: Block,
inner_block_hashes_encoded: [[Field; 2]; INNER_BLOCK_COUNT],
inner_blocks: [Block; INNER_BLOCK_COUNT]
"""

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

async def create_prover_toml_witness(
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
