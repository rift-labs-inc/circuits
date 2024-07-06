# utils to create witness data and verify proofs in python 
import hashlib
from pydantic import BaseModel
import json
from eth_abi.abi import encode as eth_abi_encode


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
