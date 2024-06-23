# Grabs blocks from btc block data api
import json
from textwrap import dedent
import asyncio
import math
import aiohttp
import hashlib
from typing import TypedDict
import os
import subprocess


def output_data_library(proposed_block_data_structs):
    print("GENERATED DATA LIBRARY:")
    print(
        f"""
library TestLib {{
    struct ProposedBlock {{
        uint256 proposed_height;
        bytes32 block_hash;
        uint32 version;
        bytes32 prev_block_hash;
        bytes32 merkle_root;
        uint32 timestamp;
        uint32 bits;
        uint32 nonce;
        bytes proof;
    }}

    function getTestBlocks() internal returns (ProposedBlock[] memory blocks) {{
        blocks = new ProposedBlock[]({len(proposed_block_data_structs)});
        """
    )

    for i, data in enumerate(proposed_block_data_structs):
        print(f"blocks[{i}] = ", data)

    print("\t}\n}")


class StaleBlockDetected(Exception):
    pass


class BitcoinApiFailure(Exception):
    pass


class BlockHeader(TypedDict):
    block_hash: str  # hexstr
    version: int
    prev_block_hash: str  # hexstr
    merkle_root: str  # hexstr
    timestamp: int
    bits: int
    nonce: int


class BitcoinBlockDataHandler:
    def __init__(self) -> None:
        self._block_height_url = (
            lambda x: f"https://blockchain.info/block-height/{x}?format=json"
        )

    async def get_block_at_height(self, height: int) -> dict:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                self._block_height_url(height), ssl=False
            ) as raw_resp:
                data = await raw_resp.json()

                if "blocks" not in data:
                    raise BitcoinApiFailure("response text:", await raw_resp.text())

                if len(data["blocks"]) > 1:
                    raise StaleBlockDetected(
                        f"Block height: {height}, has more than 1 block"
                    )

                return data["blocks"][0]

    @staticmethod
    def extract_block_header(full_block: dict) -> BlockHeader:
        return {
            "block_hash": full_block["hash"],
            "version": full_block["ver"],
            "prev_block_hash": full_block["prev_block"],
            "merkle_root": full_block["mrkl_root"],
            "timestamp": full_block["time"],
            "bits": full_block["bits"],
            "nonce": full_block["nonce"],
        }

    @staticmethod
    # TODO: THIS DOES NOT WORK?
    def hash_block_header(block_header: BlockHeader) -> str:  # hexstr
        # Concatenate and serialize the block header fields
        serialized_header = (
            block_header["version"].to_bytes(4, byteorder="little", signed=False)
            + bytes.fromhex(block_header["prev_block_hash"])
            + bytes.fromhex(block_header["merkle_root"])
            + block_header["timestamp"].to_bytes(4, byteorder="little", signed=False)
            + block_header["bits"].to_bytes(4, byteorder="little", signed=False)
            + block_header["nonce"].to_bytes(4, byteorder="little", signed=False)
        )
        print(
            "version bytes",
            block_header["version"].to_bytes(4, byteorder="little", signed=False).hex(),
        )
        print("what is this ser header", serialized_header.hex())

        # Double hash the serialized header using SHA-256
        first_hash = hashlib.sha256(serialized_header).digest()
        second_hash = hashlib.sha256(first_hash).digest()

        # Convert the double-hashed bytes to hexadecimal string
        hex_str = second_hash.hex()

        # Bitcoin's block hash is in little-endian byte order, so we need to reverse the byte order
        return hex_str

    @staticmethod
    def encode_to_noir_byte_array(hexstr: str) -> str:
        if len(hexstr) % 2 != 0:
            raise Exception("Not encodable, needs to be mod 2 length")
        if len(hexstr) == 0:
            return "[]"
        # returns array str
        window_size = 2
        array_str = ""
        for i in range(0, len(hexstr), window_size):  # Change made here
            array_str += f"0x{hexstr[i: i + window_size]},"
        return f"[{array_str[:-1]}]"

    @staticmethod
    def dump_block_header_to_toml(data: BlockHeader, height: int):
        struct_data = ""
        for key in data:
            if key == "block_hash" or key == "prev_block_hash" or key == "merkle_root":
                struct_data += f"{key} = {BitcoinBlockDataHandler.encode_to_noir_byte_array(data[key])}\n"
            else:
                struct_data += f"{key} = {data[key]}\n"
        struct_data += f"height = {height}"

    @staticmethod
    def dump_header_to_noir_struct(data: BlockHeader, data_out: str):
        # let block_header = BlockHeader { block_hash, version, prev_block_hash, merkle_root, timestamp, bits, nonce };
        struct_data = ""
        for key in data:
            if key == "block_hash" or key == "prev_block_hash" or key == "merkle_root":
                struct_data += f" {key}: {BitcoinBlockDataHandler.encode_to_noir_byte_array(data[key])},"
            else:
                struct_data += f" {key}: {data[key]},"

        final_struct = "BlockHeader {" + struct_data[:-1] + "};"
        with open(data_out, "w+") as f:
            f.write(final_struct)

    @staticmethod
    def create_prover_toml(
        previous_block_hash_noir_array_str: str,
        previous_block_height: int,
        retarget_block_timestamp: int,
        retarget_block_bits: int,
        retarget_block_height: int,
        proposed_block_height: int,
        proposed_block_block_hash_noir_array_str: str,
        proposed_block_version: int,
        proposed_block_prev_block_hash_noir_array_str: str,
        proposed_block_merkle_root_noir_array_str: str,
        proposed_block_timestamp: int,
        proposed_block_bits: int,
        proposed_block_nonce: int,
    ):
        return dedent(
            f"""
            previous_block_hash = {previous_block_hash_noir_array_str}
            previous_block_height = {previous_block_height}

            [retarget_block]
            timestamp = {retarget_block_timestamp}
            bits = {retarget_block_bits}
            height = {retarget_block_height}

            [proposed_block]
            height = {proposed_block_height}
            block_hash = {proposed_block_block_hash_noir_array_str}
            version = {proposed_block_version} 
            prev_block_hash = {proposed_block_prev_block_hash_noir_array_str}
            merkle_root = {proposed_block_merkle_root_noir_array_str} 
            timestamp = {proposed_block_timestamp} 
            bits = {proposed_block_bits} 
            nonce = {proposed_block_nonce} 
            """
        )


def test():
    api = BitcoinBlockDataHandler()
    print(api.get_block_at_height(1))


async def build_circuit_input(
    HEIGHT,
    PROPOSED_BLOCK_HEADER: BlockHeader | None = None,
    OUTPUT_TEST_DATA: bool = False,
    PROOF_IN_OUTPUT_DATA=True,
    OUTPUT_FULL_PROPOSED_BLOCK=False,
    OUTPUT_LOCATION="./block_data.json",
):
    # Edit:
    output_location = (
        os.path.dirname(os.path.realpath(__file__))
        + "/../circuits/block_verification/Prover.toml"
    )
    OUT = output_location

    # Shouldn't need to touch:
    PREVIOUS_HEIGHT = HEIGHT - 1
    LAST_RETARGET_BLOCK_HEIGHT = math.floor(HEIGHT / 2016) * 2016
    print("Proposed Block", HEIGHT)
    print("Last Block", HEIGHT - 1)
    print("Last Retarget", LAST_RETARGET_BLOCK_HEIGHT)

    handler = BitcoinBlockDataHandler()

    if PROPOSED_BLOCK_HEADER is not None:
        # just pass the proposed block data provided in args, get the retarget and previous block
        last_retarget_block, last_block = await asyncio.gather(
            *[
                handler.get_block_at_height(LAST_RETARGET_BLOCK_HEIGHT),
                handler.get_block_at_height(PREVIOUS_HEIGHT),
            ]
        )
        proposed_block_header = PROPOSED_BLOCK_HEADER
    else:
        last_retarget_block, last_block, proposed_block = await asyncio.gather(
            *[
                handler.get_block_at_height(LAST_RETARGET_BLOCK_HEIGHT),
                handler.get_block_at_height(PREVIOUS_HEIGHT),
                handler.get_block_at_height(HEIGHT),
            ]
        )
        if OUTPUT_FULL_PROPOSED_BLOCK:
            json.dump(proposed_block, open(OUTPUT_LOCATION, "w+"), indent=2)
        proposed_block_header = BitcoinBlockDataHandler.extract_block_header(
            proposed_block
        )

    last_retarget_header = BitcoinBlockDataHandler.extract_block_header(
        last_retarget_block
    )
    last_block_header = BitcoinBlockDataHandler.extract_block_header(last_block)

    prover_str = BitcoinBlockDataHandler.create_prover_toml(
        previous_block_hash_noir_array_str=BitcoinBlockDataHandler.encode_to_noir_byte_array(
            last_block_header["block_hash"]
        ),
        previous_block_height=HEIGHT - 1,
        retarget_block_timestamp=last_retarget_header["timestamp"],
        retarget_block_bits=last_retarget_header["bits"],
        retarget_block_height=LAST_RETARGET_BLOCK_HEIGHT,
        proposed_block_height=HEIGHT,
        proposed_block_block_hash_noir_array_str=BitcoinBlockDataHandler.encode_to_noir_byte_array(
            proposed_block_header["block_hash"]
        ),
        proposed_block_version=proposed_block_header["version"],
        proposed_block_prev_block_hash_noir_array_str=BitcoinBlockDataHandler.encode_to_noir_byte_array(
            proposed_block_header["prev_block_hash"]
        ),
        proposed_block_merkle_root_noir_array_str=BitcoinBlockDataHandler.encode_to_noir_byte_array(
            proposed_block_header["merkle_root"]
        ),
        proposed_block_timestamp=proposed_block_header["timestamp"],
        proposed_block_bits=proposed_block_header["bits"],
        proposed_block_nonce=proposed_block_header["nonce"],
    )

    with open(OUT, "w+") as f:
        f.write(prover_str)

    if OUTPUT_TEST_DATA:
        block_verification_dir = os.path.dirname(output_location)
        proof_file_path = block_verification_dir + "/proofs/circuits.proof"

        # Check if the proof file exists and read it
        old_hexstr = None
        if os.path.exists(proof_file_path):
            try:
                with open(proof_file_path, "r") as proof_file:
                    old_hexstr = proof_file.read()
            except Exception as e:
                print(f"Failed to read existing proof file: {e}")
                return

        # Change to the directory where nargo should be run
        os.chdir(block_verification_dir)

        print("Building proof...")
        # Run nargo prove
        process = await asyncio.create_subprocess_shell("nargo prove", shell=True)
        await process.wait()  # Wait for the process to complete

        # Read the proof file again, after running nargo prove
        new_hexstr = None
        try:
            with open(proof_file_path, "r") as proof_file:
                new_hexstr = proof_file.read()
        except Exception as e:
            print(f"Failed to read new proof file: {e}")
            return

        # Compare the old and new contents
        if old_hexstr != new_hexstr:
            # it updated!
            # print("The proof file has changed.")
            proof = new_hexstr

            # str here means hexstr
            def build_test_str(
                proposed_height: int,
                block_hash: str,
                version: int,
                prev_block_hash: str,
                merkle_root: str,
                timestamp: int,
                bits: int,
                nonce: int,
                proof: str,
            ):
                return f"""ProposedBlock({{
    proposed_height: {proposed_height},
    block_hash: 0x{block_hash},
    version: {version},
    prev_block_hash: 0x{prev_block_hash},
    merkle_root: 0x{merkle_root},
    timestamp: {timestamp},
    bits: {bits},
    nonce: {nonce},
    proof: hex"{proof}"
}});
                """

            if not PROOF_IN_OUTPUT_DATA:
                proof = "00"
            return build_test_str(
                proposed_height=HEIGHT,
                block_hash=proposed_block_header["block_hash"],
                version=proposed_block_header["version"],
                prev_block_hash=proposed_block_header["prev_block_hash"],
                merkle_root=proposed_block_header["merkle_root"],
                timestamp=proposed_block_header["timestamp"],
                bits=proposed_block_header["bits"],
                nonce=proposed_block_header["nonce"],
                proof=proof,
            )

        else:
            print(
                "The proof file has not changed or nargo prove did not update the file."
            )


def build_single_block_input_from_main_chain():
    HEIGHT = 836715
    OUTPUT_TEST_DATA = False
    OUTPUT_FULL_PROPOSED_BLOCK = True
    proposed_block_test_struct = asyncio.run(
        build_circuit_input(
            HEIGHT,
            OUTPUT_TEST_DATA=OUTPUT_TEST_DATA,
            OUTPUT_FULL_PROPOSED_BLOCK=OUTPUT_FULL_PROPOSED_BLOCK,
        )
    )
    print("TEST DATA:\n", proposed_block_test_struct)


def build_single_block_input_from_known_header():
    POT_HEIGHT = 449695
    PROPOSED_BLOCK_HEADER: BlockHeader = {
        "block_hash": "0000000000000000001a5db47750928e1cfb94ee03ed88b0343c7d1cf6387f9a",  # hexstr
        "version": 536870912,
        "prev_block_hash": "0000000000000000021140322d6f3bbc783c2fe45dca64d73847e3cd1644c389",  # hexstr
        "merkle_root": "81d0e09b909103d71004ee240c083627dde262a88d8eb494dce57b4c2dfab1a4",  # hexstr
        "timestamp": 1485203925,
        "bits": 402836551,
        "nonce": 2178712530,
    }
    OUTPUT_TEST_DATA = True
    proposed_block_test_struct = asyncio.run(
        build_circuit_input(
            POT_HEIGHT,
            PROPOSED_BLOCK_HEADER=PROPOSED_BLOCK_HEADER,
            OUTPUT_TEST_DATA=OUTPUT_TEST_DATA,
        )
    )
    print("TEST DATA:\n", proposed_block_test_struct)


def build_sequential_blocks_from_main_chain():
    # FOR OMMER TEST:
    # this is an orphan block: 449695
    START_HEIGHT = 449568
    END_HEIGHT = 449695

    # START_HEIGHT = 834624
    # END_HEIGHT = 834626 + 1
    proposed_block_data_structs = []
    for i in range(END_HEIGHT - START_HEIGHT):
        block_num = START_HEIGHT + i
        # we dont want proof for first block b/c it's used in constructor
        proposed_block_data_structs.append(
            asyncio.run(
                build_circuit_input(
                    block_num, OUTPUT_TEST_DATA=True, PROOF_IN_OUTPUT_DATA=i != 0
                )
            )
        )
        print("Finished block", i + 1, "of", END_HEIGHT - START_HEIGHT)
    output_data_library(proposed_block_data_structs)


if __name__ == "__main__":
    build_single_block_input_from_main_chain()
