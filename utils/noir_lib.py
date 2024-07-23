import asyncio
import aiofiles
import tempfile
import subprocess
import json
import os
from typing import Tuple


# UTILS

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

async def compile_project(compilation_dir: str, return_binary = False):
    command = "nargo compile --only-acir"
    await run_command(command, compilation_dir, strict_failure=False)
    if return_binary:
        async with aiofiles.open(os.path.join(compilation_dir, "target/acir.gz"), "rb") as file:
            return await file.read()

async def create_witness(prover_toml_string: str, compilation_dir: str):
    async with aiofiles.open(
        os.path.join(compilation_dir, "Prover.toml"), "w+"
    ) as file:
        await file.write(prover_toml_string)

    command = "nargo execute witness"
    await run_command(command, compilation_dir, strict_failure=False)


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
    vk_file: str,  compilation_dir: str, bb_binary: str
):
    command = f"{bb_binary} write_vk -o {vk_file}"
    await run_command(command, compilation_dir)

async def extract_vk_as_fields(vk_file: str, compilation_dir: str, bb_binary: str) -> list:
    command = f"{bb_binary} vk_as_fields -k {vk_file} -o -"
    stdout = await run_command(command, compilation_dir)
    return json.loads(stdout)

async def verify_proof(vk_path: str, compilation_dir: str, bb_binary: str):
    command = f"{bb_binary} verify -p ./target/proof -k {vk_path}"
    await run_command(command, compilation_dir)

async def create_proof(
    vk_path: str, pub_inputs: int, compilation_dir: str, bb_binary: str
):
    command = f"{bb_binary} prove -o ./target/proof"
    # Build the proof
    await run_command(command, compilation_dir)

    command = f"{bb_binary} proof_as_fields -p ./target/proof -k {vk_path} -o -"
    # Extract generated proof fields
    stdout = await run_command(command, compilation_dir) 
    proof_output = json.loads(stdout)
    return proof_output[:pub_inputs], proof_output[pub_inputs:]

