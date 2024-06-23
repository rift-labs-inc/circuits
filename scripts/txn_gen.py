import requests
import hashlib
import os

import requests
import os

def hex_to_u8_array(hex_str):
    """Convert a hex string to a Rust-like [u8; 32] array representation."""
    bytes_array = bytes.fromhex(hex_str)
    return '[' + ','.join(f'0x{byte:02x}' for byte in bytes_array) + ']'

def fetch_block_data(block_hash, proposed_txn_hash):
    """Fetch the transaction hashes and Merkle root for a given block hash from blockchain.info,
    including a proposed transaction hash."""
    url = f"https://blockchain.info/rawblock/{block_hash}"
    response = requests.get(url)
    block_data = response.json()
    
    # Extract the list of transaction hashes and convert them
    txn_hashes = [hex_to_u8_array(txn['hash']) for txn in block_data['tx']]
        
    # Extract and convert the Merkle root
    merkle_root = hex_to_u8_array(block_data['mrkl_root'])
    
    # Convert the proposed transaction hash
    proposed_txn = hex_to_u8_array(proposed_txn_hash)

    # find proposed txn index
    txn_hashes = [txn['hash'] for txn in block_data['tx']]
    
    txn_data = None  # Default to None if no transaction matches
    for txn in block_data['tx']:
        if txn['hash'].lower() == proposed_txn_hash.lower():
            txn_data = txn
            break  # Exit the loop as soon as the matching transaction is found
    if txn_data is None:
        raise Exception("Txn hash could not be found in the given block")
    
    # Locate local directory and save to txns.txt
    output_location = os.path.dirname(os.path.realpath(__file__))
    with open(f"{output_location}/../circuits/txn_verification/Prover.toml", "w") as f:
        # Write Merkle root and proposed transaction in the specified format
        f.write(f"merkle_root = {merkle_root}\n")
        f.write(f"proposed_txn_hash = {proposed_txn}\n")
        
    merkle_root = (block_data['mrkl_root'])
    
    
    return txn_hashes, merkle_root, txn_data

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

def generate_merkle_proof(txn_hashes, target_hash):
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
    print(f"Proof: {proof}")
    print(f"Depth of the Merkle Tree: {depth}")

    # add proof to Prover.toml with hashes in u8 32 byte array format EXAMPLE:
    # [[merkle_proof]]
    # bytes = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x23, 0x66, 0xf4, 0xbd, 0x69, 0x61, 0x22, 0xc3, 0xe1, 0x10, 0x96, 0xdf, 0xda, 0xca, 0xf7, 0x6b, 0x42, 0x8b, 0x2a, 0x3f, 0x23, 0x18]
    # flag = true

    output_location = os.path.dirname(os.path.realpath(__file__))

    with open(f"{output_location}/../circuits/txn_verification/Prover.toml", "a") as f:
        for i, (hash, direction) in enumerate(proof):
            flag = "true" if direction == 'right' else "false"
            f.write(f"[[proposed_merkle_proof]] # {i+1}\nhash = {hex_to_u8_array(hash)}\ndirection = {flag}\n\n")
        
        # Determine how many padding entries are needed
        num_padding_entries = 20 - len(proof)
        
        # Padding with 0 u8 32-byte arrays if needed
        for j in range(num_padding_entries):
            f.write(f"[[proposed_merkle_proof]] # {len(proof) + j + 1}\nhash = {hex_to_u8_array('00'*32)}\ndirection = false\n\n")

    return proof

def verify_merkle_proof(target_hash, proof, merkle_root):
    """Verify the Merkle proof for the target hash."""
    current_hash = target_hash
    for sibling_hash, direction in proof:
        if direction == 'left':
            current_hash = hash_pairs(sibling_hash, current_hash)
        else:
            current_hash = hash_pairs(current_hash, sibling_hash)

    print(f"Computed Merkle root: {current_hash}")
    print(f"Expected Merkle root: {merkle_root }")
    return current_hash == merkle_root

# Example usage
block_hash = "0000000000000000000314bd6f3ffc1281b0258b20444a9627b22ddaebe90112"
proposed_txn_hash = "9599579a0fe69353dd4b72c7c969bead1ccb8389b6db57498285b79cd956f2df"
# Fetch data
txn_hashes, merkle_root, txn_data = fetch_block_data(block_hash, proposed_txn_hash)

print("TXN_DATA", txn_data)

# [0] generate merkle proof from txn_hashes
proof = generate_merkle_proof(txn_hashes, proposed_txn_hash)

# [1] verify the merkle proof
is_valid = verify_merkle_proof(proposed_txn_hash, proof, merkle_root)
print(f"\nIs the Merkle proof valid? {is_valid}")

# test what hash_pairs returns
print(f"\nNum txn hashes: {len(txn_hashes)}")
print(f"merkle root: {merkle_root}")
print(f"proposed txn hash: {proposed_txn_hash}")
print(f"\nHash pairs of merkle root + proposed txn hash:\n{hash_pairs(merkle_root, proposed_txn_hash)}")
