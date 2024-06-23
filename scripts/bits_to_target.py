from hashlib import sha256

# data
version = 536887296
prev_block_hash = "0000000000000000000179226269feaacff777d42f3fa0d5b92dbceddfe156be"
merkle_root = "32c3aee57709882eaff5a047dc443915af1e42874df898dba76c57f530b2ed7b"
timestamp = 1710453557
bits = 486594666
nonce = 623717702
block_height = 0

def reverse_bytes(hex_str):
    bytes_str = bytes.fromhex(hex_str)
    return bytes_str[::-1]

def double_sha256(data):
    return sha256(sha256(data).digest()).digest()

def bits_to_target(bits):
    exponent = bits >> 24
    coefficient = bits & 0xffffff
    target = coefficient * (2**(8*(exponent - 3)))
    print("Exponent:", exponent)
    print("Coefficient:", coefficient)
    print("Target:", target)
    return target

serialized_block_header = (
    version.to_bytes(4, byteorder='little') +
    reverse_bytes(prev_block_hash) +
    reverse_bytes(merkle_root) +
    timestamp.to_bytes(4, byteorder='little') +
    bits.to_bytes(4, byteorder='little') +
    nonce.to_bytes(4, byteorder='little')
)

hash_result = double_sha256(serialized_block_header)
hash_result_reversed = hash_result[::-1]
target = bits_to_target(bits)
actual_time= 1343368
expected_time= 1209600
ratio = actual_time/expected_time

# new_target_int_full_precision = 342388188602651835427300510947335991804279054583248783
new_target_int_full_precision = int(target * ratio)
new_target_hex_full_precision = hex(new_target_int_full_precision)[2:]
new_target_hex_padded = new_target_hex_full_precision.rjust(64, '0')

print("Serialized Block Header:", serialized_block_header.hex())
print("\nDouble SHA-256 Hash:", hash_result_reversed.hex())
print("Target Int:", target)
print("Target Hex:", hex(target))
print("Hash <= Target:", int(hash_result_reversed.hex(), 16) <= target)
print ("Actual Time:", actual_time)
print("Expected Time:", expected_time)
print("Ratio:", ratio)
print("New Target Int:", new_target_int_full_precision)
print("New Target Hex:", new_target_hex_padded)

