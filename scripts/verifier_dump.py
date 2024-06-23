# Import the toml library
import toml
import os

# Assuming the TOML data is stored in a file named 'data.toml'

file_path = os.path.dirname(os.path.realpath(__file__)) + "/../circuits/block_verification/Verifier.toml"

# Function to print 'bytes32' values from the TOML data
def print_raw_public_input_from_toml():
    # Load the TOML file
    try:
        with open(file_path, 'r') as file:
            data = toml.load(file)
            
            # Previous block hash (outside of ProposedBlock)
            if "previous_block_hash" in data:
                for item in data["previous_block_hash"]:
                    print(item)
            
            # Previous block height (also outside of ProposedBlock)
            if "previous_block_height" in data:
                print(data["previous_block_height"])
            
            # RetargetBlock struct order
            if "retarget_block" in data:
                retarget_block = data["retarget_block"]
                print(retarget_block["bits"])
                print(retarget_block["height"])
                print(retarget_block["timestamp"])

            # ProposedBlock struct order
            if "proposed_block" in data:
                proposed_block = data["proposed_block"]
                print(*proposed_block["block_hash"], sep='\n')
                print(proposed_block["height"])
                print(proposed_block["version"])
                print(*proposed_block["prev_block_hash"], sep='\n')
                print(*proposed_block["merkle_root"], sep='\n')
                print(proposed_block["timestamp"])
                print(proposed_block["bits"])
                print(proposed_block["nonce"])


    except Exception as e:
        print(f"An error occurred: {e}")

# Call the function with the path to the TOML file
print_raw_public_input_from_toml()

