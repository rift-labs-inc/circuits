import os
import json

def read_json_files(directory):
    files = os.listdir(directory)
    data = {}
    for json_file in files:
        file_path = os.path.join(directory, json_file)
        with open(file_path, 'r') as file:
            data[json_file] = json.load(file)
    return data

def main():
    directory = './generated_circuit_data'
    
    all_chunks = read_json_files(directory)

    all_keys = {}
    largest_circuit_bytelen = 1000
    for file, chunk in all_chunks.items():
        for bytelen in chunk:
            all_keys[int(bytelen)] = chunk[bytelen]["vk_as_fields"][0]
            largest_circuit_bytelen = max(largest_circuit_bytelen, int(bytelen))
    print("global CIRCUIT_HASH_LIST = [", end="")
    [print(all_keys[i], end="," if i != largest_circuit_bytelen else "") for i in range(1, largest_circuit_bytelen + 1)]
    print("];")
    
    

if __name__ == '__main__':
    main()
