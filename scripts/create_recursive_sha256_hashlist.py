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
    
    total_bytes = 7000
    directory = './generated_sha_circuits'
    all_chunks = read_json_files(directory)
    all_keys = {}
    for file, chunk in all_chunks.items():
        for bytelen in chunk:
            all_keys[int(bytelen)] = chunk[bytelen]["vk_as_fields"][0]
    print("global CIRCUIT_HASH_LIST = [", end="")
    [print(all_keys[i], end="," if i != total_bytes else "") for i in range(1, total_bytes+1)]
    print("];")
    
    

if __name__ == '__main__':
    main()
