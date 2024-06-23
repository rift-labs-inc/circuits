import requests

def get_block_height():
    response = requests.get("https://blockchain.info/q/getblockcount")
    return response.json()

def get_block_time(height):
    response = requests.get(f"https://blockchain.info/block-height/{height}?format=json")
    block_data = response.json()
    # Takes the first block (since blocks with the same height might be on different chains)
    return block_data['blocks'][0]['time']

def find_longest_confirmation_time(start_height, number_of_blocks):
    times = []
    for i in range(start_height, start_height + number_of_blocks + 1):
        time = get_block_time(i)
        times.append(time)

    # Calculate the longest confirmation time between consecutive blocks
    longest_time = 0
    longest_index = 0
    for i in range(1, len(times)):
        diff = times[i] - times[i - 1]
        if diff > longest_time:
            longest_time = diff
            longest_index = i - 1

    return longest_index, longest_time

# Main execution
latest_height = get_block_height()
start_height = latest_height - 100  # Example: check the last 100 blocks

longest_index, longest_time = find_longest_confirmation_time(start_height, 6)
print(f"Longest confirmation time between consecutive blocks is {longest_time} seconds, starting at block height {start_height + longest_index}.")
