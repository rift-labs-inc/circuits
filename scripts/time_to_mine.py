def calculate_mining_time(hash_rate_per_second, current_difficulty):
    """
    Calculate the estimated time to mine a single Bitcoin block.
    
    Parameters:
    - hash_rate_per_second (float): The hash rate of the mining machine in hashes per second (H/s).
    - current_difficulty (float): The current network difficulty target.
    
    Returns:
    - float: The estimated time to mine one block, in seconds.
    """
    
    # The current network difficulty target formula is:
    # difficulty = difficulty_1_target / current_target
    #
    # However, to simplify, we use the difficulty directly as provided by network stats.
    # The probability of finding a valid block in one hash attempt is 1 / (2^32 * difficulty).
    # Therefore, the expected number of hashes needed is 2^32 * difficulty.
    # Time to find a block is then expected hashes divided by hash rate.
    
    expected_hashes = 2**32 * current_difficulty
    time_to_mine_seconds = expected_hashes / hash_rate_per_second
    
    return time_to_mine_seconds

# Example usage:

# Your machine's hash rate (e.g., 100 TH/s, which is 100e12 H/s)

hash_rate_per_second = 17700000000000000000


# Current network difficulty (as of writing, ~23 trillion, but this number changes)
current_difficulty = 88.10e12

# Calculate the estimated time
time_seconds = calculate_mining_time(hash_rate_per_second, current_difficulty)

# Convert seconds to days for a more human-readable format
time_days = time_seconds / (60)

print(f"Estimated time to mine one Bitcoin block: {time_days:.2f} minutes")
