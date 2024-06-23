# Economic Security Threshold
import requests

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

def get_bitcoin_hash_rate():
    # URL for Blockchain.com API to get the current Bitcoin hash rate
    url = "https://api.blockchain.info/q/hashrate"
    
    # Make a request to the API
    response = requests.get(url)
    # Check if the request was successful
    if response.status_code != 200:
        Exception("Failed to retrieve data: ", response.status_code)
    # convert from gigahashes/sec to hashes/sec
    return int(response.text) * 1000000000

def get_bitcoin_difficulty():
    # URL for Blockchain.com API to get the current Bitcoin network difficulty
    url = "https://api.blockchain.info/q/getdifficulty"
    
    # Make a request to the API
    response = requests.get(url)
    
    # Check if the request was successful
    if response.status_code != 200:
        Exception("Failed to retrieve data: ", response.status_code)
    return float(response.text)

def convert_seconds_to_natural_time(total_seconds):
    # Calculate days, hours, minutes and seconds
    days = total_seconds // (24 * 3600)
    total_seconds %= (24 * 3600)
    hours = total_seconds // 3600
    total_seconds %= 3600
    minutes = total_seconds // 60
    seconds = total_seconds % 60
    
    # Build the formatted time string
    time_str = ""
    if days > 0:
        time_str += f"{int(days)} days "
    if hours > 0:
        time_str += f"{int(hours)} hours "
    if minutes > 0:
        time_str += f"{int(minutes)} minutes "
    if seconds > 0 or time_str == "":
        time_str += f"{int(seconds)} seconds"
    
    return time_str.strip()

def get_current_btc_price():
    url = "https://min-api.cryptocompare.com/data/price?fsym=BTC&tsyms=USD"

    response = requests.get(url)
    response.raise_for_status()  # Raises an error for bad responses (4XX or 5XX)

    # Parse the JSON response
    data = response.json()
    btc_price = data['USD']
    return btc_price


def calculate_expected_btc(miner_hash_rate, network_hash_rate, block_reward, time_period_seconds):
    # Constants
    block_time_seconds = 600  # Average time (in seconds) it takes to mine a block (10 minutes)
    
    # Calculate the number of blocks expected to be mined in the time period
    blocks_in_time_period = time_period_seconds / block_time_seconds
    
    # Calculate the expected BTC earnings
    expected_btc = (miner_hash_rate / network_hash_rate) * block_reward * blocks_in_time_period
    return expected_btc

def exahash_to_hash(hash_rate: float):
    return hash_rate * 1000000000000000000

def main():
    ATTACKER_HASH_RATE_EXAHASH = 17
    CONFIRMATION_BLOCKS = 6
    BTC_REWARD = 3.125
    BTCUSD_EXCHANGE_RATE = get_current_btc_price() 
    

    # Your machine's hash rate (e.g., 100 TH/s, which is 100e12 H/s)
    hash_rate_per_second = exahash_to_hash(ATTACKER_HASH_RATE_EXAHASH) 
    print(hash_rate_per_second)

    network_hash_rate = get_bitcoin_hash_rate() 
    #hash_rate_per_second = network_hash_rate

    current_difficulty = get_bitcoin_difficulty()
    print("Attacker Network Control (%)", (hash_rate_per_second/network_hash_rate)*100)

    # Calculate the estimated time
    time_seconds = calculate_mining_time(hash_rate_per_second, current_difficulty)

    # Convert seconds to days for a more human-readable format
    time_to_implosion = time_seconds * CONFIRMATION_BLOCKS 
    btc_earned = calculate_expected_btc(hash_rate_per_second, network_hash_rate, BTC_REWARD, time_to_implosion)
    opportunity_cost = CONFIRMATION_BLOCKS * btc_earned * BTCUSD_EXCHANGE_RATE


    print("Time to drain liquidity providers", convert_seconds_to_natural_time(time_to_implosion))
    print("Opportunity Cost ($)", format(opportunity_cost, ","))

if __name__ == "__main__":
    main()
