#!/bin/bash

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    echo "Error: jq is not installed. Please install jq to run this script."
    exit 1
fi

# Check if curl is installed
if ! command -v curl &> /dev/null; then
    echo "Error: curl is not installed. Please install curl to run this script."
    exit 1
fi

# Set default values
OUTPUT_DIR="tests/data"
HEIGHTS=(854136 858564 856800 858565 858566 858567 858568)

# Function to display usage
usage() {
    echo "Usage: $0 [-h <height1,height2,...>] [-d <output_directory>]"
    echo "  -h: Comma-separated list of block heights (optional, default: 856800,858564,858565,858566,858567,858568)"
    echo "  -d: Output directory (optional, default: tests/data)"
    exit 1
}

# Parse command line arguments
while getopts "h:d:" opt; do
    case $opt in
        h) IFS=',' read -ra HEIGHTS <<< "$OPTARG" ;;
        d) OUTPUT_DIR=$OPTARG ;;
        *) usage ;;
    esac
done

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Download blocks
for height in "${HEIGHTS[@]}"; do
    echo "Downloading block at height $height..."
    
    # Get block hash
    block_data=$(curl -s "https://blockchain.info/block-height/$height?format=json")
    
    if [ -z "$block_data" ] || [ "$block_data" == "null" ]; then
        echo "Error: Could not retrieve block data for height $height"
        continue
    fi
    
    block_hash=$(echo "$block_data" | jq -r '.blocks[0].hash')
    
    if [ -z "$block_hash" ] || [ "$block_hash" == "null" ]; then
        echo "Error: Could not extract block hash for height $height"
        continue
    fi
    
    # Get raw block hex
    curl -s "https://blockchain.info/rawblock/$block_hash?format=hex" --output "$OUTPUT_DIR/block_$height.hex"
    
    # Add a small delay to avoid rate limiting
    sleep 5
done

echo "Download completed. Blocks saved in $OUTPUT_DIR"
