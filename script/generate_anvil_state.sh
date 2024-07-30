#!/bin/sh

set -e

# Define the state file
export PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
STATE_FILE="state.json"
RPC_URL="http://localhost:8545"

# Start the anvil process, ending it will dump state
anvil --dump-state $STATE_FILE &

# Capture the PID of the anvil process
ANVIL_PID=$!

# Function to wait for cast block-number to return successfully
wait_for_block_number() {
    until cast block-number &> /dev/null; do
        echo "Waiting for cast block-number to succeed..."
        sleep 1
    done
    echo "cast block-number succeeded."
}

# Wait for cast block-number to succeed
wait_for_block_number

# Deploy the contracts
forge script script/Deploy.s.sol --broadcast --rpc-url $RPC_URL

# Interrupt the anvil process to dump the state
kill -INT $ANVIL_PID

# Wait for the anvil process to exit
wait $ANVIL_PID

echo "State generation completed. State saved to $STATE_FILE."
