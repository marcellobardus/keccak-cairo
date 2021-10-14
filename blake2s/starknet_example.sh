#!/bin/bash

# This example deploys a contract that computes the blake2s hash of the given input and calls it.

set -ex

cd $(dirname $0)

starknet-compile blake2s_contract.cairo --output blake2s_contract_compiled.json \
    --abi blake2s_contract_abi.json
starknet deploy --contract blake2s_contract_compiled.json > deploy_output.txt
cat deploy_output.txt
CONTRACT_ADDRESS=$(sed -ne "s|^Contract address: \(0x[0-9a-fA-F]\+\)$|\1|p" deploy_output.txt)
echo "Started contract deployment to address: $CONTRACT_ADDRESS"

# Compute blake2s("Hello world").
starknet invoke --address $CONTRACT_ADDRESS --abi blake2s_contract_abi.json \
    --function compute_blake2s \
    --inputs 3 1819043144 1870078063 6581362 11
