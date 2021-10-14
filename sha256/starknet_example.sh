#!/bin/bash

# This example deploys a contract that computes the SHA256 hash of the given input and calls it.

set -ex

cd $(dirname $0)

starknet-compile sha256_contract.cairo --output sha256_contract_compiled.json \
    --abi sha256_contract_abi.json
starknet deploy --contract sha256_contract_compiled.json > deploy_output.txt
cat deploy_output.txt
CONTRACT_ADDRESS=$(sed -ne "s|^Contract address: \(0x[0-9a-fA-F]\+\)$|\1|p" deploy_output.txt)
echo "Started contract deployment to address: $CONTRACT_ADDRESS"

# Compute SHA256("Hello world").
starknet invoke --address $CONTRACT_ADDRESS --abi sha256_contract_abi.json \
    --function compute_sha256 \
    --inputs 3 1214606444 1864398703 1919706112 11
