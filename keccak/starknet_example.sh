#!/bin/bash

# This example deploys a contract that computes the keccak hash of the given input and calls it.

set -ex

starknet-compile keccak_contract.cairo --output keccak_contract_compiled.json \
    --abi keccak_contract_abi.json
starknet deploy --contract keccak_contract_compiled.json > deploy_output.txt
cat deploy_output.txt
CONTRACT_ADDRESS=$(sed -ne "s|^Contract address: \(0x[0-9a-fA-F]\+\)$|\1|p" deploy_output.txt)
echo "Started contract deployment to address: $CONTRACT_ADDRESS"

starknet invoke --address $CONTRACT_ADDRESS --abi keccak_contract_abi.json \
    --function compute_keccak \
    --inputs 2 8031924123371070792 560229490 12
