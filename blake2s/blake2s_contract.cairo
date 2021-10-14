%lang starknet
%builtins range_check bitwise

from blake2s import finalize_blake2s, blake2s
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin

# Computes the blake2s hash of the given input (up to 64 bytes).
# input should consist of a list of 32-bit integers (each representing 4 bytes, in little endian).
# n_bytes should be the number of input bytes (for example, it should be between 4*input_len - 3 and
# 4*input_len).
# Returns the 256 output bits as 2 128-bit little-endian integers.
@view
func compute_blake2s{range_check_ptr, bitwise_ptr : BitwiseBuiltin*}(
        input_len : felt, input : felt*, n_bytes : felt) -> (res0 : felt, res1 : felt):
    alloc_locals

    let (local blake2s_ptr_start : felt*) = alloc()
    let blake2s_ptr = blake2s_ptr_start

    let (local output : felt*) = blake2s{blake2s_ptr=blake2s_ptr}(input, n_bytes)
    finalize_blake2s(blake2s_ptr_start=blake2s_ptr_start, blake2s_ptr_end=blake2s_ptr)

    return (
        output[0] + 2 ** 32 * output[1] + 2 ** 64 * output[2] + 2 ** 96 * output[3],
        output[4] + 2 ** 32 * output[5] + 2 ** 64 * output[6] + 2 ** 96 * output[7])
end
