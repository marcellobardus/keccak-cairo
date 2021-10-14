%lang starknet
%builtins range_check bitwise

from sha256 import finalize_sha256, sha256
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin

# Computes the SHA256 hash of the given input (up to 55 bytes).
# input should consist of a list of 32-bit integers (each representing 4 bytes, in big endian).
# n_bytes should be the number of input bytes (for example, it should be between 4*input_len - 3 and
# 4*input_len).
# Returns the 256 output bits as 2 128-bit big-endian integers.
@view
func compute_sha256{range_check_ptr, bitwise_ptr : BitwiseBuiltin*}(
        input_len : felt, input : felt*, n_bytes : felt) -> (res0 : felt, res1 : felt):
    alloc_locals

    let (local sha256_ptr_start : felt*) = alloc()
    let sha256_ptr = sha256_ptr_start

    let (local output : felt*) = sha256{sha256_ptr=sha256_ptr}(input, n_bytes)
    finalize_sha256(sha256_ptr_start=sha256_ptr_start, sha256_ptr_end=sha256_ptr)

    return (
        output[3] + 2 ** 32 * output[2] + 2 ** 64 * output[1] + 2 ** 96 * output[0],
        output[7] + 2 ** 32 * output[6] + 2 ** 64 * output[5] + 2 ** 96 * output[4])
end
