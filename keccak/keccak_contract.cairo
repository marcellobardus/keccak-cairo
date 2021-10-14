%lang starknet
%builtins range_check bitwise

from keccak import finalize_keccak, keccak
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin

# Computes the keccak hash of the given input (up to 127 bytes).
# input should consist of a list of 64-bit integers (each representing 8 bytes, in little endian).
# n_bytes should be the number of input bytes (for example, it should be between 8*input_len - 7 and
# 8*input_len).
@view
func compute_keccak{range_check_ptr, bitwise_ptr : BitwiseBuiltin*}(
        input_len : felt, input : felt*, n_bytes : felt) -> (
        res0 : felt, res1 : felt, res2 : felt, res3 : felt):
    alloc_locals

    let (local keccak_ptr_start : felt*) = alloc()
    let keccak_ptr = keccak_ptr_start

    let (local output : felt*) = keccak{keccak_ptr=keccak_ptr}(input, n_bytes)
    finalize_keccak(keccak_ptr_start=keccak_ptr_start, keccak_ptr_end=keccak_ptr)

    return (output[0], output[1], output[2], output[3])
end
