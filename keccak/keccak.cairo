from packed_keccak import BLOCK_SIZE, packed_keccak_func
from xor_state import state_xor, mask_garbage
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.math import assert_nn_le, unsigned_div_rem
from starkware.cairo.common.memset import memset
from starkware.cairo.common.pow import pow

# Computes the keccak of 'input'. Inputs of any size are supported
# To use this function, split the input into (up to) 16 words of 64 bits (little endian).
# For example, to compute keccak('Hello world!'), use:
#   input = [8031924123371070792, 560229490]
# where:
#   8031924123371070792 == int.from_bytes(b'Hello wo', 'little')
#   560229490 == int.from_bytes(b'rld!', 'little')
#
# output is an array of 4 64-bit words (little endian).
#
#
func keccak_f{range_check_ptr, keccak_ptr : felt*, bitwise_ptr : BitwiseBuiltin*}(input : felt*) -> (output : felt*):
    let (garbaged_output) = packed_keccak_func(input)
    let (clean_output) = mask_garbage(garbaged_output)
    return (clean_output)
end

func load_full_block{range_check_ptr, keccak_ptr_start: felt*, keccak_ptr : felt*}(
        input : felt*) -> (formatted_input : felt*):
    alloc_locals

    assert keccak_ptr[0] = input[0]
    assert keccak_ptr[1] = input[1]
    assert keccak_ptr[2] = input[2]
    assert keccak_ptr[3] = input[3]
    assert keccak_ptr[4] = input[4]
    assert keccak_ptr[5] = input[5]
    assert keccak_ptr[6] = input[6]
    assert keccak_ptr[7] = input[7]
    assert keccak_ptr[8] = input[8]
    assert keccak_ptr[9] = input[9]
    assert keccak_ptr[10] = input[10]
    assert keccak_ptr[11] = input[11]
    assert keccak_ptr[12] = input[12]
    assert keccak_ptr[13] = input[13]
    assert keccak_ptr[14] = input[14]
    assert keccak_ptr[15] = input[15]
    assert keccak_ptr[16] = input[16]
    assert keccak_ptr[17] = 0
    assert keccak_ptr[18] = 0
    assert keccak_ptr[19] = 0
    assert keccak_ptr[20] = 0
    assert keccak_ptr[21] = 0
    assert keccak_ptr[22] = 0
    assert keccak_ptr[23] = 0
    assert keccak_ptr[24] = 0
    let keccak_ptr = keccak_ptr + 25

    return (keccak_ptr_start)
end

func load_block_with_padding{range_check_ptr, keccak_ptr_start: felt*, keccak_ptr : felt*}(
        input : felt*, n_bytes : felt, n_words : felt) -> (formatted_input : felt*):
    alloc_locals

    local full_word
    %{ ids.full_word = int(ids.n_bytes >= 8) %}

    if full_word != 0:
        assert keccak_ptr[0] = input[0]
        let keccak_ptr = keccak_ptr + 1
        load_block_with_padding(input=input + 1, n_bytes=n_bytes - 8, n_words=n_words - 1)
        return (keccak_ptr_start)
    else:
        local final_padding

        if n_words == 1:
            assert final_padding = 2 * 2 ** 62 # Add a padding 0x80 00 00 00 00 00 00 00
        else:
            assert final_padding = 0
        end
        
        assert_nn_le(n_bytes, 7)
        let (padding) = pow(256, n_bytes)
        local range_check_ptr = range_check_ptr

        if n_bytes == 0:
            if n_words != 0:
                assert keccak_ptr[0] = 1 + final_padding
            end
        else:
            assert keccak_ptr[0] = input[0] + padding + final_padding
        end

        if n_words == 1:
            memset(dst=keccak_ptr + 1, value=0, n=n_words - 1 + 8)
            let keccak_ptr = keccak_ptr + n_words + 8
            return (keccak_ptr_start)
        else:
            memset(dst=keccak_ptr + 1, value=0, n=n_words - 2)
            let keccak_ptr = keccak_ptr + n_words - 1
            assert keccak_ptr[0] = 2 * 2 ** 62
            memset(dst=keccak_ptr + 1, value=0, n=8)
            return (keccak_ptr_start)
        end
    end
end

func recursive_keccak{range_check_ptr, keccak_ptr : felt*, bitwise_ptr : BitwiseBuiltin*}(state: felt*, input : felt*, n_bytes : felt) -> (output : felt*):
    alloc_locals
    local n_bytes_in_current_block
    %{ ids.n_bytes_in_current_block = min(int(ids.n_bytes), 136) %}

    if n_bytes_in_current_block == 136:
        let (formatted_input: felt *) = load_full_block{keccak_ptr_start=keccak_ptr}(input=input)
        let (xor: felt*) = state_xor(state, formatted_input)
        let (keccak_f_ptr: felt*) = keccak_f(input=xor)
        let (state_update: felt*) = recursive_keccak(state=keccak_f_ptr, input=input+17, n_bytes=n_bytes-n_bytes_in_current_block)
        return (state_update)
    else:
        let (formatted_input: felt *) = load_block_with_padding{keccak_ptr_start=keccak_ptr}(input=input, n_bytes=n_bytes_in_current_block, n_words=17)
        let (xor: felt*) = state_xor(state, formatted_input)
        let (keccak_f_ptr: felt*) = keccak_f(input=xor)
        return (keccak_f_ptr)
    end
end

func keccak{range_check_ptr, keccak_ptr : felt*, bitwise_ptr : BitwiseBuiltin*}(input : felt*, n_bytes : felt) -> (output : felt*):
    let keccak_ptr_start = keccak_ptr
    alloc_locals

    let (local state : felt*) = alloc()

    assert state[0] = 0
    assert state[1] = 0
    assert state[2] = 0
    assert state[3] = 0
    assert state[4] = 0
    assert state[5] = 0
    assert state[6] = 0
    assert state[7] = 0
    assert state[8] = 0
    assert state[9] = 0
    assert state[10] = 0
    assert state[11] = 0
    assert state[12] = 0
    assert state[13] = 0
    assert state[14] = 0
    assert state[15] = 0
    assert state[16] = 0
    assert state[17] = 0
    assert state[18] = 0
    assert state[19] = 0
    assert state[20] = 0
    assert state[21] = 0
    assert state[22] = 0
    assert state[23] = 0
    assert state[24] = 0

    let (output: felt*) = recursive_keccak(state=state, input=input, n_bytes=n_bytes)
    return (output)
end
