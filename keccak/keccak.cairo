from packed_keccak import BLOCK_SIZE, packed_keccak_func
from xor_state import state_xor, mask_garbage
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.math import assert_nn_le, unsigned_div_rem
from starkware.cairo.common.memset import memset
from starkware.cairo.common.pow import pow

const KECCAK_STATE_SIZE_FELTS = 25

# Computes the keccak of 'input'. Inputs of up to 127 bytes are supported.
# To use this function, split the input into (up to) 16 words of 64 bits (little endian).
# For example, to compute keccak('Hello world!'), use:
#   input = [8031924123371070792, 560229490]
# where:
#   8031924123371070792 == int.from_bytes(b'Hello wo', 'little')
#   560229490 == int.from_bytes(b'rld!', 'little')
#
# output is an array of 4 64-bit words (little endian).
#
# Assumption: n_bytes <= 127.
#
# Note: You must call finalize_keccak() at the end of the program. Otherwise, this function
# is not sound and a malicious prover may return a wrong result.
# Note: the interface of this function may change in the future.
func keccak_f{range_check_ptr, keccak_ptr : felt*, bitwise_ptr : BitwiseBuiltin*}(input : felt*) -> (output : felt*):
    %{ print("\n[keccak_f]: Entering with params keccak_ptr:", ids.keccak_ptr, "input:", ids.input) %}
    let (garbaged_output) = packed_keccak_func(input)
    let (clean_output) = mask_garbage(garbaged_output)
    return (clean_output)
end

func load_full_block{range_check_ptr, keccak_ptr_start: felt*, keccak_ptr : felt*}(
        input : felt*) -> (formatted_input : felt*):
    %{ print("[absorb_full_block]: Entering absorb_full_block with params input:", ids.input, "keccak_ptr_start:", ids.keccak_ptr_start) %}
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
    %{ print("[load_block_with_padding]: Entering with params keccak_ptr:", ids.keccak_ptr, "input:", ids.input, "n_bytes:", ids.n_bytes, "n_words:", ids.n_words, "keccak_ptr_start:", ids.keccak_ptr_start) %}
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
            %{ print("n_words==1", ids.n_words) %}
            assert final_padding = 2 * 2 ** 62 # Add a padding 0x80 00 00 00 00 00 00 00
        else:
            %{ print("n_words!=1", ids.n_words) %}
            assert final_padding = 0
        end
        
        assert_nn_le(n_bytes, 7)
        let (padding) = pow(256, n_bytes)
        local range_check_ptr = range_check_ptr

        if n_bytes == 0:
            if n_words != 0:
                %{ print("n_bytes==0 && n_words!=0", ids.n_bytes, ids.n_words) %}
                assert keccak_ptr[0] = 1 + final_padding
            end
        else:
            %{ print("n_bytes!=0", ids.n_bytes) %}
            assert keccak_ptr[0] = input[0] + padding + final_padding
        end

        if n_words == 1:
            %{ print("n_words==1", ids.n_words) %}
            memset(dst=keccak_ptr + 1, value=0, n=n_words - 1 + 8)
            let keccak_ptr = keccak_ptr + n_words + 8
            return (keccak_ptr_start)
        else:
            %{ print("n_words!=0", ids.n_words) %}
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
    %{ print("\n[recursive keccak]: Entering with params keccak_ptr:", ids.keccak_ptr, "input:", ids.input, "n_bytes:", ids.n_bytes, "state:", ids.state) %}
    %{ print("[recursive keccak]: input: ", *list(map(hex, memory.get_range(ids.input, int(ids.n_bytes / 8))))) %}

    local n_bytes_in_current_block
    %{ ids.n_bytes_in_current_block = min(int(ids.n_bytes), 136) %}

    if n_bytes_in_current_block == 136:
        let (formatted_input: felt *) = load_full_block{keccak_ptr_start=keccak_ptr}(input=input)
        %{ 
            print("\t[recursive_keccak] load_full_block filled in the input to formatted_input:")
            def look_up(name, index_from, n):
                for index in range(0, n):
                    try:
                        print(name, ":\t",index_from + index, "\t:", hex(int(memory.get_range(index_from + index, 1)[0])))
                    except:
                        print(name, ":\t", index_from + index, "\t:    *** EMPTY ***")

            look_up("FORMATTED_INPUT", ids.formatted_input, 30)
        %}

        let (xor: felt*) = state_xor(state, formatted_input)
        %{ 
            print("\t[recursive_keccak] XOR:")
            def look_up(name, index_from, n):
                for index in range(0, n):
                    try:
                        print(name, ":\t",index_from + index, "\t:", hex(int(memory.get_range(index_from + index, 1)[0])))
                    except:
                        print(name, ":\t", index_from + index, "\t:    *** EMPTY ***")

            look_up("XOR", ids.xor, 30)
        %}

        let (keccak_f_ptr: felt*) = keccak_f(input=xor)
        %{ 
            print("\t[recursive_keccak] keccak_F keccak_f_ptr:")
            def look_up(name, index_from, n):
                for index in range(0, n):
                    try:
                        print(name, ":\t",index_from + index, "\t:", hex(int(memory.get_range(index_from + index, 1)[0])))
                    except:
                        print(name, ":\t", index_from + index, "\t:    *** EMPTY ***")

            look_up("keccak_f_ptr", ids.keccak_f_ptr, 30)
        %}

        let (state_update: felt*) = recursive_keccak(state=keccak_f_ptr, input=input+17, n_bytes=n_bytes-n_bytes_in_current_block)
        return (state_update)
    else:
        let (formatted_input: felt *) = load_block_with_padding{keccak_ptr_start=keccak_ptr}(input=input, n_bytes=n_bytes_in_current_block, n_words=17)
        %{ 
            print("\t[recursive_keccak] load_full_block filled in the input to formatted_input:")
            def look_up(name, index_from, n):
                for index in range(0, n):
                    try:
                        print(name, ":\t",index_from + index, "\t:", hex(int(memory.get_range(index_from + index, 1)[0])))
                    except:
                        print(name, ":\t", index_from + index, "\t:    *** EMPTY ***")

            look_up("FORMATTED_INPUT", ids.formatted_input, 30)
        %}

        let (xor: felt*) = state_xor(state, formatted_input)
        %{ 
            print("\t[recursive_keccak] XOR:")
            def look_up(name, index_from, n):
                for index in range(0, n):
                    try:
                        print(name, ":\t",index_from + index, "\t:", hex(int(memory.get_range(index_from + index, 1)[0])))
                    except:
                        print(name, ":\t", index_from + index, "\t:    *** EMPTY ***")

            look_up("XOR", ids.xor, 30)
        %}

        let (keccak_f_ptr: felt*) = keccak_f(input=xor)
        %{ 
            print("\t[recursive_keccak] keccak_F keccak_f_ptr:")
            def look_up(name, index_from, n):
                for index in range(0, n):
                    try:
                        print(name, ":\t",index_from + index, "\t:", hex(int(memory.get_range(index_from + index, 1)[0])))
                    except:
                        print(name, ":\t", index_from + index, "\t:    *** EMPTY ***")

            look_up("keccak_f_ptr", ids.keccak_f_ptr, 30)
        %}

        return (keccak_f_ptr)
    end
end

func keccak{range_check_ptr, keccak_ptr : felt*, bitwise_ptr : BitwiseBuiltin*}(input : felt*, n_bytes : felt) -> (output : felt*):
    %{ print("\n[keccak]: Entering with params keccak_ptr:", ids.keccak_ptr, "input:", ids.input, "n_bytes:", ids.n_bytes) %}

    let keccak_ptr_start = keccak_ptr

    alloc_locals
    # local n_bytes_modulo_chunk_size
    # %{ ids.n_bytes_modulo_chunk_size = ids.n_bytes * 8 % 1088 %}
    # assert n_bytes_modulo_chunk_size = 0
    
    # let state = keccak_ptr
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

    %{ 
        print("\t[keccak] Initialized state:")
        def look_up(name, index_from, n):
            for index in range(0, n):
                try:
                    print(name, ":\t",index_from + index, "\t:", hex(int(memory.get_range(index_from + index, 1)[0])))
                except:
                    print(name, ":\t", index_from + index, "\t:    *** EMPTY ***")

        look_up("STATE", ids.state, 30)
    %}

    let (output: felt*) = recursive_keccak(state=state, input=input, n_bytes=n_bytes)
    return (output)
end
