from packed_keccak import BLOCK_SIZE, packed_keccak_func
from xor_state import state_xor
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
func keccak_f{range_check_ptr, keccak_ptr : felt*}(input : felt*, n_bytes : felt) -> (output : felt*):
    let keccak_ptr_start = input
    let output = keccak_ptr + KECCAK_STATE_SIZE_FELTS
    %{
        from starkware.cairo.common.cairo_keccak.keccak_utils import keccak_func
        _keccak_state_size_felts = int(ids.KECCAK_STATE_SIZE_FELTS)
        assert 0 <= _keccak_state_size_felts < 100
        print("line 46")
        print("Cairo state: ", list(map(lambda x: hex(x),  memory.get_range(
            ids.keccak_ptr_start, _keccak_state_size_felts))))

        output_values = keccak_func(memory.get_range(
            ids.keccak_ptr_start, _keccak_state_size_felts))
        segments.write_arg(ids.output, output_values)
    %}

    %{
        print("Keccak ptr: ", ids.keccak_ptr)
        print("Keccak ptr start ", ids.keccak_ptr_start)
    %}
    return (output)
end

func recursive_keccak{range_check_ptr, keccak_ptr : felt*, bitwise_ptr : BitwiseBuiltin*}(state: felt*, input : felt*, n_bytes : felt) -> (output : felt*):
    alloc_locals
    %{ print("recursive keccak: Entering with params state: ", ids.state, " input: ", ids.input, " n_bytes: ", ids.n_bytes) %}
    %{ print("recursive keccak: input: ", memory.get_range(ids.input, int(ids.n_bytes / 8))) %}

    let input_cp = input
    _keccak_input(input=input, n_bytes=136, n_words=17)
    %{ print("recursive keccak: KeccakInput") %}

    %{ print("recursive keccak: XOR : StateAddr", ids.state) %}
    %{ print("recursive keccak: XOR : InputAddr", ids.input) %}

    %{ 
        def look_up(index_from, n):
            for index in range(0, n):
                try:
                    print("Index: ",index_from + index, " : ", memory.get_range(index_from + index, 1))
                except:
                    print("Index: ", index_from + index, " : ", None)

        look_up(ids.keccak_ptr, 30)
    %}


    let (xor: felt*) = state_xor(state, input)
    %{ print("recursive keccak: XOR") %}

    let (state_update: felt*) = keccak_f(input=xor, n_bytes=136)
    %{ print("recursive keccak: KeccakF") %}

    local n_bytes_above_zero
    %{ ids.n_bytes_above_zero = int(ids.n_bytes > 0) %}

    if n_bytes_above_zero != 0:
        let (state_update: felt*) = recursive_keccak(state=state_update, input=input_cp+17, n_bytes=n_bytes-136)
        return (state_update)
    else:
        return (state_update)
    end
end

func keccak{range_check_ptr, keccak_ptr : felt*, bitwise_ptr : BitwiseBuiltin*}(input : felt*, n_bytes : felt) -> (output : felt*):
    alloc_locals
    local n_bytes_modulo_chunk_size
    %{ ids.n_bytes_modulo_chunk_size = ids.n_bytes * 8 % 1088 %}
    assert n_bytes_modulo_chunk_size = 0
    
    let state = keccak_ptr

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

    let keccak_ptr = keccak_ptr + 25

    let (output: felt*) = recursive_keccak(state=state, input=input, n_bytes=n_bytes)
    return (output)
end

func _keccak_input{range_check_ptr, keccak_ptr : felt*}(
        input : felt*, n_bytes : felt, n_words : felt):
    alloc_locals
    
    %{
        print("NBytes: ", ids.n_bytes)
        print("InputId: ", ids.input)
    %}

    local n_bytes_above_0
    %{ ids.n_bytes_above_0 = int(ids.n_bytes > 0) %}

    if n_bytes_above_0 != 0:
        assert keccak_ptr[0] = input[0]
        let keccak_ptr = keccak_ptr + 1
        return _keccak_input(input=input + 1, n_bytes=n_bytes - 8, n_words=n_words - 1)
    else:
        assert keccak_ptr[0] = 0
        assert keccak_ptr[1] = 0
        assert keccak_ptr[2] = 0
        assert keccak_ptr[3] = 0
        assert keccak_ptr[4] = 0
        assert keccak_ptr[5] = 0
        assert keccak_ptr[6] = 0
        assert keccak_ptr[7] = 0
        let keccak_ptr = keccak_ptr + 8

        local range_check_ptr = range_check_ptr
        return ()
    end
end

# Handles n blocks of BLOCK_SIZE keccak instances.
func _finalize_keccak_inner{range_check_ptr, bitwise_ptr : BitwiseBuiltin*}(
        keccak_ptr : felt*, n : felt):
    if n == 0:
        return ()
    end

    alloc_locals

    local MAX_VALUE = 2 ** 64 - 1

    let keccak_ptr_start = keccak_ptr

    let (local inputs_start : felt*) = alloc()

    # Handle inputs.

    tempvar inputs = inputs_start
    tempvar keccak_ptr = keccak_ptr
    tempvar range_check_ptr = range_check_ptr
    tempvar m = 25

    input_loop:
    tempvar x0 = keccak_ptr[0]
    assert [range_check_ptr] = x0
    assert [range_check_ptr + 1] = MAX_VALUE - x0
    tempvar x1 = keccak_ptr[50]
    assert [range_check_ptr + 2] = x1
    assert [range_check_ptr + 3] = MAX_VALUE - x1
    tempvar x2 = keccak_ptr[100]
    assert [range_check_ptr + 4] = x2
    assert [range_check_ptr + 5] = MAX_VALUE - x2
    assert inputs[0] = x0 + 2 ** 64 * x1 + 2 ** 128 * x2

    tempvar inputs = inputs + 1
    tempvar keccak_ptr = keccak_ptr + 1
    tempvar range_check_ptr = range_check_ptr + 6
    tempvar m = m - 1
    jmp input_loop if m != 0

    # Run keccak on the 3 instances.

    let (outputs) = packed_keccak_func(inputs_start)
    local bitwise_ptr : BitwiseBuiltin* = bitwise_ptr

    # Handle outputs.

    tempvar outputs = outputs
    tempvar keccak_ptr = keccak_ptr
    tempvar range_check_ptr = range_check_ptr
    tempvar m = 25

    output_loop:
    tempvar x0 = keccak_ptr[0]
    assert [range_check_ptr] = x0
    assert [range_check_ptr + 1] = MAX_VALUE - x0
    tempvar x1 = keccak_ptr[50]
    assert [range_check_ptr + 2] = x1
    assert [range_check_ptr + 3] = MAX_VALUE - x1
    tempvar x2 = keccak_ptr[100]
    assert [range_check_ptr + 4] = x2
    assert [range_check_ptr + 5] = MAX_VALUE - x2
    assert outputs[0] = x0 + 2 ** 64 * x1 + 2 ** 128 * x2

    tempvar outputs = outputs + 1
    tempvar keccak_ptr = keccak_ptr + 1
    tempvar range_check_ptr = range_check_ptr + 6
    tempvar m = m - 1
    jmp output_loop if m != 0

    return _finalize_keccak_inner(keccak_ptr=keccak_ptr_start + 150, n=n - 1)
end

# Verifies that the results of keccak() are valid.
func finalize_keccak{range_check_ptr, bitwise_ptr : BitwiseBuiltin*}(
        keccak_ptr_start : felt*, keccak_ptr_end : felt*):
    alloc_locals

    tempvar n = (keccak_ptr_end - keccak_ptr_start) / (2 * KECCAK_STATE_SIZE_FELTS)
    if n == 0:
        return ()
    end

    %{
        # Add dummy pairs of input and output.
        _keccak_state_size_felts = int(ids.KECCAK_STATE_SIZE_FELTS)
        _block_size = int(ids.BLOCK_SIZE)
        assert 0 <= _keccak_state_size_felts < 100
        assert 0 <= _block_size < 1000
        inp = [0] * _keccak_state_size_felts
        padding = (inp + keccak_func(inp)) * _block_size
        segments.write_arg(ids.keccak_ptr_end, padding)
    %}

    # Compute the amount of blocks (rounded up).
    let (local q, r) = unsigned_div_rem(n + BLOCK_SIZE - 1, BLOCK_SIZE)
    _finalize_keccak_inner(keccak_ptr_start, n=q)
    return ()
end