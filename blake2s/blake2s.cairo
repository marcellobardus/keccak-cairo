from packed_blake2s import N_PACKED_INSTANCES, blake2s_compress
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.registers import get_fp_and_pc
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.math import assert_nn_le, unsigned_div_rem
from starkware.cairo.common.memset import memset
from starkware.cairo.common.pow import pow

const BLAKE2S_INPUT_CHUNK_SIZE_FELTS = 16
const BLAKE2S_STATE_SIZE_FELTS = 8
# Each instance consists of 16 words of message, 8 words for the input state, 8 words
# for the output state and 2 words for t0 and f0.
const BLAKE2S_INSTANCE_SIZE = BLAKE2S_INPUT_CHUNK_SIZE_FELTS + 2 * BLAKE2S_STATE_SIZE_FELTS + 2

# Computes blake2s of 'input'. Inputs of up to 64 bytes are supported.
# To use this function, split the input into (up to) 16 words of 32 bits (little endian).
# For example, to compute blake2s('Hello world'), use:
#   input = [1819043144, 1870078063, 6581362]
# where:
#   1819043144 == int.from_bytes(b'Hell', 'little')
#   1870078063 == int.from_bytes(b'o wo', 'little')
#   6581362 == int.from_bytes(b'rld', 'little')
#
# output is an array of 8 32-bit words (little endian).
#
# Assumption: n_bytes <= 64.
#
# Note: You must call finalize_blake2s() at the end of the program. Otherwise, this function
# is not sound and a malicious prover may return a wrong result.
# Note: the interface of this function may change in the future.
func blake2s{range_check_ptr, blake2s_ptr : felt*}(input : felt*, n_bytes : felt) -> (
        output : felt*):
    assert_nn_le(n_bytes, 64)
    let blake2s_start = blake2s_ptr
    _blake2s_input(input=input, n_bytes=n_bytes, n_words=BLAKE2S_INPUT_CHUNK_SIZE_FELTS)

    # Set the initial state to IV (IV[0] is modified).
    assert blake2s_ptr[0] = 0x6B08E647  # IV[0] ^ 0x01010020 (config: no key, 32 bytes output).
    assert blake2s_ptr[1] = 0xBB67AE85
    assert blake2s_ptr[2] = 0x3C6EF372
    assert blake2s_ptr[3] = 0xA54FF53A
    assert blake2s_ptr[4] = 0x510E527F
    assert blake2s_ptr[5] = 0x9B05688C
    assert blake2s_ptr[6] = 0x1F83D9AB
    assert blake2s_ptr[7] = 0x5BE0CD19
    let blake2s_ptr = blake2s_ptr + BLAKE2S_STATE_SIZE_FELTS

    assert blake2s_ptr[0] = n_bytes  # n_bytes.
    assert blake2s_ptr[1] = 0xffffffff  # Is last byte = True.
    let blake2s_ptr = blake2s_ptr + 2

    let output = blake2s_ptr
    %{
        from starkware.cairo.common.cairo_blake2s.blake2s_utils import IV, blake2s_compress

        _blake2s_input_chunk_size_felts = int(ids.BLAKE2S_INPUT_CHUNK_SIZE_FELTS)
        assert 0 <= _blake2s_input_chunk_size_felts < 100

        new_state = blake2s_compress(
            message=memory.get_range(ids.blake2s_start, _blake2s_input_chunk_size_felts),
            h=[IV[0] ^ 0x01010020] + IV[1:],
            t0=ids.n_bytes,
            t1=0,
            f0=0xffffffff,
            f1=0,
        )

        segments.write_arg(ids.output, new_state)
    %}
    let blake2s_ptr = blake2s_ptr + BLAKE2S_STATE_SIZE_FELTS
    return (output)
end

func _blake2s_input{range_check_ptr, blake2s_ptr : felt*}(
        input : felt*, n_bytes : felt, n_words : felt):
    alloc_locals

    local full_word
    %{ ids.full_word = int(ids.n_bytes >= 4) %}

    if full_word != 0:
        assert blake2s_ptr[0] = input[0]
        let blake2s_ptr = blake2s_ptr + 1
        return _blake2s_input(input=input + 1, n_bytes=n_bytes - 4, n_words=n_words - 1)
    end

    # This is the last input word, so we should fill the rest with zeros.

    if n_bytes == 0:
        memset(dst=blake2s_ptr, value=0, n=n_words)
        let blake2s_ptr = blake2s_ptr + n_words
        return ()
    end

    assert_nn_le(n_bytes, 3)
    local range_check_ptr = range_check_ptr

    assert blake2s_ptr[0] = input[0]

    memset(dst=blake2s_ptr + 1, value=0, n=n_words - 1)
    let blake2s_ptr = blake2s_ptr + n_words
    return ()
end

# Verifies that the results of blake2s() are valid.
func finalize_blake2s{range_check_ptr, bitwise_ptr : BitwiseBuiltin*}(
        blake2s_ptr_start : felt*, blake2s_ptr_end : felt*):
    alloc_locals

    let (__fp__, _) = get_fp_and_pc()

    let (sigma) = _get_sigma()

    tempvar n = (blake2s_ptr_end - blake2s_ptr_start) / BLAKE2S_INSTANCE_SIZE
    if n == 0:
        return ()
    end

    %{
        # Add dummy pairs of input and output.
        from starkware.cairo.common.cairo_blake2s.blake2s_utils import IV, blake2s_compress

        _n_packed_instances = int(ids.N_PACKED_INSTANCES)
        assert 0 <= _n_packed_instances < 20
        _blake2s_input_chunk_size_felts = int(ids.BLAKE2S_INPUT_CHUNK_SIZE_FELTS)
        assert 0 <= _blake2s_input_chunk_size_felts < 100

        message = [0] * _blake2s_input_chunk_size_felts
        modified_iv = [IV[0] ^ 0x01010020] + IV[1:]
        output = blake2s_compress(
            message=message,
            h=modified_iv,
            t0=0,
            t1=0,
            f0=0xffffffff,
            f1=0,
        )
        padding = (message + modified_iv + [0, 0xffffffff] + output) * (_n_packed_instances - 1)
        segments.write_arg(ids.blake2s_ptr_end, padding)
    %}

    # Compute the amount of chunks (rounded up).
    let (local n_chunks, _) = unsigned_div_rem(n + N_PACKED_INSTANCES - 1, N_PACKED_INSTANCES)
    let blake2s_ptr = blake2s_ptr_start
    _finalize_blake2s_inner{blake2s_ptr=blake2s_ptr}(n=n_chunks, sigma=sigma)
    return ()
end

func _get_sigma() -> (sigma : felt*):
    alloc_locals
    let (__fp__, _) = get_fp_and_pc()
    local sigma = 0
    local a = 1
    local a = 2
    local a = 3
    local a = 4
    local a = 5
    local a = 6
    local a = 7
    local a = 8
    local a = 9
    local a = 10
    local a = 11
    local a = 12
    local a = 13
    local a = 14
    local a = 15
    local a = 14
    local a = 10
    local a = 4
    local a = 8
    local a = 9
    local a = 15
    local a = 13
    local a = 6
    local a = 1
    local a = 12
    local a = 0
    local a = 2
    local a = 11
    local a = 7
    local a = 5
    local a = 3
    local a = 11
    local a = 8
    local a = 12
    local a = 0
    local a = 5
    local a = 2
    local a = 15
    local a = 13
    local a = 10
    local a = 14
    local a = 3
    local a = 6
    local a = 7
    local a = 1
    local a = 9
    local a = 4
    local a = 7
    local a = 9
    local a = 3
    local a = 1
    local a = 13
    local a = 12
    local a = 11
    local a = 14
    local a = 2
    local a = 6
    local a = 5
    local a = 10
    local a = 4
    local a = 0
    local a = 15
    local a = 8
    local a = 9
    local a = 0
    local a = 5
    local a = 7
    local a = 2
    local a = 4
    local a = 10
    local a = 15
    local a = 14
    local a = 1
    local a = 11
    local a = 12
    local a = 6
    local a = 8
    local a = 3
    local a = 13
    local a = 2
    local a = 12
    local a = 6
    local a = 10
    local a = 0
    local a = 11
    local a = 8
    local a = 3
    local a = 4
    local a = 13
    local a = 7
    local a = 5
    local a = 15
    local a = 14
    local a = 1
    local a = 9
    local a = 12
    local a = 5
    local a = 1
    local a = 15
    local a = 14
    local a = 13
    local a = 4
    local a = 10
    local a = 0
    local a = 7
    local a = 6
    local a = 3
    local a = 9
    local a = 2
    local a = 8
    local a = 11
    local a = 13
    local a = 11
    local a = 7
    local a = 14
    local a = 12
    local a = 1
    local a = 3
    local a = 9
    local a = 5
    local a = 0
    local a = 15
    local a = 4
    local a = 8
    local a = 6
    local a = 2
    local a = 10
    local a = 6
    local a = 15
    local a = 14
    local a = 9
    local a = 11
    local a = 3
    local a = 0
    local a = 8
    local a = 12
    local a = 2
    local a = 13
    local a = 7
    local a = 1
    local a = 4
    local a = 10
    local a = 5
    local a = 10
    local a = 2
    local a = 8
    local a = 4
    local a = 7
    local a = 6
    local a = 1
    local a = 5
    local a = 15
    local a = 11
    local a = 9
    local a = 14
    local a = 3
    local a = 12
    local a = 13
    local a = 0
    return (&sigma)
end

# Handles n chunks of N_PACKED_INSTANCES blake2s instances.
func _finalize_blake2s_inner{range_check_ptr, bitwise_ptr : BitwiseBuiltin*, blake2s_ptr : felt*}(
        n : felt, sigma : felt*):
    if n == 0:
        return ()
    end

    alloc_locals

    local MAX_VALUE = 2 ** 32 - 1

    let blake2s_start = blake2s_ptr

    # Load instance data.
    let (local data : felt*) = alloc()
    _pack_ints(BLAKE2S_INSTANCE_SIZE, data)

    let message = data
    let input_state = message + BLAKE2S_INPUT_CHUNK_SIZE_FELTS
    let t0_and_f0 = input_state + BLAKE2S_STATE_SIZE_FELTS
    let output_state = t0_and_f0 + 2

    # Run blake2s on N_PACKED_INSTANCES instances.
    local blake2s_ptr : felt* = blake2s_ptr
    local range_check_ptr = range_check_ptr
    blake2s_compress(
        h=input_state,
        message=data,
        t0=t0_and_f0[0],
        f0=t0_and_f0[1],
        sigma=sigma,
        output=output_state)

    local bitwise_ptr : BitwiseBuiltin* = bitwise_ptr

    let blake2s_ptr = blake2s_start + BLAKE2S_INSTANCE_SIZE * N_PACKED_INSTANCES

    return _finalize_blake2s_inner(n=n - 1, sigma=sigma)
end

# Given N_PACKED_INSTANCES sets of m (32-bit) integers in the blake2s implicit argument,
# where each set starts at offset BLAKE2S_INSTANCE_SIZE from the previous set,
# computes m packed integers.
# blake2s_ptr is advanced m steps (just after the first set).
func _pack_ints{range_check_ptr, blake2s_ptr : felt*}(m, packed_values : felt*):
    static_assert N_PACKED_INSTANCES == 7
    alloc_locals

    local MAX_VALUE = 2 ** 32 - 1

    # TODO: consider using split_int().
    tempvar packed_values = packed_values
    tempvar blake2s_ptr = blake2s_ptr
    tempvar range_check_ptr = range_check_ptr
    tempvar m = m

    loop:
    tempvar x0 = blake2s_ptr[0 * BLAKE2S_INSTANCE_SIZE]
    assert [range_check_ptr + 0] = x0
    assert [range_check_ptr + 1] = MAX_VALUE - x0
    tempvar x1 = blake2s_ptr[1 * BLAKE2S_INSTANCE_SIZE]
    assert [range_check_ptr + 2] = x1
    assert [range_check_ptr + 3] = MAX_VALUE - x1
    tempvar x2 = blake2s_ptr[2 * BLAKE2S_INSTANCE_SIZE]
    assert [range_check_ptr + 4] = x2
    assert [range_check_ptr + 5] = MAX_VALUE - x2
    tempvar x3 = blake2s_ptr[3 * BLAKE2S_INSTANCE_SIZE]
    assert [range_check_ptr + 6] = x3
    assert [range_check_ptr + 7] = MAX_VALUE - x3
    tempvar x4 = blake2s_ptr[4 * BLAKE2S_INSTANCE_SIZE]
    assert [range_check_ptr + 8] = x4
    assert [range_check_ptr + 9] = MAX_VALUE - x4
    tempvar x5 = blake2s_ptr[5 * BLAKE2S_INSTANCE_SIZE]
    assert [range_check_ptr + 10] = x5
    assert [range_check_ptr + 11] = MAX_VALUE - x5
    tempvar x6 = blake2s_ptr[6 * BLAKE2S_INSTANCE_SIZE]
    assert [range_check_ptr + 12] = x6
    assert [range_check_ptr + 13] = MAX_VALUE - x6
    assert packed_values[0] = x0 + 2 ** 35 * x1 + 2 ** (35 * 2) * x2 + 2 ** (35 * 3) * x3 +
        2 ** (35 * 4) * x4 + 2 ** (35 * 5) * x5 + 2 ** (35 * 6) * x6

    tempvar packed_values = packed_values + 1
    tempvar blake2s_ptr = blake2s_ptr + 1
    tempvar range_check_ptr = range_check_ptr + 14
    tempvar m = m - 1
    jmp loop if m != 0

    return ()
end
