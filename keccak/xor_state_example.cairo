%builtins output range_check bitwise

from xor_state import state_xor
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin

func main{output_ptr : felt*, range_check_ptr, bitwise_ptr : BitwiseBuiltin*}():
    alloc_locals
    local bitwise_ptr_start : BitwiseBuiltin* = bitwise_ptr
    let (local keccak_ptr : felt*) = alloc()
    let keccak_ptr_start = keccak_ptr


    let (local state : felt*) = alloc()
    let (local values: felt*) = alloc()

    assert state[0] = %[ int.from_bytes(b'30345678', 'little') %]
    assert state[1] = %[ int.from_bytes(b'gabzsvmf', 'little') %]
    assert state[2] = %[ int.from_bytes(b'eixnkgck', 'little') %]
    assert state[3] = %[ int.from_bytes(b'llvydhra', 'little') %]
    assert state[4] = %[ int.from_bytes(b'wqlxblbw', 'little') %]
    assert state[5] = %[ int.from_bytes(b'aiesgdya', 'little') %]
    assert state[6] = %[ int.from_bytes(b'onwcttdj', 'little') %]
    assert state[7] = %[ int.from_bytes(b'elybogdy', 'little') %]
    assert state[8] = %[ int.from_bytes(b'ruqjjeca', 'little') %]
    assert state[9] = %[ int.from_bytes(b'xyzkbtgx', 'little') %]
    assert state[10] = %[ int.from_bytes(b'mflkrzih', 'little') %]
    assert state[11] = %[ int.from_bytes(b'jrmorulg', 'little') %]
    assert state[12] = %[ int.from_bytes(b'ffzqceeb', 'little') %]
    assert state[13] = %[ int.from_bytes(b'emlhjdhg', 'little') %]
    assert state[14] = %[ int.from_bytes(b'zhamobne', 'little') %]
    assert state[15] = %[ int.from_bytes(b'sgomqsy1', 'little') %]
    assert state[16] = %[ int.from_bytes(b'23456789', 'little') %]
    assert state[17] = %[ int.from_bytes(b'jrmorulg', 'little') %]
    assert state[18] = %[ int.from_bytes(b'ffzqceeb', 'little') %]
    assert state[19] = %[ int.from_bytes(b'emlhjdhg', 'little') %]
    assert state[20] = %[ int.from_bytes(b'zhamobne', 'little') %]
    assert state[21] = %[ int.from_bytes(b'sgomqsy1', 'little') %]
    assert state[22] = %[ int.from_bytes(b'23456789', 'little') %]
    assert state[23] = %[ int.from_bytes(b'23456789', 'little') %]
    assert state[24] = %[ int.from_bytes(b'23456789', 'little') %]


    assert values[0] = %[ int.from_bytes(b'30345678', 'little') %]
    assert values[1] = %[ int.from_bytes(b'gabzsvmf', 'little') %]
    assert values[2] = %[ int.from_bytes(b'eixnkgck', 'little') %]
    assert values[3] = %[ int.from_bytes(b'llvydhra', 'little') %]
    assert values[4] = %[ int.from_bytes(b'wqlxblbw', 'little') %]
    assert values[5] = %[ int.from_bytes(b'aiesgdya', 'little') %]
    assert values[6] = %[ int.from_bytes(b'onwcttdj', 'little') %]
    assert values[7] = %[ int.from_bytes(b'elybogdy', 'little') %]
    assert values[8] = %[ int.from_bytes(b'ruqjjeca', 'little') %]
    assert values[9] = %[ int.from_bytes(b'xyzkbtgx', 'little') %]
    assert values[10] = %[ int.from_bytes(b'mflkrzih', 'little') %]
    assert values[11] = %[ int.from_bytes(b'jrmorulg', 'little') %]
    assert values[12] = %[ int.from_bytes(b'ffzqceeb', 'little') %]
    assert values[13] = %[ int.from_bytes(b'emlhjdhg', 'little') %]
    assert values[14] = %[ int.from_bytes(b'zhamobne', 'little') %]
    assert values[15] = %[ int.from_bytes(b'sgomqsy1', 'little') %]
    assert values[16] = %[ int.from_bytes(b'23456789', 'little') %]
    assert values[17] = %[ int.from_bytes(b'ffzqceeb', 'little') %]
    assert values[18] = %[ int.from_bytes(b'emlhjdhg', 'little') %]
    assert values[19] = %[ int.from_bytes(b'zhamobne', 'little') %]
    assert values[20] = %[ int.from_bytes(b'sgomqsy1', 'little') %]
    assert values[21] = %[ int.from_bytes(b'23456789', 'little') %]
    assert values[22] = %[ int.from_bytes(b'zhamobne', 'little') %]
    assert values[23] = %[ int.from_bytes(b'sgomqsy1', 'little') %]
    assert values[24] = %[ int.from_bytes(b'23456789', 'little') %]

    let (output) = state_xor(state, values)

    %{
        output = memory.get_range(ids.output, 25)
        print(output)
    %}

    %{ 
        for i in range(0, 24):
            assert memory.get_range(ids.output + i, 1)[0] == memory.get_range(ids.state + i, 1)[0] ^ memory.get_range(ids.values + i, 1)[0] 
    %}

    
    return ()
end
