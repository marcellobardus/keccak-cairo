%builtins output range_check bitwise

from keccak import finalize_keccak, keccak
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin

func main{output_ptr : felt*, range_check_ptr, bitwise_ptr : BitwiseBuiltin*}():
    alloc_locals
    local bitwise_ptr_start : BitwiseBuiltin* = bitwise_ptr
    let (local keccak_ptr : felt*) = alloc()
    let keccak_ptr_start = keccak_ptr

    # Compute keccak of a long random string:
    #   x = "uzlbpiahgabzsvmfeixnkgckllvydhrawqlxblbwaiesgdyaonwcttdjelybogdyruqjjeca" +
    #       "xyzkbtgxmflkrzihjrmorulgffzqceebemlhjdhgzhamobnesgomqsy"
    let (local input : felt*) = alloc()
    assert input[0] = %[ int.from_bytes(b'\x11\x22\x00\x00\x00\x00\x33\x44', 'little') %]
    assert input[1] = %[ int.from_bytes(b'gabzsvmf', 'little') %]
    assert input[2] = %[ int.from_bytes(b'eixnkgck', 'little') %]
    assert input[3] = %[ int.from_bytes(b'llvydhra', 'little') %]
    assert input[4] = %[ int.from_bytes(b'wqlxblbw', 'little') %]
    assert input[5] = %[ int.from_bytes(b'aiesgdya', 'little') %]
    assert input[6] = %[ int.from_bytes(b'onwcttdj', 'little') %]
    assert input[7] = %[ int.from_bytes(b'elybogdy', 'little') %]
    assert input[8] = %[ int.from_bytes(b'ruqjjeca', 'little') %]
    assert input[9] = %[ int.from_bytes(b'xyzkbtgx', 'little') %]
    assert input[10] = %[ int.from_bytes(b'mflkrzih', 'little') %]
    assert input[11] = %[ int.from_bytes(b'jrmorulg', 'little') %]
    assert input[12] = %[ int.from_bytes(b'ffzqceeb', 'little') %]
    assert input[13] = %[ int.from_bytes(b'emlhjdhg', 'little') %]
    assert input[14] = %[ int.from_bytes(b'zhamobne', 'little') %]
    assert input[15] = %[ int.from_bytes(b'sgomqsy1', 'little') %]
    assert input[16] = %[ int.from_bytes(b'\x55\x66\x00\x00\x00\x00\x77\x88', 'little') %]

    assert input[17] = %[ int.from_bytes(b'\xAA\xBB\x00\x00\x00\x00\xCC\xDD', 'little') %]
    assert input[18] = %[ int.from_bytes(b'gabzsvmf', 'little') %]
    assert input[19] = %[ int.from_bytes(b'eixnkgck', 'little') %]
    assert input[20] = %[ int.from_bytes(b'llvydhra', 'little') %]
    assert input[21] = %[ int.from_bytes(b'wqlxblbw', 'little') %]
    assert input[22] = %[ int.from_bytes(b'aiesgdya', 'little') %]
    assert input[23] = %[ int.from_bytes(b'onwcttdj', 'little') %]
    assert input[24] = %[ int.from_bytes(b'elybogdy', 'little') %]
    assert input[25] = %[ int.from_bytes(b'ruqjjeca', 'little') %]
    assert input[26] = %[ int.from_bytes(b'xyzkbtgx', 'little') %]
    assert input[27] = %[ int.from_bytes(b'mflkrzih', 'little') %]
    assert input[28] = %[ int.from_bytes(b'jrmorulg', 'little') %]
    assert input[29] = %[ int.from_bytes(b'ffzqceeb', 'little') %]
    assert input[30] = %[ int.from_bytes(b'emlhjdhg', 'little') %]
    assert input[31] = %[ int.from_bytes(b'zhamobne', 'little') %]
    assert input[32] = %[ int.from_bytes(b'sgomqsy1', 'little') %]
    assert input[33] = %[ int.from_bytes(b'\xEE\xFF\x00\x00\x00\xF9\xE9\x81', 'little') %]

    let (output) = keccak{keccak_ptr=keccak_ptr}(input, 272)
    %{
        from web3 import Web3
        input_str = "30345678gabzsvmfeixnkgckllvydhrawqlxblbwaiesgdyaonwcttdjelybogdyruqjjecaxyzkbtgxmflkrzihjrmorulgffzqceebemlhjdhgzhamobnesgomqsy12345678930345678gabzsvmfeixnkgckllvydhrawqlxblbwaiesgdyaonwcttdjelybogdyruqjjecaxyzkbtgxmflkrzihjrmorulgffzqceebemlhjdhgzhamobnesgomqsy12345678"
        print("Input bytes size: ", len(input_str.encode('utf-8')))
        output = ''.join(v.to_bytes(8, 'little').hex() for v in memory.get_range(ids.output, 4))
        print(f'Keccak of "{input_str}": {output}')
        web3_result = Web3.keccak(text=input_str).hex()
        print("Web3 output: ", web3_result)
        print("Cairo output: ", '0x' + output)
        assert '0x' + output == web3_result
    %}
    assert output_ptr[0] = output[0]
    assert output_ptr[1] = output[1]
    assert output_ptr[2] = output[2]
    assert output_ptr[3] = output[3]
    let output_ptr = output_ptr + 4

    finalize_keccak(keccak_ptr_start=keccak_ptr_start, keccak_ptr_end=keccak_ptr)

    %{
        # Print the number of used bitwise builtin instances.
        bitwise_start = ids.bitwise_ptr_start.address_
        print('Bitwise usage:', (ids.bitwise_ptr.address_ - bitwise_start) / 5)
    %}

    return ()
end
