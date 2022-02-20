from bitstring import BitArray
from src.key import __key_schedule
from typing import List, Tuple
from src.utility import INITIAL_PERMUTATION, INVERSE_INITIAL_PERMUTATION, PERMUTATION
from src.utility import E_BIT_SELECTION, SBOX_1, SBOX_2
from src.utility import __bitwise_xor, __pad_arr

__nibbles = lambda block: (block[:4], block[4:])

# iterate through indices given in INITIAL_PERMUTATION and convert to BitArray
def __initial_permutation(block: BitArray) -> BitArray:
    return BitArray(bin="".join([
        block.bin[num - 1] for num in INITIAL_PERMUTATION
    ]))

# iterate through indices given in INVERSE_INITIAL_PERMUTATION and convert to BitArray
def __inverse_permutation(block: BitArray) -> BitArray:
    return BitArray(bin="".join([
        block.bin[num - 1] for num in INVERSE_INITIAL_PERMUTATION
    ]))

# iterate through indices given in PERMUTATION and convert to BitArray
def __permutation(block: str) -> BitArray:
    return BitArray(bin="".join([
        block[num - 1] for num in PERMUTATION
    ]))

def __round(block: BitArray, key: BitArray) -> Tuple[BitArray, BitArray]:
    # block is given as (l + r), a total of 8 bits
    L, R = __nibbles(block)

    # L' = R
    # R' = L ^ f(R, K)
    l_prime = R
    r_prime = __bitwise_xor(L, __cipher(R, key))

    return (l_prime, r_prime)

# iterate through the indices given in EB_BIT_SELECTION and convert to BitArray
def __expand(R: BitArray) -> BitArray:
    return BitArray(bin="".join([
        R.bin[num - 1] for num in E_BIT_SELECTION
    ]))

# determines the location where we retrieve a value from an SBOX
def __sbox_processing(block: BitArray, sbox: List[List[int]]) -> BitArray:
    # the row location is given by the first and last bits of the block
    # the column location is given by the middle two bits of the block
    row: int = int(block.bin[0] + block.bin[-1], 2)
    col: int = int(block.bin[1:3], 2)

    # retrieve the value and pad it to 2 bits
    res: BitArray = BitArray(bin(sbox[row][col]))
    __pad_arr(res, 2)

    return res

# follows the f function in the DES algorithm
def __cipher(block: BitArray, key: BitArray) -> BitArray:
    expanded: BitArray = __expand(block)
    combined: BitArray = __bitwise_xor(expanded, key)
    
    # split combined key/block into nibbles to retrieve values from SBOXes
    s1_target, s2_target = __nibbles(combined)

    s1_result: BitArray = __sbox_processing(s1_target, SBOX_1)
    s2_result: BitArray = __sbox_processing(s2_target, SBOX_2)

    # call permutation on the retrieved SBOX values
    return __permutation(s1_result.bin + s2_result.bin)