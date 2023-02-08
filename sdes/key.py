from bitstring import BitArray
from .utility import PERMUTED_CHOICE_1, PERMUTED_CHOICE_2

# iterate through the indices given in PERMUTED_CHOICE_1 and convert to BitArray
def __permuted_choice_1(key: BitArray, idx: int) -> BitArray:
    return BitArray(bin="".join([
        key.bin[bit - 1] for bit in PERMUTED_CHOICE_1[idx]
    ]))

# iterate through the indices given in PERMUTED_CHOICE_2 and convert to BitArray
def __permuted_choice_2(C: BitArray, D: BitArray) -> BitArray:
    joined: BitArray = C + D
    return BitArray(bin="".join([
        joined.bin[bit - 1] for bit in PERMUTED_CHOICE_2
    ]))

# follows the key schedule algorithm in the DES algorithm
def __key_schedule(n: int, key: BitArray) -> BitArray:
    # PERMUTED_CHOICE_1 is a 2d array. idx 0 defines the first row which C chooses from,
    # and idx 1 defines the second row which D chooses from.
    C: BitArray = __permuted_choice_1(key, 0)
    D: BitArray = __permuted_choice_1(key, 1)

    # we must perform a certain amount of left shifts to get the necessary key
    # if we're on the first iteration, shift once
    # all other iterations shift twice
    # this can be simplified into (n * 2) - 1 rather than a loop
    n_adjusted: int = (n * 2) - 1

    # rotate the bits of C and D by n_adjusted
    C.rol(n_adjusted)
    D.rol(n_adjusted)

    return __permuted_choice_2(C, D)
