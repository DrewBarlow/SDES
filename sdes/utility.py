from bitstring import BitArray
from typing import Generator, List

INITIAL_PERMUTATION: List[int] = [2, 6, 3, 1, 4, 8, 5, 7]
INVERSE_INITIAL_PERMUTATION: List[int] = [4, 1, 3, 5, 7, 2, 8, 6]
PERMUTATION: List[int] = [2, 4, 3, 1]
PERMUTED_CHOICE_1: List[List[int]] = [
    [3, 5, 2, 7, 4],
    [10, 1, 9, 8, 6]
]
PERMUTED_CHOICE_2: List[int] = [6, 3, 7, 4, 8, 5, 10, 9]
E_BIT_SELECTION: List[int] = [4, 1, 2, 3, 2, 3, 4, 1]
SBOX_1: List[List[int]] = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2]
]
SBOX_2: List[List[int]] = [
    [0, 1, 2, 3],
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3]
]

# adds as many zeroes as needed to reach the desired length (bin)
def __pad_arr(arr: BitArray, desired_len: int) -> BitArray:
    arr.bin = ('0' * (desired_len - len(arr.bin))) + arr.bin

    return arr

# adds a 0 to complete a byte if text is uneven (hex)
def __pad_text(text: str) -> str:
    return ('0' if len(text) % 2 else '') + text

# splits the text into bytes (from hex)
def __blocks(text: int) -> Generator[int, None, None]:
    str_text: str = __pad_text(str(hex(text))[2:])

    for byte in [str_text[i:i+2] for i in range(0, len(str_text), 2)]:
        yield int(byte, 16)

    return

def __bitwise_xor(L: BitArray, R: BitArray) -> BitArray:
    return BitArray(bin="".join([
        str(int(l, 2) ^ int(r, 2)) for l, r in zip(L.bin, R.bin)
    ]))