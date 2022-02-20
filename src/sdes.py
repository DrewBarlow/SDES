from bitstring import BitArray
from src.key import __key_schedule
from src.round import __initial_permutation, __inverse_permutation, __nibbles, __round
from src.utility import __blocks, __pad_arr, __pad_text
from typing import Callable

KEY_SIZE: int = 10
BLOCK_SIZE: int = 8

# main encipher fxn for single des
def __sdes_encipher(plaintext: int, key: int) -> int:
    pt_arr: BitArray = BitArray(bin(plaintext))
    key_arr: BitArray = BitArray(bin(key))

    # we pad the plaintext and key with 0s to fit their expected sizes
    __pad_arr(pt_arr, BLOCK_SIZE)
    __pad_arr(key_arr, KEY_SIZE)

    init: BitArray = __initial_permutation(pt_arr)

    # we split the initial permutation into two nibbles
    # we then perform our four rounds of enciphering
    l, r = __nibbles(init)
    for i in range(4):
        key: BitArray = __key_schedule(i + 1, key_arr)
        l, r = __round(l + r, key)

    # return the final permutation as an integer
    return int(__inverse_permutation(r + l).bin, 2)

# main decipher fxn for single des
def __sdes_decipher(ciphertext: int, key: int) -> int:
    # same story here as above in encipher
    ct_arr: BitArray = BitArray(bin(ciphertext))
    key_arr: BitArray = BitArray(bin(key))
    __pad_arr(ct_arr, BLOCK_SIZE)
    __pad_arr(key_arr, KEY_SIZE)

    init: BitArray = __initial_permutation(ct_arr)

    # we perform our operations backwards from encipherment
    # this is the same as above, but with r and l swapped
    r, l = __nibbles(init)
    for i in range(3, -1, -1):
        key: BitArray = __key_schedule(i + 1, key_arr)
        r, l = __round(r + l, key)
    
    return int(__inverse_permutation(l + r).bin, 2)

# main encipher fxn for double des
def dsdes_encipher(plaintext: int, key_1: int, key_2: int) -> int:
    return __sdes_encipher(__sdes_encipher(plaintext, key_1), key_2)

# main decipher fxn for double des
def dsdes_decipher(ciphertext: int, key_1: int, key_2: int) -> int:
    return __sdes_decipher(__sdes_decipher(ciphertext, key_2), key_1)

# ECB mode for SDES
def __sdes_ECB(text: int, key: int, fxn: Callable[[int, int], int]) -> int:
    full_text: str = ""

    for block in __blocks(text):
        full_text += __pad_text(str(hex(fxn(block, key)))[2:])

    return int(full_text, 16)

def sdes_encipher_ECB(plaintext: int, key: int) -> int:
    return __sdes_ECB(plaintext, key, __sdes_encipher)

def sdes_decipher_ECB(ciphertext: int, key: int) -> int:
    return __sdes_ECB(ciphertext, key, __sdes_decipher)

# ECB mode for DSDES
def dsdes_encipher_ECB(plaintext: int, key_1: int, key_2: int) -> int:
    sdes_key_1: int = sdes_encipher_ECB(plaintext, key_1)
    return sdes_encipher_ECB(sdes_key_1, key_2)

def dsdes_decipher_ECB(ciphertext: int, key_1: int, key_2: int) -> int:
    sdes_key_2: int = sdes_decipher_ECB(ciphertext, key_2)
    return sdes_decipher_ECB(sdes_key_2, key_1)

# CBC mode for SDES
def sdes_encipher_CBC(plaintext: int, key: int, iv: int) -> int:
    prev_text: int = iv
    full_text: str = ""

    # split the text into blocks
    # XOR the previous block's output text with the current block,
    # then append the result to the text string
    for block in __blocks(plaintext):
        prev_text = __sdes_encipher(block ^ prev_text, key)
        full_text += __pad_text(str(hex(prev_text))[2:])

    return int(full_text, 16)

def sdes_decipher_CBC(ciphertext: int, key: int, iv: int) -> int:
    prev_text: int = iv
    full_text: str = ""

    # split the text into blocks
    # swap the order of XORing from above
    for block in __blocks(ciphertext):
        full_text += __pad_text(str(hex(prev_text ^ __sdes_decipher(block, key)))[2:])
        prev_text = block

    return int(full_text, 16)

# CBC mode for DSDES
def dsdes_encipher_CBC(plaintext: int, key_1: int, key_2: int, iv: int) -> int:
    sdes_key_1: int = sdes_encipher_CBC(plaintext, key_1, iv)
    return sdes_encipher_CBC(sdes_key_1, key_2, iv)

def dsdes_decipher_CBC(ciphertext: int, key_1: int, key_2: int, iv: int) -> int:
    sdes_key_2: int = sdes_decipher_CBC(ciphertext, key_2, iv)
    return sdes_decipher_CBC(sdes_key_2, key_1, iv)
