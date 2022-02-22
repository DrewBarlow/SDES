from src.sdes import *
from typing import Dict, List, Tuple

# Table A_1 (p, c) from answer Appendix A
A_1: Dict[int, Tuple[int, int]] = {
    0: (0b10000000, 0b10101000),
    1: (0b01000000, 0b10111110),
    2: (0b00100000, 0b00010110),
    3: (0b00010000, 0b01001010),
    4: (0b00001000, 0b01001001),
    5: (0b00000100, 0b01001110),
    6: (0b00000010, 0b00010101),
    7: (0b00000001, 0b01101000)
}

# Table A_2 (k, c) from answer Appendix A
A_2: Dict[int, Tuple[int, int]] = {
    0: (0b1000000000, 0b01100001),
    1: (0b0100000000, 0b00010011),
    2: (0b0010000000, 0b01001111),
    3: (0b0001000000, 0b11100101),
    4: (0b0000100000, 0b01100101),
    5: (0b0000010000, 0b01011100),
    6: (0b0000001000, 0b10101110),
    7: (0b0000000100, 0b11011001),
    8: (0b0000000010, 0b10101010),
    9: (0b0000000001, 0b01001110),
}

# Table A_3 (k, c) from answer Appendix A
A_3: Dict[int, Tuple[int, int]] = {
    0: (0b0000000011, 0b00000011),
    1: (0b0011001010, 0b00100010),
    2: (0b0001011001, 0b01000000),
    3: (0b1011001111, 0b01100000)
}

# Table A_4 (k, c) from answer Appendix A
A_4: Dict[int, Tuple[int, int]] = {
    0: (0b0001101101, 0b10000111),
    1: (0b0001101110, 0b10110110),
    2: (0b0001110000, 0b10110100),
    3: (0b0001110001, 0b00110011),
    4: (0b0001110110, 0b11011001),
    5: (0b0001111000, 0b10001101),
    6: (0b0001111001, 0b00010001)
}

# plaintext/ciphertext pairs from assignment description
PT_CT_FROM_ASSIGNMENT: Dict[int, int] = {
    0x42: 0x52,
    0x72: 0xf0,
    0x75: 0xbe,
    0x74: 0x69,
    0x65: 0x8a
}

# given ciphertext from assignment description
CT_FROM_ASSIGNMENT: str = 0x586519b031aaee9a235247601fb37baefbcd54d8c3763f8523d2a1315ed8bdcc

def e_variable_plaintext_known_answer() -> bool:
    KEY: int = 0b0000000000
    
    for p, c in A_1.values():
        if sdes_encipher_ECB(p, KEY) != c:
            return False

    return True

def d_variable_plaintext_known_answer() -> bool:
    KEY: int = 0b0000000000

    for p, c in A_1.values():
        if sdes_decipher_ECB(c, KEY) != p:
            return False

    return True

def e_variable_key_known_answer() -> None:
    P: int = 0b00000000

    for k, c in A_2.values():
        if sdes_encipher_ECB(P, k) != c:
            return False

    return True

def d_variable_key_known_answer() -> bool:
    P: int = 0b00000000

    for k, c in A_2.values():
        if sdes_decipher_ECB(c, k) != P:
            return False

    return True

def e_permutation_operation_known_answer() -> bool:
    P: int = 0b00000000

    for k, c in A_3.values():
        if sdes_encipher_ECB(P, k) != c:
            return False

    return True

def d_permutation_operation_known_answer() -> bool:
    P: int = 0b00000000

    for k, c in A_3.values():
        if sdes_decipher_ECB(c, k) != P:
            return False

    return True

def e_substitution_table_known_answer() -> bool:
    P: int = 0b00000000

    for k, c in A_4.values():
        if sdes_encipher_ECB(P, k) != c:
            return False

    return True

def d_substitution_table_known_answer() -> bool:
    P: int = 0b00000000

    for k, c in A_4.values():
        if sdes_decipher_ECB(c, k) != P:
            return False

    return True

def e_dsdes_brute_force_key_check() -> bool:
    KEY1_FOUND: int = 0b1100111111
    KEY2_FOUND: int = 0b0101010011

    for p, c in PT_CT_FROM_ASSIGNMENT.items():
        if dsdes_encipher_ECB(p, KEY1_FOUND, KEY2_FOUND) != c:
            return False

    return True

def d_dsdes_brute_force_key_check() -> bool:
    KEY1_FOUND: int = 0b1100111111
    KEY2_FOUND: int = 0b0101010011

    for p, c in PT_CT_FROM_ASSIGNMENT.items():
        if dsdes_decipher_ECB(c, KEY1_FOUND, KEY2_FOUND) != p:
            return False

    return True

def primitive_modes_tests() -> bool:
    KEY1 = 0b0010000101
    KEY2 = 0b1000110000
    PT = 0x4c4d46414f4f4f

    CTSECB = sdes_encipher_ECB(PT, KEY1)
    CTDECB = dsdes_encipher_ECB(PT, KEY1, KEY2)
    CTSCBC = sdes_encipher_CBC(PT, KEY1, 0x9c)
    CTDCBC = dsdes_encipher_CBC(PT, KEY1, KEY2, 0x9c)

    deciphered: List[int] = [
        sdes_decipher_ECB(CTSECB, KEY1),
        dsdes_decipher_ECB(CTDECB, KEY1, KEY2),
        sdes_decipher_CBC(CTSCBC, KEY1, 0x9c),
        dsdes_decipher_CBC(CTDCBC, KEY1, KEY2, 0x9c)
    ]

    for dec in deciphered:
        if dec != PT:
            return False

    return True

def d_dsdes_ciphertext_to_ascii() -> str:
    KEY1_FOUND: int = 0b1100111111
    KEY2_FOUND: int = 0b0101010011
    IV: int = 0x9c

    text: str = str(hex(dsdes_decipher_CBC(
        CT_FROM_ASSIGNMENT, 
        KEY1_FOUND, 
        KEY2_FOUND,
        IV
    )))[2:]
    print(text)

    #return "BROKEN!"
    return bytes.fromhex(text).decode("ASCII")

def main() -> None:
    pf = lambda b: "passed" if b else "failed"

    # running tests given in the answers doc
    # if a fxn returns True, all values match the table
    # if false, at least one value does not match the table
    evpka: str = pf(e_variable_plaintext_known_answer())
    dvpka: str = pf(d_variable_plaintext_known_answer())
    evkka: str = pf(e_variable_key_known_answer())
    dvkka: str = pf(d_variable_key_known_answer())
    epoka: str = pf(e_permutation_operation_known_answer())
    dpoka: str = pf(d_permutation_operation_known_answer())
    estka: str = pf(e_substitution_table_known_answer())
    dstka: str = pf(d_substitution_table_known_answer())
    edbfkc: str = pf(e_dsdes_brute_force_key_check())
    ddbfkc: str = pf(d_dsdes_brute_force_key_check())
    pmt: str = pf(primitive_modes_tests())
    ddcta: str = d_dsdes_ciphertext_to_ascii()

    print(f"Variable Plaintext Known Answer (Encrypt) {evpka}.")
    print(f"Variable Plaintext Known Answer (Decrypt) {dvpka}.")
    print(f"Variable Key Known Answer (Encrypt) {evkka}.")
    print(f"Variable Key Known Answer (Decrypt) {dvkka}.")
    print(f"Permutation Operation Known Answer (Encrypt) {epoka}.")
    print(f"Permutation Operation Known Answer (Decrypt) {dpoka}.")
    print(f"Substitution Table Known Answer (Encrypt) {estka}.")
    print(f"Substitution Table Known Answer (Decrypt) {dstka}.")
    print(f"DSDES Brute Force Key Check (Encrypt) {edbfkc}.")
    print(f"DSDES Brute Force Key Check (Decrypt) {ddbfkc}.")
    print(f"Primitive Modes Tests {pmt}.")
    print(f"Decrypted ciphertext from assignment: '{ddcta}'.")

    return

if __name__ == "__main__":
    main()
    
