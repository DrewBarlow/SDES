from .. import sdes
from sdes.sdes import dsdes_encipher_ECB, sdes_encipher_ECB, sdes_decipher_ECB
from time import perf_counter
from typing import Dict, List, Tuple

PT_CT_FROM_ASSIGNMENT: Dict[int, int] = {
    0x42: 0x52,
    0x72: 0xf0,
    0x75: 0xbe,
    0x74: 0x69,
    0x65: 0x8a
}
KEY_SPACE: int = 2 ** 10

def meet_in_the_middle() -> Tuple[int, int]:
    encrypted_plaintext: Dict[int, List[int]] = {}
    decrypted_ciphertext: Dict[int, List[int]] = {}
    INIT_PT: int = 0x42
    INIT_CT: int = 0x52

    # use the encrypted plaintext and decrypted ciphertext
    # as dictionary keys that store a list of working keys
    # that match that middle text.
    for i in range(KEY_SPACE):
        ept: int = sdes_encipher_ECB(INIT_PT, i)
        dct: int = sdes_decipher_ECB(INIT_CT, i)

        if encrypted_plaintext.get(ept):
            encrypted_plaintext[ept].append(i)
        else:
            encrypted_plaintext[ept] = [i]

        if decrypted_ciphertext.get(dct):
            decrypted_ciphertext[dct].append(i)
        else:
            decrypted_ciphertext[dct] = [i]

    # grab the list of keys for the common texts
    # between the encrypted plaintext and decrypted ciphertext
    for ept, ept_keys in encrypted_plaintext.items():
        dct_keys = decrypted_ciphertext.get(ept)

        if dct_keys:
            # match all of the keys at the common text
            for e_key in ept_keys:
                for d_key in dct_keys:
                    all_match: bool = True

                    # make sure that the two keys check out in ECB mode
                    for pt, ct in PT_CT_FROM_ASSIGNMENT.items():
                        if dsdes_encipher_ECB(pt, e_key, d_key) != ct:
                            all_match = False
                    if all_match:
                        return (e_key, d_key)

    return (None, None)

def main() -> None:
    start: float = perf_counter()
    key1, key2 = meet_in_the_middle()
    end: float = perf_counter()
    seconds: str = f"{end - start:.4f}"

    print(f"Found working keys ({bin(key1)}, {bin(key2)}) in {seconds} seconds.")
    with open("times/meet_in_the_middle_time.txt", 'w') as f:
        f.write(seconds)

    return

if __name__ == "__main__":
    main()
