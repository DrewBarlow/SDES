from sdes.sdes import dsdes_encipher_ECB
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

def brute_force() -> Tuple[int, int]:
    for i in range(KEY_SPACE):
        for j in range(KEY_SPACE):
            results: List[bool] = [(dsdes_encipher_ECB(p, i, j) == c) for p, c in PT_CT_FROM_ASSIGNMENT.items()]

            if False not in results:
                return (i, j)

    return -1

def main() -> None:
    start: float = perf_counter()
    key1, key2 = brute_force()
    end: float = perf_counter()

    print(f"Found working keys ({bin(key1)}, {bin(key2)}) in {end - start:.4f} seconds.")
    with open("times/brute_force_time.txt", 'w') as f:
        f.write(f"{end - start:.4f}")

    return

if __name__ == "__main__":
    main()
