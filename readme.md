## MAIN FUNCTIONS:
  * sdes_encipher_ECB(plaintext, key)
  * sdes_decipher_ECB(ciphertext, key)
  * dsdes_encipher_ECB(plaintext, key1, key2)
  * dsdes_decipher_ECB(ciphertext, key1, key2)
  * sdes_encipher_CBC(plaintext, key, iv)
  * sdes_decipher_CBC(ciphertext, key, iv)
  * dsdes_encipher_CBC(plaintext, key1, key2, iv)
  * dsdes_decipher_CBC(ciphertext, key1, key2, iv)

.
## NOTE:
### I did not do official packaging with setuptools or anything.
### Therefore, I recommend either copying `sdes/` into `attacks/` or making a symlink.

## Answers to Questions
### Keys used to produce the ciphertext in the known pairs:
  * Key 1: `0b1100111111`; and,
  * Key 2: `0b0101010011`.

### Time taken to determine the key pair (meet in the middle):
  * 2.902s.

### Time taken to determine the key pair (brute force):
  * 8176s; or,
  * 136m16s; or,
  * 2h16m16s.

### Decryption of the text encrypted using CBC mode:
  * `"Congratulations on your success!"`
  * Code for this can be found in main.py at line 189.

### A list of the S-DES weak keys:
  * `0b0000000000`; and,
  * `0b1111111111`; and,
  * `0b0111101000`; and,
  * `0b1000010111`.
