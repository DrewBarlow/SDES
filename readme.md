# CMSC 687, Project 1
## Drew Barlow (JU08810)

### MAIN FUNCTIONS:
  * sdes_encipher_ECB(plaintext, key)
  * sdes_decipher_ECB(ciphertext, key)
  * dsdes_encipher_ECB(plaintext, key1, key2)
  * dsdes_decipher_ECB(ciphertext, key1, key2)
  * sdes_encipher_CBC(plaintext, key, iv)
  * sdes_decipher_CBC(ciphertext, key, iv)
  * dsdes_encipher_CBC(plaintext, key1, key2, iv)
  * dsdes_decipher_CBC(ciphertext, key1, key2, iv)

### ANSWERS TO QUESTIONS:
#### 2 | Key(s) used to produce the ciphertext in the known pairs
  * Key 1: `0b1100111111`; and,
  * Key 2: `0b0101010011`.

#### 3 | ...Time taken to determine the key (meet in the middle)
  * ???

#### 4 | ...Time it takes to uncover the key (brute force)
  * 8176s; or,
  * 136m16s; or,
  * 2h16m16s.

#### 5 | Decryption of the text encrypted using CBC mode...
  * `♥♀♥☻\n♦\n♣☺♂♥♠♂♫♣♂♂☺\n♥☻♀\n☺☼☼`

#### 6. A list of the S-DES weak keys
  * `0b0000000000`
  * `0b1111111111`
  * ...???