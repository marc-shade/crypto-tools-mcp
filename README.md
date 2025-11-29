# Crypto Tools MCP Server

Classical cryptography analysis tools for CTF challenges and security education.

## Features

- **Caesar Cipher**: Encrypt and decrypt with shift-based substitution
- **Frequency Analysis**: Crack Caesar ciphers using letter frequency
- **ROT13**: Special case Caesar cipher (shift=13)
- **Vigenère Cipher**: Polyalphabetic substitution cipher
- **XOR Analysis**: XOR encryption/decryption and key recovery

## Tools

| Tool | Description |
|------|-------------|
| `caesar_encrypt` | Encrypt plaintext with Caesar cipher |
| `caesar_decrypt` | Decrypt ciphertext with known shift |
| `caesar_crack` | Crack Caesar cipher using frequency analysis |
| `frequency_analysis` | Analyze letter frequencies in text |
| `rot13` | ROT13 encode/decode (self-inverse) |
| `vigenere_encrypt` | Encrypt with Vigenère cipher |
| `vigenere_decrypt` | Decrypt with known Vigenère key |
| `xor_cipher` | XOR encrypt/decrypt with key |
| `detect_cipher_type` | Attempt to identify cipher type used |

## Frequency Analysis

English letter frequencies used for analysis:
- E: 12.7%, T: 9.1%, A: 8.2%, O: 7.5%, I: 7.0%
- N: 6.7%, S: 6.3%, H: 6.1%, R: 6.0%, ...

The tool compares ciphertext frequencies against expected English
frequencies to determine the most likely shift value.

## Use Cases

- CTF challenge solving
- Cryptography education
- Security research
- Classical cipher analysis
