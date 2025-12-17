# Crypto Tools MCP Server

[![MCP](https://img.shields.io/badge/MCP-Compatible-blue)](https://modelcontextprotocol.io)
[![Python-3.10+](https://img.shields.io/badge/Python-3.10%2B-green)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![Part of Agentic System](https://img.shields.io/badge/Part_of-Agentic_System-brightgreen)](https://github.com/marc-shade/agentic-system-oss)

> **Cryptographic utilities and secure data handling.**

Part of the [Agentic System](https://github.com/marc-shade/agentic-system-oss) - a 24/7 autonomous AI framework with persistent memory.

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
---

## Part of the MCP Ecosystem

This server integrates with other MCP servers for comprehensive AGI capabilities:

| Server | Purpose |
|--------|---------|
| [enhanced-memory-mcp](https://github.com/marc-shade/enhanced-memory-mcp) | 4-tier persistent memory with semantic search |
| [agent-runtime-mcp](https://github.com/marc-shade/agent-runtime-mcp) | Persistent task queues and goal decomposition |
| [agi-mcp](https://github.com/marc-shade/agi-mcp) | Full AGI orchestration with 21 tools |
| [cluster-execution-mcp](https://github.com/marc-shade/cluster-execution-mcp) | Distributed task routing across nodes |
| [node-chat-mcp](https://github.com/marc-shade/node-chat-mcp) | Inter-node AI communication |
| [ember-mcp](https://github.com/marc-shade/ember-mcp) | Production-only policy enforcement |

See [agentic-system-oss](https://github.com/marc-shade/agentic-system-oss) for the complete framework.
