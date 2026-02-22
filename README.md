![crypto_tools_mcp](https://github.com/user-attachments/assets/9f39e2bc-de67-4c7d-b0ca-6c96da9bb360)

# Crypto Tools MCP Server

[![MCP](https://img.shields.io/badge/MCP-Compatible-blue)](https://modelcontextprotocol.io)
[![Python-3.10+](https://img.shields.io/badge/Python-3.10%2B-green)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-412_passed-brightgreen)]()
[![Coverage](https://img.shields.io/badge/Coverage-86%25-green)]()
[![FIPS 140-3](https://img.shields.io/badge/FIPS_140--3-Validated-red)](https://csrc.nist.gov/publications/detail/fips/140/3/final)
[![CNSA 2.0](https://img.shields.io/badge/CNSA_2.0-Ready-orange)](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF)
[![Post-Quantum](https://img.shields.io/badge/Post--Quantum-FIPS_203%2F204%2F205-purple)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![Part of Agentic System](https://img.shields.io/badge/Part_of-Agentic_System-brightgreen)](https://github.com/marc-shade/agentic-system-oss)

> **Defense-grade cryptographic compliance and analysis tools for MCP.**

Part of the [Agentic System](https://github.com/marc-shade/agentic-system-oss) - a 24/7 autonomous AI framework with persistent memory.

## Features

### Defense Compliance Modules

- **FIPS 140-3 Validator** - Validate algorithms against Federal Information Processing Standards
- **CNSA 2.0 Analyzer** - NSA Commercial National Security Algorithm Suite readiness
- **Post-Quantum Readiness** - NIST FIPS 203/204/205 quantum vulnerability assessment
- **Key Lifecycle Manager** - Key state management per NIST SP 800-57 Part 1 Rev 5
- **Crypto Audit Engine** - Code/config scanning with CWE mapping and SARIF output

### Classical Cryptography

- **Caesar Cipher** - Encrypt, decrypt, and crack with frequency analysis
- **Vigenere Cipher** - Polyalphabetic substitution cipher
- **XOR Analysis** - XOR encryption/decryption and brute-force key recovery
- **ROT13** - Self-inverse Caesar variant
- **Frequency Analysis** - Letter frequency and Index of Coincidence
- **Cipher Detection** - Automatic cipher type identification

---

## Tools

### Compliance Tools

| Tool | Description |
|------|-------------|
| `check_fips_compliance` | Validate algorithms against FIPS 140-3 approved list |
| `analyze_cnsa_compliance` | Check CNSA 2.0 readiness with gap analysis |
| `assess_pqc_readiness` | Post-quantum cryptography readiness assessment |
| `manage_key_lifecycle` | Key lifecycle management per SP 800-57 |
| `audit_crypto_usage` | Scan code for cryptographic issues (CWE mapped) |
| `generate_compliance_report` | Unified report across all standards |

### Classical Crypto Tools

| Tool | Description |
|------|-------------|
| `caesar_encrypt` | Encrypt plaintext with Caesar cipher |
| `caesar_decrypt` | Decrypt ciphertext with known shift |
| `caesar_crack` | Crack Caesar cipher using frequency analysis |
| `frequency_analysis` | Analyze letter frequencies in text |
| `rot13` | ROT13 encode/decode (self-inverse) |
| `vigenere_encrypt` | Encrypt with Vigenere cipher |
| `vigenere_decrypt` | Decrypt with known Vigenere key |
| `xor_cipher` | XOR encrypt/decrypt with key |
| `brute_force_xor` | Brute-force XOR with single-byte keys |
| `detect_cipher_type` | Identify cipher type used |
| `generate_key` | Generate cryptographically secure random key |
| `validate_key` | Validate key strength for an algorithm |

---

## FIPS 140-3 Compliance

Validates algorithms against the FIPS 140-3 approved list per NIST SP 800-131A Rev 2.

### Approved Algorithms

| Category | Algorithms | Standard |
|----------|-----------|----------|
| Symmetric | AES-128, AES-192, AES-256, AES-GCM, AES-CCM | FIPS 197, SP 800-38D |
| Hash | SHA-224, SHA-256, SHA-384, SHA-512, SHA-3 family | FIPS 180-4, FIPS 202 |
| MAC | HMAC-SHA-2, CMAC-AES, GMAC-AES | FIPS 198-1, SP 800-38B |
| Signature | RSA (2048+), ECDSA (P-256/384/521), EdDSA | FIPS 186-5 |
| Post-Quantum | ML-KEM, ML-DSA, SLH-DSA | FIPS 203, 204, 205 |
| DRBG | CTR_DRBG, Hash_DRBG, HMAC_DRBG | SP 800-90A Rev 1 |
| KDF | SP 800-108, SP 800-56C, HKDF, PBKDF2 | SP 800-108, SP 800-56C |
| Key Wrap | AES-KW, AES-KWP | SP 800-38F |

### Disallowed Algorithms

| Algorithm | Reason |
|-----------|--------|
| MD5 | Collision attacks trivial |
| SHA-1 | Practical collision attacks (SHAttered, 2017) |
| DES | 56-bit key, brute-forceable since 1998 |
| 3DES/TDEA | 64-bit block size (Sweet32), deprecated 2023 |
| RC4 | Statistical biases, banned in TLS |
| Blowfish | 64-bit block size, not FIPS approved |
| Dual_EC_DRBG | NSA backdoor, withdrawn |

### Usage Example

```
check_fips_compliance(algorithms="AES-256,SHA-384,RSA-2048,MD5,3DES")
```

---

## CNSA 2.0 (National Security Systems)

Analyzes cryptographic posture against NSA's Commercial National Security Algorithm Suite 2.0.

### CNSA 2.0 Required Algorithms

| Use Case | Algorithm | Parameter |
|----------|-----------|-----------|
| Symmetric Encryption | AES-256 | 256-bit key (not 128/192) |
| Hashing | SHA-384 | Minimum (not SHA-256) |
| Key Encapsulation | ML-KEM-1024 | NIST Level 5 (not 512/768) |
| Digital Signatures | ML-DSA-87 | NIST Level 5 (not 44/65) |
| Hash-Based Signatures | SLH-DSA-256 | NIST Level 5 (alternative) |

### CNSA 2.0 Transition Timeline

| Category | Deadline | Requirement |
|----------|----------|-------------|
| Software/firmware signing | 2025 | ML-DSA-87 or SLH-DSA-256 |
| Web servers/browsers (TLS) | 2025 | ML-KEM-1024 + ML-DSA-87 |
| Cloud services | 2025 | Full CNSA 2.0 suite |
| Networking equipment | 2026 | ML-KEM-1024 + ML-DSA-87 |
| Operating systems | 2027 | Native PQC support |
| Custom/niche applications | 2030 | Complete PQC migration |
| All NSS (full compliance) | 2033 | Classical algorithms retired |

### CNSA 1.0 vs 2.0

| Use Case | CNSA 1.0 | CNSA 2.0 | Change |
|----------|----------|----------|--------|
| Symmetric | AES-256 | AES-256 | No change |
| Hash | SHA-384 | SHA-384 | No change |
| Signatures | ECDSA-P384, RSA-3072+ | ML-DSA-87, SLH-DSA-256 | Classical -> PQC |
| Key Exchange | ECDH-P384, DH-3072+ | ML-KEM-1024 | ECDH -> Lattice KEM |

### Usage Example

```
analyze_cnsa_compliance(algorithms="AES-256,ECDSA-P384,SHA-256,RSA-2048")
```

---

## Post-Quantum Cryptography (FIPS 203/204/205)

Assesses readiness for the quantum computing threat per NIST post-quantum standards.

### NIST PQC Standards

| Standard | Algorithm | Type | NIST Level | Key Size | Sig/CT Size |
|----------|-----------|------|------------|----------|-------------|
| FIPS 203 | ML-KEM-512 | KEM | 1 | 800 B | 768 B |
| FIPS 203 | ML-KEM-768 | KEM | 3 | 1,184 B | 1,088 B |
| FIPS 203 | ML-KEM-1024 | KEM | 5 | 1,568 B | 1,568 B |
| FIPS 204 | ML-DSA-44 | Signature | 2 | 1,312 B | 2,420 B |
| FIPS 204 | ML-DSA-65 | Signature | 3 | 1,952 B | 3,309 B |
| FIPS 204 | ML-DSA-87 | Signature | 5 | 2,592 B | 4,627 B |
| FIPS 205 | SLH-DSA-128s | Signature | 1 | 32 B | 7,856 B |
| FIPS 205 | SLH-DSA-256s | Signature | 5 | 64 B | 29,792 B |

### Quantum Vulnerability

| Algorithm | Attack | Quantum Security |
|-----------|--------|-----------------|
| RSA (all sizes) | Shor's algorithm | **0 bits (broken)** |
| ECDSA/ECDH (all curves) | Shor's algorithm | **0 bits (broken)** |
| DH (all sizes) | Shor's algorithm | **0 bits (broken)** |
| AES-128 | Grover's algorithm | 64 bits (reduced) |
| AES-256 | Grover's algorithm | 128 bits (adequate) |
| SHA-256 | Grover's algorithm | 128 bits (adequate) |

### HNDL Threat Assessment

Harvest-Now-Decrypt-Later (HNDL): adversaries intercept encrypted data today to decrypt once quantum computers are available. The tool calculates HNDL risk based on data sensitivity, shelf life, and algorithm vulnerability.

### Usage Example

```
assess_pqc_readiness(
    algorithms="RSA-2048,ECDSA-P256,AES-256,SHA-256",
    data_sensitivity="critical",
    data_shelf_life_years=15,
    system_type="nss"
)
```

---

## Key Lifecycle Management (SP 800-57)

Manages cryptographic key states and cryptoperiods per NIST SP 800-57 Part 1 Rev 5.

### Key States

```
Pre-activation -> Active -> Deactivated -> Destroyed
                    |            |
                    v            v
                Suspended   Compromised -> Destroyed-Compromised
```

### Cryptoperiod Limits

| Key Type | Max Active Period |
|----------|------------------|
| Session key (TLS) | 24 hours |
| API key | 90 days |
| Master key | 1 year |
| SSH key | 1 year |
| TLS certificate key | 398 days |
| Symmetric encryption | 2 years |
| Signing private key | 3 years |
| Intermediate CA | 3-5 years |
| Root CA | 10-20 years |

### Usage Examples

```
# Create and track a key
manage_key_lifecycle(action="create", key_id="prod-aes-1", name="Production AES Key",
                     key_type="symmetric_encryption", algorithm="AES-256",
                     owner="security-team", location="AWS KMS")

# Activate the key
manage_key_lifecycle(action="transition", key_id="prod-aes-1", new_state="active")

# Check compliance
manage_key_lifecycle(action="check", key_id="prod-aes-1")

# Get full inventory
manage_key_lifecycle(action="inventory")

# Check rotation schedule
manage_key_lifecycle(action="rotation")

# Validate key management practices
manage_key_lifecycle(action="validate_practice",
                     practice_description="Keys stored in HSM with RBAC, rotated annually...")
```

---

## Crypto Audit Engine

Scans code and configuration for cryptographic security issues with CWE mapping.

### Detection Categories

| Category | Rules | CWE IDs |
|----------|-------|---------|
| Hardcoded Secrets | Keys, AWS creds, hex material | CWE-798 |
| Weak Random | Non-CSPRNG usage | CWE-330, CWE-338 |
| Broken Algorithms | MD5, SHA-1, DES, RC4 | CWE-327, CWE-328 |
| Insecure Modes | ECB, CBC without HMAC | CWE-327 |
| Missing KDF | Raw password as key | CWE-327 |
| Weak Key Length | RSA <2048, short symmetric | CWE-326 |
| Certificate Issues | verify=False, CERT_NONE | CWE-295 |
| Insecure TLS | SSLv3, TLS 1.0, TLS 1.1 | CWE-757 |
| Timing Attacks | Non-constant-time comparison | CWE-208 |

### SARIF Output

The audit engine outputs SARIF (Static Analysis Results Interchange Format) for CI/CD integration with GitHub Code Scanning, Azure DevOps, and other platforms.

### Usage Example

```
# Audit source code
audit_crypto_usage(text="import hashlib\nh = hashlib.md5(data)\nkey = 'hardcoded_secret_key'")

# Get SARIF output for CI/CD
audit_crypto_usage(text=source_code, output_format="sarif")
```

---

## Comprehensive Compliance Report

Generate a unified report covering all standards.

```
generate_compliance_report(
    algorithms="AES-256,RSA-2048,SHA-256,ECDSA-P256",
    scan_text=source_code,
    system_type="federal",
    data_sensitivity="high",
    data_shelf_life_years=10
)
```

### Compliance Coverage Matrix

| Standard | Control | Coverage |
|----------|---------|----------|
| FIPS 140-3 | Algorithm validation | Full |
| SP 800-131A Rev 2 | Algorithm transitions | Full |
| SP 800-57 Part 1 | Key management | Full |
| SP 800-53 SC-12 | Key establishment | Full |
| SP 800-53 SC-13 | Cryptographic protection | Full |
| SP 800-53 SC-17 | PKI certificates | Partial |
| SP 800-53 SC-28 | Information at rest | Partial |
| CNSA 2.0 | NSS algorithm suite | Full |
| CNSSP 15 | AES policy | Full |
| FIPS 203 | ML-KEM | Full |
| FIPS 204 | ML-DSA | Full |
| FIPS 205 | SLH-DSA | Full |
| OMB M-23-02 | PQC migration | Full |
| SP 800-88 | Media sanitization | Guidance |

---

## Testing

```bash
# Run all tests with coverage
python -m pytest tests/ -v --cov=crypto_tools_mcp --cov-report=term-missing

# Run compliance tests only
python -m pytest tests/test_compliance.py -v

# Run classical cipher tests only
python -m pytest tests/test_encryption.py tests/test_hashing.py -v
```

Test coverage: 412 tests across 6 test modules covering classical ciphers, key management, MCP tool registration, and all five compliance modules (FIPS, CNSA, PQC, Key Lifecycle, Crypto Audit).

---

## Installation

```bash
# Clone and install
git clone https://github.com/marc-shade/crypto-tools-mcp.git
cd crypto-tools-mcp
pip install -e .

# Or install with uv
uv pip install -e .
```

### MCP Configuration

Add to your Claude Desktop or MCP client configuration:

```json
{
  "mcpServers": {
    "crypto-tools": {
      "command": "crypto-tools-mcp"
    }
  }
}
```

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
