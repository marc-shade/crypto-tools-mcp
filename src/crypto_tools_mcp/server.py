#!/usr/bin/env python3
"""
Crypto Tools MCP Server

Defense-grade cryptographic analysis and compliance tools.
Classical cryptography (Caesar, Vigenere, XOR, frequency analysis) plus
FIPS 140-3, CNSA 2.0, Post-Quantum Cryptography (FIPS 203/204/205),
Key Lifecycle Management (SP 800-57), and Crypto Audit Engine.
"""

import json
import math
import string
import time
import secrets
from collections import Counter
from pathlib import Path
from typing import Optional, Dict, Any

from mcp.server.fastmcp import FastMCP

from crypto_tools_mcp.compliance.fips_validator import FIPSValidator
from crypto_tools_mcp.compliance.cnsa_analyzer import CNSAAnalyzer
from crypto_tools_mcp.compliance.pqc_readiness import PQCReadinessAssessor
from crypto_tools_mcp.compliance.key_lifecycle import KeyLifecycleManager
from crypto_tools_mcp.compliance.crypto_audit import CryptoAuditEngine

mcp = FastMCP("crypto-tools")

# Compliance engine singletons
_fips_validator = FIPSValidator()
_cnsa_analyzer = CNSAAnalyzer()
_pqc_assessor = PQCReadinessAssessor()
_key_lifecycle = KeyLifecycleManager()
_crypto_audit = CryptoAuditEngine()

# Audit log for crypto operations (educational tracking)
AUDIT_LOG_FILE = Path("/tmp/crypto-tools-audit.log")


def audit_log(operation: str, details: Dict[str, Any] = None):
    """Log crypto operations for audit trail."""
    try:
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "operation": operation,
            "details": {k: v for k, v in (details or {}).items() if k != "plaintext" and k != "key"}
        }
        with open(AUDIT_LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


def validate_key_strength(key: str, min_length: int = 4) -> tuple[bool, str]:
    """Validate key meets minimum security requirements."""
    if len(key) < min_length:
        return False, f"Key too short (minimum {min_length} characters)"
    if key.lower() in ["password", "secret", "key", "test", "abc", "123"]:
        return False, "Key is a common weak password"
    return True, "Key passes basic validation"


def secure_key_clear(key_var: str) -> None:
    """
    Placeholder documenting the limitation of key clearing in Python.

    True secure memory clearing is not possible in pure Python due to
    garbage collection, string interning, and immutable string objects.
    For production key handling, use:
    - The ``cryptography`` library's key management
    - OS-level secure memory (e.g., mlock/mprotect)
    - Hardware Security Modules (HSM) via PKCS#11

    Callers should set their reference to ``os.urandom(len(key))`` or ``None``
    after use to drop the reference to the original key material.
    """


class SecureKeyHolder:
    """Context manager for secure key handling."""

    def __init__(self, key: str):
        self.key = key
        self._start_time = time.time()

    def __enter__(self):
        return self.key

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Log operation duration (without key content)
        duration = time.time() - self._start_time
        audit_log("key_session_end", {"duration_ms": round(duration * 1000, 2)})
        # Best-effort: replace reference with random bytes, then drop it
        import os
        if self.key:
            self.key = os.urandom(len(self.key))
        self.key = None


def generate_secure_key(length: int = 16, charset: str = "alphanumeric") -> str:
    """Generate a cryptographically secure random key."""
    if charset == "alphanumeric":
        alphabet = string.ascii_letters + string.digits
    elif charset == "hex":
        alphabet = string.hexdigits[:16]
    elif charset == "alpha":
        alphabet = string.ascii_uppercase
    else:
        alphabet = string.ascii_letters + string.digits + string.punctuation

    return ''.join(secrets.choice(alphabet) for _ in range(length))

# English letter frequencies (percentage)
ENGLISH_FREQ = {
    'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97,
    'N': 6.75, 'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25,
    'L': 4.03, 'C': 2.78, 'U': 2.76, 'M': 2.41, 'W': 2.36,
    'F': 2.23, 'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.29,
    'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15, 'Q': 0.10, 'Z': 0.07
}

# Common English words for validation
COMMON_WORDS = {'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'i',
                'it', 'for', 'not', 'on', 'with', 'he', 'as', 'you', 'do', 'at',
                'this', 'but', 'his', 'by', 'from', 'they', 'we', 'say', 'her', 'she'}


def shift_char(char: str, shift: int, encrypt: bool = True) -> str:
    """Shift a single character by the given amount."""
    if char.upper() in string.ascii_uppercase:
        base = ord('A') if char.isupper() else ord('a')
        if not encrypt:
            shift = -shift
        return chr((ord(char) - base + shift) % 26 + base)
    return char


def chi_squared_score(text: str) -> float:
    """Calculate chi-squared score against English frequencies."""
    text = text.upper()
    letters = [c for c in text if c in string.ascii_uppercase]
    if not letters:
        return float('inf')

    freq = Counter(letters)
    total = len(letters)

    score = 0.0
    for letter in string.ascii_uppercase:
        observed = freq.get(letter, 0) / total * 100
        expected = ENGLISH_FREQ.get(letter, 0)
        if expected > 0:
            score += ((observed - expected) ** 2) / expected

    return score


def count_english_words(text: str) -> int:
    """Count how many common English words appear in text."""
    words = text.lower().split()
    return sum(1 for word in words if word.strip('.,!?;:') in COMMON_WORDS)


@mcp.tool()
async def caesar_encrypt(plaintext: str, shift: int = 3) -> str:
    """
    Encrypt plaintext using Caesar cipher.

    Args:
        plaintext: Text to encrypt
        shift: Number of positions to shift (default: 3)

    Returns:
        JSON with encrypted ciphertext
    """
    shift = shift % 26
    ciphertext = ''.join(shift_char(c, shift, encrypt=True) for c in plaintext)

    return json.dumps({
        "success": True,
        "plaintext": plaintext,
        "ciphertext": ciphertext,
        "shift": shift,
        "method": "Caesar cipher"
    }, indent=2)


@mcp.tool()
async def caesar_decrypt(ciphertext: str, shift: int = 3) -> str:
    """
    Decrypt ciphertext using Caesar cipher with known shift.

    Args:
        ciphertext: Text to decrypt
        shift: Number of positions that were shifted

    Returns:
        JSON with decrypted plaintext
    """
    shift = shift % 26
    plaintext = ''.join(shift_char(c, shift, encrypt=False) for c in ciphertext)

    return json.dumps({
        "success": True,
        "ciphertext": ciphertext,
        "plaintext": plaintext,
        "shift": shift,
        "method": "Caesar cipher"
    }, indent=2)


@mcp.tool()
async def caesar_crack(ciphertext: str, show_all: bool = False) -> str:
    """
    Crack Caesar cipher using frequency analysis.

    Args:
        ciphertext: Encrypted text to crack
        show_all: Show all 26 possible decryptions

    Returns:
        JSON with most likely plaintext and shift value
    """
    results = []

    for shift in range(26):
        decrypted = ''.join(shift_char(c, shift, encrypt=False) for c in ciphertext)
        chi_score = chi_squared_score(decrypted)
        word_count = count_english_words(decrypted)

        results.append({
            "shift": shift,
            "plaintext": decrypted,
            "chi_squared": round(chi_score, 2),
            "english_words": word_count,
            "confidence": round(100 - min(chi_score, 100), 1)
        })

    # Sort by chi-squared score (lower is better)
    results.sort(key=lambda x: x["chi_squared"])

    best = results[0]

    response = {
        "success": True,
        "ciphertext": ciphertext,
        "best_guess": {
            "plaintext": best["plaintext"],
            "shift": best["shift"],
            "confidence": best["confidence"],
            "english_words_found": best["english_words"]
        },
        "method": "Frequency analysis (chi-squared test)"
    }

    if show_all:
        response["all_possibilities"] = results
    else:
        response["top_3"] = results[:3]

    return json.dumps(response, indent=2)


@mcp.tool()
async def frequency_analysis(text: str) -> str:
    """
    Perform letter frequency analysis on text.

    Args:
        text: Text to analyze

    Returns:
        JSON with letter frequencies and comparison to English
    """
    text_upper = text.upper()
    letters = [c for c in text_upper if c in string.ascii_uppercase]

    if not letters:
        return json.dumps({
            "success": False,
            "error": "No letters found in text"
        })

    freq = Counter(letters)
    total = len(letters)

    analysis = []
    for letter in sorted(freq, key=freq.get, reverse=True):
        observed = freq[letter] / total * 100
        expected = ENGLISH_FREQ.get(letter, 0)
        deviation = observed - expected

        analysis.append({
            "letter": letter,
            "count": freq[letter],
            "percentage": round(observed, 2),
            "english_expected": expected,
            "deviation": round(deviation, 2)
        })

    # Index of Coincidence
    ioc = sum(freq[l] * (freq[l] - 1) for l in freq) / (total * (total - 1)) if total > 1 else 0

    return json.dumps({
        "success": True,
        "total_letters": total,
        "unique_letters": len(freq),
        "index_of_coincidence": round(ioc, 4),
        "expected_english_ioc": 0.0667,
        "expected_random_ioc": 0.0385,
        "top_10_frequencies": analysis[:10],
        "full_analysis": analysis,
        "interpretation": {
            "ioc_indicates": "English-like text" if ioc > 0.05 else "Random or polyalphabetic cipher",
            "most_common": f"{analysis[0]['letter']} ({analysis[0]['percentage']}%)" if analysis else "N/A",
            "likely_maps_to_E": analysis[0]['letter'] if analysis else "N/A"
        }
    }, indent=2)


@mcp.tool()
async def rot13(text: str) -> str:
    """
    Apply ROT13 cipher (self-inverse: encoding = decoding).

    Args:
        text: Text to encode/decode

    Returns:
        JSON with ROT13 result
    """
    result = ''.join(shift_char(c, 13) for c in text)

    return json.dumps({
        "success": True,
        "input": text,
        "output": result,
        "method": "ROT13 (Caesar shift=13)",
        "note": "ROT13 is self-inverse: apply twice to get original"
    }, indent=2)


@mcp.tool()
async def generate_key(
    length: int = 16,
    charset: str = "alphanumeric",
    purpose: str = "general"
) -> str:
    """
    Generate a cryptographically secure random key.

    Args:
        length: Key length (8-64 characters)
        charset: Character set - alphanumeric, hex, alpha, or full
        purpose: Description of key purpose for audit log

    Returns:
        JSON with generated key and security info
    """
    # Validate length
    if length < 8:
        return json.dumps({"success": False, "error": "Key length must be at least 8 characters"})
    if length > 64:
        return json.dumps({"success": False, "error": "Key length must be at most 64 characters"})

    key = generate_secure_key(length, charset)

    # Calculate entropy based on actual charset size
    charset_sizes = {
        "alphanumeric": 62,  # a-z A-Z 0-9
        "hex": 16,
        "alpha": 26,  # A-Z only
        "full": 94,   # printable ASCII
    }
    charset_size = charset_sizes.get(charset, 62)
    entropy_bits = round(length * math.log2(charset_size), 1)

    audit_log("key_generated", {
        "length": length,
        "charset": charset,
        "purpose": purpose
    })

    return json.dumps({
        "success": True,
        "key": key,
        "length": len(key),
        "charset": charset,
        "entropy_bits": entropy_bits,
        "security_note": "Store this key securely. It will not be logged or stored by this tool.",
        "recommendations": [
            "Use a password manager to store this key",
            "Never share keys over insecure channels",
            "Rotate keys regularly for production use"
        ]
    }, indent=2)


@mcp.tool()
async def validate_key(key: str, algorithm: str = "vigenere") -> str:
    """
    Validate a key's strength for the specified algorithm.

    Args:
        key: Key to validate
        algorithm: Target algorithm (caesar, vigenere, xor)

    Returns:
        JSON with validation results and recommendations
    """
    issues = []
    recommendations = []

    # Length checks by algorithm
    min_lengths = {"caesar": 1, "vigenere": 4, "xor": 8}
    min_len = min_lengths.get(algorithm, 4)

    if len(key) < min_len:
        issues.append(f"Key too short for {algorithm} (minimum {min_len})")
        recommendations.append(f"Use at least {min_len} characters")

    # Weak key detection
    if key.lower() in ["password", "secret", "key", "test", "abc", "123", "aaa", "abc123"]:
        issues.append("Key is a commonly guessed password")
        recommendations.append("Use a randomly generated key")

    # Pattern detection
    if len(set(key)) == 1:
        issues.append("Key contains only one repeated character")
        recommendations.append("Use a more varied key")

    if key.isdigit():
        issues.append("Key contains only digits")
        recommendations.append("Include letters for stronger security")

    # Entropy estimate
    charset_size = len(set(key))
    entropy = len(key) * (charset_size.bit_length() if charset_size > 0 else 0)

    strength = "strong"
    if issues:
        strength = "weak" if len(issues) > 1 else "moderate"

    audit_log("key_validated", {
        "algorithm": algorithm,
        "strength": strength,
        "issues_found": len(issues)
    })

    return json.dumps({
        "success": True,
        "algorithm": algorithm,
        "key_length": len(key),
        "unique_characters": charset_size,
        "estimated_entropy_bits": entropy,
        "strength": strength,
        "issues": issues,
        "recommendations": recommendations if recommendations else ["Key appears sufficiently strong"],
        "passed": len(issues) == 0
    }, indent=2)


@mcp.tool()
async def vigenere_encrypt(plaintext: str, key: str, validate: bool = True) -> str:
    """
    Encrypt plaintext using Vigenère cipher.

    Args:
        plaintext: Text to encrypt
        key: Encryption key (letters only)
        validate: Whether to validate key strength (default: True)

    Returns:
        JSON with encrypted ciphertext
    """
    key = ''.join(c.upper() for c in key if c.isalpha())
    if not key:
        return json.dumps({"success": False, "error": "Key must contain letters"})

    # Key validation
    key_warning = None
    if validate:
        is_valid, msg = validate_key_strength(key)
        if not is_valid:
            key_warning = msg

    audit_log("vigenere_encrypt", {"key_length": len(key)})

    result = []
    key_index = 0

    for char in plaintext:
        if char.upper() in string.ascii_uppercase:
            shift = ord(key[key_index % len(key)]) - ord('A')
            result.append(shift_char(char, shift, encrypt=True))
            key_index += 1
        else:
            result.append(char)

    response = {
        "success": True,
        "plaintext": plaintext,
        "ciphertext": ''.join(result),
        "key": key,
        "key_length": len(key),
        "method": "Vigenère cipher"
    }
    if key_warning:
        response["security_warning"] = key_warning

    return json.dumps(response, indent=2)


@mcp.tool()
async def vigenere_decrypt(ciphertext: str, key: str) -> str:
    """
    Decrypt ciphertext using Vigenère cipher with known key.

    Args:
        ciphertext: Text to decrypt
        key: Decryption key

    Returns:
        JSON with decrypted plaintext
    """
    key = ''.join(c.upper() for c in key if c.isalpha())
    if not key:
        return json.dumps({"success": False, "error": "Key must contain letters"})

    result = []
    key_index = 0

    for char in ciphertext:
        if char.upper() in string.ascii_uppercase:
            shift = ord(key[key_index % len(key)]) - ord('A')
            result.append(shift_char(char, shift, encrypt=False))
            key_index += 1
        else:
            result.append(char)

    return json.dumps({
        "success": True,
        "ciphertext": ciphertext,
        "plaintext": ''.join(result),
        "key": key,
        "method": "Vigenère cipher"
    }, indent=2)


@mcp.tool()
async def xor_cipher(text: str, key: str, input_hex: bool = False) -> str:
    """
    XOR encrypt/decrypt text with a key.

    Args:
        text: Text or hex string to process
        key: XOR key
        input_hex: If True, treat input as hex string

    Returns:
        JSON with XOR result in multiple formats
    """
    if input_hex:
        try:
            data = bytes.fromhex(text.replace(' ', ''))
        except ValueError:
            return json.dumps({"success": False, "error": "Invalid hex string"})
    else:
        data = text.encode('utf-8')

    key_bytes = key.encode('utf-8')
    result = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))

    try:
        result_text = result.decode('utf-8')
        is_printable = all(c.isprintable() or c.isspace() for c in result_text)
    except UnicodeDecodeError:
        result_text = None
        is_printable = False

    return json.dumps({
        "success": True,
        "input": text,
        "key": key,
        "result_hex": result.hex(),
        "result_text": result_text if is_printable else "(non-printable)",
        "result_bytes": list(result),
        "method": "XOR cipher",
        "note": "XOR is self-inverse: apply twice with same key to get original"
    }, indent=2)


@mcp.tool()
async def detect_cipher_type(ciphertext: str) -> str:
    """
    Attempt to identify the type of cipher used.

    Args:
        ciphertext: Encrypted text to analyze

    Returns:
        JSON with cipher type analysis
    """
    text_upper = ciphertext.upper()
    letters = [c for c in text_upper if c in string.ascii_uppercase]

    if not letters:
        return json.dumps({
            "success": True,
            "analysis": "No letters found - possibly encoded (Base64, hex) or non-alphabetic cipher"
        })

    total = len(letters)
    freq = Counter(letters)

    # Calculate Index of Coincidence
    ioc = sum(freq[l] * (freq[l] - 1) for l in freq) / (total * (total - 1)) if total > 1 else 0

    # Chi-squared against English
    chi_sq = chi_squared_score(ciphertext)

    # Unique letter ratio
    unique_ratio = len(freq) / 26

    # Analysis
    indicators = []
    likely_type = "unknown"

    if ioc > 0.06:
        indicators.append("High IoC suggests monoalphabetic substitution")
        if chi_sq < 50:
            likely_type = "Caesar cipher or simple substitution"
            indicators.append("Chi-squared score suggests possible Caesar/shift cipher")
        else:
            likely_type = "Monoalphabetic substitution (not Caesar)"
    elif ioc > 0.04:
        indicators.append("Medium IoC suggests polyalphabetic cipher")
        likely_type = "Vigenère or similar polyalphabetic cipher"
    else:
        indicators.append("Low IoC suggests random/complex encryption")
        likely_type = "Modern cipher, XOR with long key, or random"

    if unique_ratio < 0.5:
        indicators.append(f"Only {len(freq)} unique letters - limited alphabet")

    # Check for patterns
    has_spaces = ' ' in ciphertext
    has_punctuation = any(c in string.punctuation for c in ciphertext)

    return json.dumps({
        "success": True,
        "ciphertext_length": len(ciphertext),
        "letter_count": total,
        "unique_letters": len(freq),
        "index_of_coincidence": round(ioc, 4),
        "chi_squared_score": round(chi_sq, 2),
        "has_spaces": has_spaces,
        "has_punctuation": has_punctuation,
        "likely_cipher_type": likely_type,
        "indicators": indicators,
        "recommendations": [
            "If Caesar: try caesar_crack tool",
            "If Vigenère: analyze key length using Kasiski examination",
            "If substitution: use frequency analysis to map letters",
            "If XOR: look for repeating patterns in hex output"
        ]
    }, indent=2)


@mcp.tool()
async def brute_force_xor(ciphertext_hex: str, max_key_length: int = 4) -> str:
    """
    Brute force XOR cipher with single-byte or short keys.

    Args:
        ciphertext_hex: Hex-encoded ciphertext
        max_key_length: Maximum key length to try (1-4)

    Returns:
        JSON with potential plaintexts
    """
    try:
        data = bytes.fromhex(ciphertext_hex.replace(' ', ''))
    except ValueError:
        return json.dumps({"success": False, "error": "Invalid hex string"})

    results = []
    max_key_length = min(max_key_length, 4)

    # Single byte keys
    for key in range(256):
        result = bytes(b ^ key for b in data)
        try:
            text = result.decode('utf-8')
            if all(c.isprintable() or c.isspace() for c in text):
                word_count = count_english_words(text)
                if word_count > 0 or len(text) < 20:
                    results.append({
                        "key": f"0x{key:02x}",
                        "key_char": chr(key) if 32 <= key < 127 else f"\\x{key:02x}",
                        "plaintext": text[:100] + ("..." if len(text) > 100 else ""),
                        "english_words": word_count,
                        "key_length": 1
                    })
        except UnicodeDecodeError:
            pass

    # Sort by English word count
    results.sort(key=lambda x: x["english_words"], reverse=True)

    return json.dumps({
        "success": True,
        "ciphertext_length": len(data),
        "keys_tried": 256,
        "printable_results": len(results),
        "top_results": results[:10],
        "note": "Results sorted by English word count"
    }, indent=2)


# =============================================================================
# Defense-Grade Cryptographic Compliance Tools
# =============================================================================


@mcp.tool()
async def check_fips_compliance(
    algorithms: str,
    scan_text: str = "",
) -> str:
    """
    Validate cryptographic algorithms against FIPS 140-3 approved list.

    Checks algorithm compliance, key lengths, security strength per
    SP 800-57, and maps findings to NIST 800-53 controls (SC-12, SC-13).

    Args:
        algorithms: Comma-separated list of algorithm names (e.g. "AES-256,SHA-384,RSA-2048,MD5")
        scan_text: Optional source code or config text to scan for algorithm usage

    Returns:
        JSON FIPS 140-3 compliance report with pass/fail per algorithm
    """
    algo_list = [a.strip() for a in algorithms.split(",") if a.strip()]

    if not algo_list and not scan_text:
        return json.dumps({
            "success": False,
            "error": "Provide algorithm names (comma-separated) or text to scan"
        })

    include_scan = bool(scan_text)

    if algo_list:
        report = _fips_validator.generate_compliance_report(
            algo_list, include_scan=include_scan, scan_text=scan_text
        )
    else:
        report = _fips_validator.scan_text_for_algorithms(scan_text)

    report["success"] = True
    audit_log("fips_compliance_check", {
        "algorithms_checked": len(algo_list),
        "scan_performed": include_scan,
        "status": report.get("overall_compliance", report.get("overall_status", "unknown")),
    })

    return json.dumps(report, indent=2)


@mcp.tool()
async def analyze_cnsa_compliance(
    algorithms: str,
    include_gap_analysis: bool = True,
    scan_text: str = "",
) -> str:
    """
    Check NSA CNSA 2.0 readiness for National Security Systems.

    Analyzes algorithms against CNSA 2.0 requirements (AES-256, SHA-384,
    ML-KEM-1024, ML-DSA-87), tracks transition timeline, and assesses
    crypto agility.

    Args:
        algorithms: Comma-separated algorithm names (e.g. "AES-256,ECDSA-P384,SHA-256")
        include_gap_analysis: Include full gap analysis with migration roadmap (default True)
        scan_text: Optional source code or config text to scan

    Returns:
        JSON CNSA 2.0 compliance analysis with gap assessment
    """
    algo_list = [a.strip() for a in algorithms.split(",") if a.strip()]

    if not algo_list and not scan_text:
        return json.dumps({
            "success": False,
            "error": "Provide algorithm names (comma-separated) or text to scan"
        })

    result = {}

    if algo_list and include_gap_analysis:
        result = _cnsa_analyzer.generate_gap_analysis(algo_list)
    elif algo_list:
        result = _cnsa_analyzer.analyze_multiple(algo_list)

    if scan_text:
        scan_result = _cnsa_analyzer.scan_text(scan_text)
        if result:
            result["code_scan"] = scan_result
        else:
            result = scan_result

    result["success"] = True

    audit_log("cnsa_compliance_check", {
        "algorithms_checked": len(algo_list),
        "gap_analysis": include_gap_analysis,
        "status": result.get("overall_compliance", result.get("overall_status", "unknown")),
    })

    return json.dumps(result, indent=2)


@mcp.tool()
async def assess_pqc_readiness(
    algorithms: str,
    data_sensitivity: str = "high",
    data_shelf_life_years: int = 10,
    system_type: str = "general",
    include_hndl: bool = True,
    include_roadmap: bool = True,
) -> str:
    """
    Assess post-quantum cryptography readiness per FIPS 203/204/205.

    Evaluates quantum vulnerability of current algorithms, calculates
    quantum risk scores, assesses Harvest-Now-Decrypt-Later threats,
    and generates PQC migration roadmaps.

    Args:
        algorithms: Comma-separated algorithm names (e.g. "RSA-2048,ECDSA-P256,AES-256")
        data_sensitivity: Data sensitivity level - "low", "medium", "high", or "critical"
        data_shelf_life_years: How many years data must remain confidential
        system_type: System type - "nss" (National Security), "federal", or "general"
        include_hndl: Include Harvest-Now-Decrypt-Later assessment (default True)
        include_roadmap: Include migration roadmap (default True)

    Returns:
        JSON post-quantum readiness assessment with risk scores and migration plan
    """
    algo_list = [a.strip() for a in algorithms.split(",") if a.strip()]

    if not algo_list:
        return json.dumps({
            "success": False,
            "error": "Provide algorithm names (comma-separated)"
        })

    result = _pqc_assessor.assess_multiple(algo_list)

    if include_hndl:
        result["hndl_assessment"] = _pqc_assessor.hndl_threat_assessment(
            algo_list, data_sensitivity, data_shelf_life_years
        )

    if include_roadmap:
        result["migration_roadmap"] = _pqc_assessor.generate_migration_roadmap(
            algo_list, system_type
        )

    result["hybrid_recommendations"] = _pqc_assessor.hybrid_mode_recommendations(algo_list)
    result["success"] = True

    audit_log("pqc_readiness_assessment", {
        "algorithms_checked": len(algo_list),
        "overall_risk": result.get("overall_quantum_risk", "unknown"),
        "system_type": system_type,
    })

    return json.dumps(result, indent=2)


@mcp.tool()
async def manage_key_lifecycle(
    action: str,
    key_id: str = "",
    name: str = "",
    key_type: str = "symmetric_encryption",
    algorithm: str = "AES-256",
    key_length_bits: int = 256,
    new_state: str = "",
    reason: str = "",
    owner: str = "",
    location: str = "",
    purpose: str = "",
    practice_description: str = "",
) -> str:
    """
    Manage cryptographic key lifecycle per NIST SP 800-57.

    Actions: create, transition, check, inventory, rotation, policies, destroy_guidance, report, validate_practice

    Args:
        action: Action to perform - "create", "transition", "check", "inventory",
                "rotation", "policies", "destroy_guidance", "report", "validate_practice"
        key_id: Key identifier (required for create, transition, check)
        name: Human-readable key name (for create)
        key_type: Key type e.g. "symmetric_encryption", "tls_key", "api_key" (for create)
        algorithm: Algorithm e.g. "AES-256", "RSA-4096" (for create)
        key_length_bits: Key length in bits (for create)
        new_state: Target state for transition - "active", "deactivated", "compromised", "destroyed"
        reason: Reason for state transition
        owner: Key owner/custodian
        location: Key storage location (e.g. "HSM", "AWS KMS")
        purpose: Key purpose description
        practice_description: Text description of key management practices (for validate_practice)

    Returns:
        JSON key lifecycle management result
    """
    action = action.lower().strip()

    if action == "create":
        if not key_id or not name:
            return json.dumps({"success": False, "error": "key_id and name required for create"})
        result = _key_lifecycle.create_key(
            key_id=key_id, name=name, key_type=key_type, algorithm=algorithm,
            key_length_bits=key_length_bits, owner=owner, location=location, purpose=purpose,
        )
    elif action == "transition":
        if not key_id or not new_state:
            return json.dumps({"success": False, "error": "key_id and new_state required for transition"})
        result = _key_lifecycle.transition_key(key_id, new_state, reason)
    elif action == "check":
        if not key_id:
            return json.dumps({"success": False, "error": "key_id required for check"})
        result = _key_lifecycle.check_key_compliance(key_id)
    elif action == "inventory":
        result = _key_lifecycle.get_key_inventory()
    elif action == "rotation":
        result = _key_lifecycle.check_rotation_schedule()
    elif action == "policies":
        result = _key_lifecycle.get_cryptoperiod_policies()
    elif action == "destroy_guidance":
        result = _key_lifecycle.get_destruction_guidance(key_type)
    elif action == "report":
        result = _key_lifecycle.generate_lifecycle_report()
    elif action == "validate_practice":
        if not practice_description:
            return json.dumps({"success": False, "error": "practice_description required"})
        result = _key_lifecycle.validate_key_management_practice(practice_description)
    else:
        return json.dumps({
            "success": False,
            "error": f"Unknown action: {action}",
            "valid_actions": [
                "create", "transition", "check", "inventory",
                "rotation", "policies", "destroy_guidance", "report", "validate_practice",
            ],
        })

    result["success"] = True
    audit_log("key_lifecycle", {"action": action, "key_id": key_id or "N/A"})

    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def audit_crypto_usage(
    text: str,
    output_format: str = "json",
) -> str:
    """
    Scan text or code for cryptographic security issues.

    Detects hardcoded keys, weak algorithms, insecure modes (ECB),
    missing key derivation, disabled certificate validation, insecure
    TLS versions, and more. Maps findings to CWE IDs.

    Args:
        text: Source code, configuration, or documentation text to audit
        output_format: Output format - "json" (default) or "sarif" for CI/CD integration

    Returns:
        JSON audit report with findings, CWE mappings, and remediation
    """
    if not text.strip():
        return json.dumps({"success": False, "error": "No text provided for audit"})

    result = _crypto_audit.scan_text(text)

    if output_format.lower() == "sarif":
        sarif = _crypto_audit.to_sarif(result)
        sarif["success"] = True
        audit_log("crypto_audit", {
            "format": "sarif",
            "findings": result["total_findings"],
            "risk": result["overall_risk"],
        })
        return json.dumps(sarif, indent=2)

    result["success"] = True
    audit_log("crypto_audit", {
        "format": "json",
        "findings": result["total_findings"],
        "risk": result["overall_risk"],
    })

    return json.dumps(result, indent=2)


@mcp.tool()
async def generate_compliance_report(
    algorithms: str,
    scan_text: str = "",
    system_type: str = "general",
    data_sensitivity: str = "high",
    data_shelf_life_years: int = 10,
) -> str:
    """
    Generate comprehensive cryptographic compliance report covering
    FIPS 140-3, CNSA 2.0, post-quantum readiness, and code audit.

    Produces a unified report suitable for security assessments,
    compliance audits, and migration planning.

    Args:
        algorithms: Comma-separated algorithm names to evaluate
        scan_text: Optional source code or config text to audit
        system_type: System type - "nss", "federal", or "general"
        data_sensitivity: Data sensitivity - "low", "medium", "high", or "critical"
        data_shelf_life_years: How many years data must remain confidential

    Returns:
        JSON comprehensive compliance report across all standards
    """
    algo_list = [a.strip() for a in algorithms.split(",") if a.strip()]

    if not algo_list and not scan_text:
        return json.dumps({
            "success": False,
            "error": "Provide algorithm names and/or text to scan"
        })

    report = {
        "report_type": "Comprehensive Cryptographic Compliance Report",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "system_type": system_type,
        "standards_evaluated": [
            "FIPS 140-3",
            "NIST SP 800-131A Rev 2",
            "NIST SP 800-57 Part 1 Rev 5",
            "NSA CNSA 2.0",
            "NIST FIPS 203 (ML-KEM)",
            "NIST FIPS 204 (ML-DSA)",
            "NIST FIPS 205 (SLH-DSA)",
            "OMB M-23-02 (PQC Migration)",
        ],
    }

    if algo_list:
        # FIPS 140-3
        report["fips_140_3"] = _fips_validator.generate_compliance_report(
            algo_list, include_scan=bool(scan_text), scan_text=scan_text
        )

        # CNSA 2.0
        report["cnsa_2_0"] = _cnsa_analyzer.generate_gap_analysis(algo_list)

        # Post-Quantum Readiness
        pqc = _pqc_assessor.assess_multiple(algo_list)
        pqc["hndl_assessment"] = _pqc_assessor.hndl_threat_assessment(
            algo_list, data_sensitivity, data_shelf_life_years
        )
        pqc["migration_roadmap"] = _pqc_assessor.generate_migration_roadmap(
            algo_list, system_type
        )
        report["post_quantum"] = pqc

    # Code Audit
    if scan_text:
        report["code_audit"] = _crypto_audit.scan_text(scan_text)

    # Overall compliance determination
    statuses = []
    if "fips_140_3" in report:
        statuses.append(report["fips_140_3"].get("overall_compliance", "UNKNOWN"))
    if "cnsa_2_0" in report:
        statuses.append(report["cnsa_2_0"].get("overall_compliance", "UNKNOWN"))
    if "code_audit" in report:
        risk = report["code_audit"].get("overall_risk", "UNKNOWN")
        statuses.append("NON_COMPLIANT" if risk in ("CRITICAL", "HIGH") else "COMPLIANT")

    if "NON_COMPLIANT" in statuses:
        overall = "NON_COMPLIANT"
    elif any("WARNING" in s for s in statuses):
        overall = "COMPLIANT_WITH_WARNINGS"
    elif all(s == "COMPLIANT" for s in statuses):
        overall = "COMPLIANT"
    else:
        overall = "REVIEW_REQUIRED"

    report["overall_compliance"] = overall

    # Executive summary
    summaries = []
    if "fips_140_3" in report:
        fips_sum = report["fips_140_3"].get("algorithm_validation", {}).get("summary", {})
        summaries.append(
            f"FIPS 140-3: {fips_sum.get('passed', 0)} passed, "
            f"{fips_sum.get('failed', 0)} failed, "
            f"{fips_sum.get('warnings', 0)} warnings."
        )
    if "cnsa_2_0" in report:
        cnsa_status = report["cnsa_2_0"].get("overall_compliance", "unknown")
        summaries.append(f"CNSA 2.0: {cnsa_status}.")
    if "post_quantum" in report:
        pq_risk = report["post_quantum"].get("overall_quantum_risk", "unknown")
        summaries.append(f"Quantum Risk: {pq_risk}.")
    if "code_audit" in report:
        audit_risk = report["code_audit"].get("overall_risk", "unknown")
        findings = report["code_audit"].get("total_findings", 0)
        summaries.append(f"Code Audit: {findings} findings, risk level {audit_risk}.")

    report["executive_summary"] = " ".join(summaries)
    report["success"] = True

    audit_log("full_compliance_report", {
        "algorithms": len(algo_list),
        "scan_performed": bool(scan_text),
        "overall": overall,
    })

    return json.dumps(report, indent=2, default=str)


def main():
    """Run the crypto tools MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
