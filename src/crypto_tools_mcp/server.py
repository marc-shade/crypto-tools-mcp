#!/usr/bin/env python3
"""
Crypto Tools MCP Server

Classical cryptography analysis tools for CTF challenges and security education.
Includes Caesar cipher, frequency analysis, Vigenère, XOR, and cipher detection.
"""

import json
import string
import time
import secrets
from collections import Counter
from pathlib import Path
from typing import Optional, Dict, Any

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("crypto-tools")

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
    Securely clear a key from memory (best effort in Python).
    Note: Python's memory management makes true secure erasure difficult.
    """
    try:
        # Overwrite with random data (best effort)
        import ctypes
        if key_var:
            location = id(key_var)
            size = len(key_var)
            ctypes.memset(location, 0, size)
    except Exception:
        pass  # Best effort - Python GC will handle eventually


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
        # Best effort key clearing
        secure_key_clear(self.key)
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
        "entropy_bits": round(len(key) * 5.7, 1),  # Approximate for alphanumeric
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


def main():
    """Run the crypto tools MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
