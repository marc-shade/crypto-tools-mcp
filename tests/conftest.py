"""Pytest configuration and fixtures for crypto-tools-mcp tests."""

import json
import pytest
import sys
from pathlib import Path

# Add src to path for imports
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from crypto_tools_mcp.server import (
    shift_char,
    chi_squared_score,
    count_english_words,
    generate_secure_key,
    validate_key_strength,
    SecureKeyHolder,
    ENGLISH_FREQ,
    COMMON_WORDS,
)


# ============================================================================
# Test Data Fixtures
# ============================================================================

@pytest.fixture
def sample_plaintext():
    """Standard plaintext for encryption tests."""
    return "Hello World"


@pytest.fixture
def sample_plaintext_long():
    """Longer plaintext for better frequency analysis."""
    return "The quick brown fox jumps over the lazy dog"


@pytest.fixture
def caesar_test_vectors():
    """Known Caesar cipher test vectors."""
    return [
        {"plaintext": "ABC", "shift": 1, "ciphertext": "BCD"},
        {"plaintext": "abc", "shift": 1, "ciphertext": "bcd"},
        {"plaintext": "XYZ", "shift": 3, "ciphertext": "ABC"},
        {"plaintext": "Hello", "shift": 13, "ciphertext": "Uryyb"},  # ROT13
        {"plaintext": "ATTACK AT DAWN", "shift": 3, "ciphertext": "DWWDFN DW GDZQ"},
        {"plaintext": "Hello, World!", "shift": 7, "ciphertext": "Olssv, Dvysk!"},
    ]


@pytest.fixture
def vigenere_test_vectors():
    """Known Vigenere cipher test vectors."""
    return [
        {"plaintext": "ATTACKATDAWN", "key": "LEMON", "ciphertext": "LXFOPVEFRNHR"},
        {"plaintext": "HELLO", "key": "KEY", "ciphertext": "RIJVS"},
        {"plaintext": "hello world", "key": "KEY", "ciphertext": "rijvs uyvjn"},
    ]


@pytest.fixture
def xor_test_vectors():
    """Known XOR cipher test vectors.

    XOR calculation: each byte of text XOR'd with corresponding key byte.
    'A' (0x41) XOR 'A' (0x41) = 0x00
    'A' (0x41) XOR 'X' (0x58) = 0x19
    'h' (0x68) XOR 'K' (0x4b) = 0x23
    """
    return [
        {"text": "A", "key": "A", "result_hex": "00"},
        {"text": "ABC", "key": "X", "result_hex": "191a1b"},
        {"text": "hello", "key": "K", "result_hex": "232e272724"},  # h=68, e=65, l=6c, l=6c, o=6f XOR K=4b
    ]


@pytest.fixture
def english_sample_text():
    """Sample English text for frequency analysis."""
    return """
    The quick brown fox jumps over the lazy dog. This sentence contains every
    letter of the alphabet. It is often used for testing fonts and keyboards.
    The frequency of letters in English follows a predictable pattern, with E
    being the most common letter followed by T, A, O, I, N, S, H, and R.
    """


@pytest.fixture
def random_text():
    """Random-looking text (low English word count)."""
    return "XQZJK VWMPL BNRTY FGCDS"


@pytest.fixture
def weak_keys():
    """List of weak keys that should fail validation."""
    return ["password", "secret", "key", "test", "abc", "123", "aaa", "abc123"]


@pytest.fixture
def strong_keys():
    """List of strong keys that should pass validation."""
    return ["Tr0ub4dor&3", "correcthorsebatterystaple", "X9#kL2$mN7@pQ4"]


# ============================================================================
# Helper Functions
# ============================================================================

def parse_json_response(response: str) -> dict:
    """Parse JSON response from MCP tools."""
    return json.loads(response)


def assert_success(response: str) -> dict:
    """Assert response is successful and return parsed JSON."""
    data = parse_json_response(response)
    assert data.get("success") is True, f"Expected success=True, got: {data}"
    return data


def assert_failure(response: str) -> dict:
    """Assert response failed and return parsed JSON."""
    data = parse_json_response(response)
    assert data.get("success") is False, f"Expected success=False, got: {data}"
    return data


# Export helpers for use in tests
@pytest.fixture
def json_helpers():
    """Provide JSON helper functions to tests."""
    return {
        "parse": parse_json_response,
        "assert_success": assert_success,
        "assert_failure": assert_failure,
    }
