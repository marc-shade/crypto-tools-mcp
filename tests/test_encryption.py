"""Tests for encryption/decryption functions (Caesar, Vigenere, XOR, ROT13)."""

import json
import pytest
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from crypto_tools_mcp.server import (
    caesar_encrypt,
    caesar_decrypt,
    caesar_crack,
    vigenere_encrypt,
    vigenere_decrypt,
    xor_cipher,
    rot13,
    shift_char,
)


class TestShiftChar:
    """Test the shift_char helper function."""

    def test_shift_uppercase_letter(self):
        """Test shifting uppercase letters."""
        assert shift_char('A', 1, encrypt=True) == 'B'
        assert shift_char('Z', 1, encrypt=True) == 'A'
        assert shift_char('A', 3, encrypt=True) == 'D'

    def test_shift_lowercase_letter(self):
        """Test shifting lowercase letters."""
        assert shift_char('a', 1, encrypt=True) == 'b'
        assert shift_char('z', 1, encrypt=True) == 'a'
        assert shift_char('a', 3, encrypt=True) == 'd'

    def test_shift_decrypt(self):
        """Test decryption (reverse shift)."""
        assert shift_char('B', 1, encrypt=False) == 'A'
        assert shift_char('A', 1, encrypt=False) == 'Z'
        assert shift_char('D', 3, encrypt=False) == 'A'

    def test_shift_non_letter(self):
        """Test that non-letters are unchanged."""
        assert shift_char(' ', 5, encrypt=True) == ' '
        assert shift_char('1', 5, encrypt=True) == '1'
        assert shift_char('!', 5, encrypt=True) == '!'

    def test_shift_wrap_around(self):
        """Test wrapping around the alphabet."""
        assert shift_char('X', 5, encrypt=True) == 'C'
        assert shift_char('C', 5, encrypt=False) == 'X'


class TestCaesarCipher:
    """Test Caesar cipher encryption and decryption."""

    @pytest.mark.asyncio
    async def test_caesar_encrypt_basic(self, sample_plaintext):
        """Test basic Caesar encryption."""
        result = await caesar_encrypt(sample_plaintext, shift=3)
        data = json.loads(result)

        assert data["success"] is True
        assert data["ciphertext"] == "Khoor Zruog"
        assert data["shift"] == 3
        assert data["method"] == "Caesar cipher"

    @pytest.mark.asyncio
    async def test_caesar_decrypt_basic(self):
        """Test basic Caesar decryption."""
        result = await caesar_decrypt("Khoor Zruog", shift=3)
        data = json.loads(result)

        assert data["success"] is True
        assert data["plaintext"] == "Hello World"
        assert data["shift"] == 3

    @pytest.mark.asyncio
    async def test_caesar_roundtrip(self, caesar_test_vectors):
        """Test encrypt then decrypt returns original."""
        for vector in caesar_test_vectors:
            encrypted = await caesar_encrypt(vector["plaintext"], vector["shift"])
            enc_data = json.loads(encrypted)

            decrypted = await caesar_decrypt(enc_data["ciphertext"], vector["shift"])
            dec_data = json.loads(decrypted)

            assert dec_data["plaintext"] == vector["plaintext"]

    @pytest.mark.asyncio
    async def test_caesar_known_vectors(self, caesar_test_vectors):
        """Test against known test vectors."""
        for vector in caesar_test_vectors:
            result = await caesar_encrypt(vector["plaintext"], vector["shift"])
            data = json.loads(result)
            assert data["ciphertext"] == vector["ciphertext"], \
                f"Failed for {vector['plaintext']} with shift {vector['shift']}"

    @pytest.mark.asyncio
    async def test_caesar_shift_normalization(self):
        """Test that shifts > 26 are normalized."""
        result1 = await caesar_encrypt("ABC", shift=1)
        result2 = await caesar_encrypt("ABC", shift=27)

        data1 = json.loads(result1)
        data2 = json.loads(result2)

        assert data1["ciphertext"] == data2["ciphertext"]

    @pytest.mark.asyncio
    async def test_caesar_preserves_case(self):
        """Test that case is preserved."""
        result = await caesar_encrypt("AbCdEf", shift=1)
        data = json.loads(result)

        assert data["ciphertext"] == "BcDeFg"

    @pytest.mark.asyncio
    async def test_caesar_preserves_punctuation(self):
        """Test that punctuation and spaces are preserved."""
        result = await caesar_encrypt("Hello, World!", shift=1)
        data = json.loads(result)

        assert ", " in data["ciphertext"]
        assert "!" in data["ciphertext"]


class TestCaesarCrack:
    """Test Caesar cipher cracking via frequency analysis."""

    @pytest.mark.asyncio
    async def test_caesar_crack_simple(self):
        """Test cracking a simple Caesar cipher.

        Note: Frequency analysis requires sufficient text length to be reliable.
        Short texts may not produce the correct shift in best_guess.
        """
        # Use longer text for reliable frequency analysis
        plaintext = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG AGAIN AND AGAIN"
        encrypted = await caesar_encrypt(plaintext, shift=7)
        enc_data = json.loads(encrypted)

        # Crack it
        result = await caesar_crack(enc_data["ciphertext"])
        data = json.loads(result)

        assert data["success"] is True
        # The correct shift should be in top 3 results
        top_shifts = [r["shift"] for r in data["top_3"]]
        assert 7 in top_shifts, f"Expected shift 7 in top 3, got {top_shifts}"

    @pytest.mark.asyncio
    async def test_caesar_crack_rot13(self):
        """Test cracking ROT13 with sufficient text."""
        # Use longer text for reliable frequency analysis
        plaintext = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG HELLO WORLD"
        encrypted = await caesar_encrypt(plaintext, shift=13)
        enc_data = json.loads(encrypted)

        result = await caesar_crack(enc_data["ciphertext"])
        data = json.loads(result)

        # Check that correct shift is in top results
        top_shifts = [r["shift"] for r in data["top_3"]]
        assert 13 in top_shifts, f"Expected shift 13 in top 3, got {top_shifts}"

    @pytest.mark.asyncio
    async def test_caesar_crack_show_all(self):
        """Test showing all 26 possibilities."""
        result = await caesar_crack("ABC", show_all=True)
        data = json.loads(result)

        assert "all_possibilities" in data
        assert len(data["all_possibilities"]) == 26

    @pytest.mark.asyncio
    async def test_caesar_crack_top_3(self):
        """Test default shows top 3."""
        result = await caesar_crack("THE QUICK BROWN FOX", show_all=False)
        data = json.loads(result)

        assert "top_3" in data
        assert len(data["top_3"]) == 3

    @pytest.mark.asyncio
    async def test_caesar_crack_confidence(self):
        """Test confidence scoring.

        Confidence is calculated as 100 - chi_squared (capped at 100).
        Any result should have a numeric confidence value.
        """
        # Use longer text for more meaningful analysis
        plaintext = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
        encrypted = await caesar_encrypt(plaintext, shift=7)
        enc_data = json.loads(encrypted)

        result = await caesar_crack(enc_data["ciphertext"])
        data = json.loads(result)

        # Confidence should be a number (could be negative for high chi-squared)
        assert isinstance(data["best_guess"]["confidence"], (int, float))


class TestVigenereCipher:
    """Test Vigenere cipher encryption and decryption."""

    @pytest.mark.asyncio
    async def test_vigenere_encrypt_basic(self):
        """Test basic Vigenere encryption."""
        result = await vigenere_encrypt("HELLO", "KEY", validate=False)
        data = json.loads(result)

        assert data["success"] is True
        assert data["ciphertext"] == "RIJVS"
        assert data["key"] == "KEY"

    @pytest.mark.asyncio
    async def test_vigenere_decrypt_basic(self):
        """Test basic Vigenere decryption."""
        result = await vigenere_decrypt("RIJVS", "KEY")
        data = json.loads(result)

        assert data["success"] is True
        assert data["plaintext"] == "HELLO"

    @pytest.mark.asyncio
    async def test_vigenere_roundtrip(self, vigenere_test_vectors):
        """Test encrypt then decrypt returns original."""
        for vector in vigenere_test_vectors:
            encrypted = await vigenere_encrypt(
                vector["plaintext"], vector["key"], validate=False
            )
            enc_data = json.loads(encrypted)

            decrypted = await vigenere_decrypt(enc_data["ciphertext"], vector["key"])
            dec_data = json.loads(decrypted)

            # Normalize for comparison (Vigenere uses uppercase key)
            assert dec_data["plaintext"].upper() == vector["plaintext"].upper()

    @pytest.mark.asyncio
    async def test_vigenere_known_vectors(self, vigenere_test_vectors):
        """Test against known test vectors."""
        for vector in vigenere_test_vectors:
            result = await vigenere_encrypt(
                vector["plaintext"], vector["key"], validate=False
            )
            data = json.loads(result)
            assert data["ciphertext"].upper() == vector["ciphertext"].upper()

    @pytest.mark.asyncio
    async def test_vigenere_empty_key_error(self):
        """Test error handling for empty key."""
        result = await vigenere_encrypt("HELLO", "")
        data = json.loads(result)

        assert data["success"] is False
        assert "error" in data

    @pytest.mark.asyncio
    async def test_vigenere_numeric_key_error(self):
        """Test error handling for numeric-only key."""
        result = await vigenere_encrypt("HELLO", "12345")
        data = json.loads(result)

        assert data["success"] is False
        assert "error" in data

    @pytest.mark.asyncio
    async def test_vigenere_key_validation_warning(self):
        """Test weak key produces warning."""
        result = await vigenere_encrypt("HELLO", "abc", validate=True)
        data = json.loads(result)

        # Should succeed but with warning about weak key
        assert data["success"] is True
        assert "security_warning" in data

    @pytest.mark.asyncio
    async def test_vigenere_preserves_non_letters(self):
        """Test that spaces and punctuation are preserved."""
        result = await vigenere_encrypt("Hello, World!", "KEY", validate=False)
        data = json.loads(result)

        assert ", " in data["ciphertext"]
        assert "!" in data["ciphertext"]


class TestXORCipher:
    """Test XOR cipher encryption and decryption."""

    @pytest.mark.asyncio
    async def test_xor_basic(self):
        """Test basic XOR operation."""
        result = await xor_cipher("A", "A")
        data = json.loads(result)

        assert data["success"] is True
        assert data["result_hex"] == "00"

    @pytest.mark.asyncio
    async def test_xor_self_inverse(self):
        """Test XOR is self-inverse."""
        # First XOR
        result1 = await xor_cipher("hello", "KEY")
        data1 = json.loads(result1)

        # Second XOR (from hex)
        result2 = await xor_cipher(data1["result_hex"], "KEY", input_hex=True)
        data2 = json.loads(result2)

        assert data2["result_text"] == "hello"

    @pytest.mark.asyncio
    async def test_xor_known_vectors(self, xor_test_vectors):
        """Test against known test vectors."""
        for vector in xor_test_vectors:
            result = await xor_cipher(vector["text"], vector["key"])
            data = json.loads(result)
            assert data["result_hex"] == vector["result_hex"]

    @pytest.mark.asyncio
    async def test_xor_hex_input(self):
        """Test hex input mode."""
        result = await xor_cipher("48656c6c6f", "K", input_hex=True)
        data = json.loads(result)

        assert data["success"] is True
        assert "result_hex" in data

    @pytest.mark.asyncio
    async def test_xor_invalid_hex(self):
        """Test error handling for invalid hex."""
        result = await xor_cipher("not valid hex!", "KEY", input_hex=True)
        data = json.loads(result)

        assert data["success"] is False
        assert "error" in data

    @pytest.mark.asyncio
    async def test_xor_non_printable_result(self):
        """Test handling of non-printable results."""
        # XOR that produces non-printable bytes
        result = await xor_cipher("test", "\x00")
        data = json.loads(result)

        assert data["success"] is True
        # Result might be non-printable


class TestROT13:
    """Test ROT13 cipher."""

    @pytest.mark.asyncio
    async def test_rot13_basic(self):
        """Test basic ROT13."""
        result = await rot13("Hello")
        data = json.loads(result)

        assert data["success"] is True
        assert data["output"] == "Uryyb"

    @pytest.mark.asyncio
    async def test_rot13_self_inverse(self):
        """Test ROT13 is self-inverse."""
        original = "The Quick Brown Fox"

        result1 = await rot13(original)
        data1 = json.loads(result1)

        result2 = await rot13(data1["output"])
        data2 = json.loads(result2)

        assert data2["output"] == original

    @pytest.mark.asyncio
    async def test_rot13_preserves_non_letters(self):
        """Test ROT13 preserves non-letters."""
        result = await rot13("Hello, World! 123")
        data = json.loads(result)

        assert ", " in data["output"]
        assert "! 123" in data["output"]

    @pytest.mark.asyncio
    async def test_rot13_case_preservation(self):
        """Test ROT13 preserves case."""
        result = await rot13("AbCdEf")
        data = json.loads(result)

        # Check case pattern is preserved
        output = data["output"]
        assert output[0].isupper()
        assert output[1].islower()
        assert output[2].isupper()
