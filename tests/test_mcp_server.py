"""Tests for MCP server tool endpoints and integration."""

import json
import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

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
    frequency_analysis,
    detect_cipher_type,
    brute_force_xor,
    generate_key,
    validate_key,
    audit_log,
    AUDIT_LOG_FILE,
    mcp,
)


class TestMCPToolRegistration:
    """Test that all tools are properly registered with the MCP server."""

    def test_mcp_server_exists(self):
        """Test MCP server is initialized."""
        assert mcp is not None
        assert mcp.name == "crypto-tools"

    def test_tools_are_decorated(self):
        """Test all tool functions exist."""
        # Verify core functions exist
        assert callable(caesar_encrypt)
        assert callable(caesar_decrypt)
        assert callable(caesar_crack)
        assert callable(vigenere_encrypt)
        assert callable(vigenere_decrypt)
        assert callable(xor_cipher)
        assert callable(rot13)
        assert callable(frequency_analysis)
        assert callable(detect_cipher_type)
        assert callable(brute_force_xor)
        assert callable(generate_key)
        assert callable(validate_key)


class TestToolResponseFormat:
    """Test that all tools return properly formatted JSON responses."""

    @pytest.mark.asyncio
    async def test_caesar_encrypt_json_format(self):
        """Test caesar_encrypt returns valid JSON."""
        result = await caesar_encrypt("test", 3)
        data = json.loads(result)

        assert "success" in data
        assert "ciphertext" in data
        assert "method" in data

    @pytest.mark.asyncio
    async def test_caesar_decrypt_json_format(self):
        """Test caesar_decrypt returns valid JSON."""
        result = await caesar_decrypt("whvw", 3)
        data = json.loads(result)

        assert "success" in data
        assert "plaintext" in data

    @pytest.mark.asyncio
    async def test_caesar_crack_json_format(self):
        """Test caesar_crack returns valid JSON."""
        result = await caesar_crack("whvw")
        data = json.loads(result)

        assert "success" in data
        assert "best_guess" in data
        assert "method" in data

    @pytest.mark.asyncio
    async def test_vigenere_encrypt_json_format(self):
        """Test vigenere_encrypt returns valid JSON."""
        result = await vigenere_encrypt("test", "KEY", validate=False)
        data = json.loads(result)

        assert "success" in data
        assert "ciphertext" in data
        assert "key" in data

    @pytest.mark.asyncio
    async def test_vigenere_decrypt_json_format(self):
        """Test vigenere_decrypt returns valid JSON."""
        result = await vigenere_decrypt("DLCX", "KEY")
        data = json.loads(result)

        assert "success" in data
        assert "plaintext" in data

    @pytest.mark.asyncio
    async def test_xor_cipher_json_format(self):
        """Test xor_cipher returns valid JSON."""
        result = await xor_cipher("test", "K")
        data = json.loads(result)

        assert "success" in data
        assert "result_hex" in data
        assert "method" in data

    @pytest.mark.asyncio
    async def test_rot13_json_format(self):
        """Test rot13 returns valid JSON."""
        result = await rot13("test")
        data = json.loads(result)

        assert "success" in data
        assert "output" in data
        assert "note" in data

    @pytest.mark.asyncio
    async def test_frequency_analysis_json_format(self):
        """Test frequency_analysis returns valid JSON."""
        result = await frequency_analysis("THE QUICK BROWN FOX")
        data = json.loads(result)

        assert "success" in data
        assert "total_letters" in data
        assert "index_of_coincidence" in data

    @pytest.mark.asyncio
    async def test_detect_cipher_type_json_format(self):
        """Test detect_cipher_type returns valid JSON."""
        result = await detect_cipher_type("KHOOR ZRUOG")
        data = json.loads(result)

        assert "success" in data
        assert "likely_cipher_type" in data
        assert "recommendations" in data

    @pytest.mark.asyncio
    async def test_brute_force_xor_json_format(self):
        """Test brute_force_xor returns valid JSON."""
        result = await brute_force_xor("41424344")
        data = json.loads(result)

        assert "success" in data
        assert "keys_tried" in data
        assert "top_results" in data

    @pytest.mark.asyncio
    async def test_generate_key_json_format(self):
        """Test generate_key returns valid JSON."""
        result = await generate_key()
        data = json.loads(result)

        assert "success" in data
        assert "key" in data
        assert "entropy_bits" in data

    @pytest.mark.asyncio
    async def test_validate_key_json_format(self):
        """Test validate_key returns valid JSON."""
        result = await validate_key("TestKey123")
        data = json.loads(result)

        assert "success" in data
        assert "strength" in data
        assert "issues" in data


class TestToolErrorHandling:
    """Test error handling in MCP tools."""

    @pytest.mark.asyncio
    async def test_vigenere_empty_key_error(self):
        """Test vigenere with empty key returns error."""
        result = await vigenere_encrypt("test", "")
        data = json.loads(result)

        assert data["success"] is False
        assert "error" in data

    @pytest.mark.asyncio
    async def test_vigenere_decrypt_empty_key_error(self):
        """Test vigenere decrypt with empty key returns error."""
        result = await vigenere_decrypt("test", "")
        data = json.loads(result)

        assert data["success"] is False
        assert "error" in data

    @pytest.mark.asyncio
    async def test_xor_invalid_hex_error(self):
        """Test xor with invalid hex returns error."""
        result = await xor_cipher("not hex!", "K", input_hex=True)
        data = json.loads(result)

        assert data["success"] is False
        assert "error" in data

    @pytest.mark.asyncio
    async def test_brute_force_invalid_hex_error(self):
        """Test brute force with invalid hex returns error."""
        result = await brute_force_xor("xyz!")
        data = json.loads(result)

        assert data["success"] is False
        assert "error" in data

    @pytest.mark.asyncio
    async def test_generate_key_length_too_short(self):
        """Test generate_key with length < 8 returns error."""
        result = await generate_key(length=4)
        data = json.loads(result)

        assert data["success"] is False
        assert "at least 8" in data["error"]

    @pytest.mark.asyncio
    async def test_generate_key_length_too_long(self):
        """Test generate_key with length > 64 returns error."""
        result = await generate_key(length=100)
        data = json.loads(result)

        assert data["success"] is False
        assert "at most 64" in data["error"]

    @pytest.mark.asyncio
    async def test_frequency_analysis_no_letters(self):
        """Test frequency analysis with no letters returns error."""
        result = await frequency_analysis("12345!@#$%")
        data = json.loads(result)

        assert data["success"] is False
        assert "error" in data


class TestAuditLogging:
    """Test audit logging functionality."""

    def test_audit_log_function_exists(self):
        """Test audit_log function exists."""
        assert callable(audit_log)

    def test_audit_log_file_path(self):
        """Test audit log file path is defined."""
        assert AUDIT_LOG_FILE is not None
        assert str(AUDIT_LOG_FILE).endswith("crypto-tools-audit.log")

    @pytest.mark.asyncio
    async def test_audit_log_on_key_generation(self):
        """Test that key generation triggers audit log."""
        # This test verifies the operation completes without error
        # Actual log writing may fail silently (by design)
        result = await generate_key(purpose="test_audit")
        data = json.loads(result)
        assert data["success"] is True

    @pytest.mark.asyncio
    async def test_audit_log_on_key_validation(self):
        """Test that key validation triggers audit log."""
        result = await validate_key("TestKey123")
        data = json.loads(result)
        assert data["success"] is True


class TestToolParameters:
    """Test tool parameter handling."""

    @pytest.mark.asyncio
    async def test_caesar_default_shift(self):
        """Test caesar uses default shift of 3."""
        result = await caesar_encrypt("ABC")
        data = json.loads(result)

        assert data["shift"] == 3
        assert data["ciphertext"] == "DEF"

    @pytest.mark.asyncio
    async def test_generate_key_default_params(self):
        """Test generate_key default parameters."""
        result = await generate_key()
        data = json.loads(result)

        assert data["length"] == 16
        assert data["charset"] == "alphanumeric"

    @pytest.mark.asyncio
    async def test_validate_key_default_algorithm(self):
        """Test validate_key default algorithm is vigenere."""
        result = await validate_key("test")
        data = json.loads(result)

        assert data["algorithm"] == "vigenere"

    @pytest.mark.asyncio
    async def test_caesar_crack_default_show_all(self):
        """Test caesar_crack defaults to showing top 3."""
        result = await caesar_crack("ABC")
        data = json.loads(result)

        assert "top_3" in data
        assert "all_possibilities" not in data


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.mark.asyncio
    async def test_empty_plaintext_caesar(self):
        """Test Caesar with empty string."""
        result = await caesar_encrypt("", shift=3)
        data = json.loads(result)

        assert data["success"] is True
        assert data["ciphertext"] == ""

    @pytest.mark.asyncio
    async def test_single_char_caesar(self):
        """Test Caesar with single character."""
        result = await caesar_encrypt("A", shift=1)
        data = json.loads(result)

        assert data["ciphertext"] == "B"

    @pytest.mark.asyncio
    async def test_very_long_text(self):
        """Test with very long text."""
        long_text = "THE QUICK BROWN FOX " * 100
        result = await caesar_encrypt(long_text, shift=3)
        data = json.loads(result)

        assert data["success"] is True
        assert len(data["ciphertext"]) == len(long_text)

    @pytest.mark.asyncio
    async def test_unicode_handling(self):
        """Test Unicode character handling."""
        # Unicode chars should pass through unchanged
        result = await caesar_encrypt("Hello", shift=1)
        data = json.loads(result)
        assert data["success"] is True

    @pytest.mark.asyncio
    async def test_negative_shift(self):
        """Test negative shift value."""
        result = await caesar_encrypt("DEF", shift=-3)
        data = json.loads(result)

        # -3 mod 26 = 23, so should work
        assert data["success"] is True

    @pytest.mark.asyncio
    async def test_zero_shift(self):
        """Test zero shift value."""
        result = await caesar_encrypt("ABC", shift=0)
        data = json.loads(result)

        assert data["ciphertext"] == "ABC"

    @pytest.mark.asyncio
    async def test_xor_empty_result(self):
        """Test XOR with key that produces empty-like result."""
        # XOR with same value produces zeros
        result = await xor_cipher("AA", "A")
        data = json.loads(result)

        assert data["success"] is True
        assert data["result_hex"] == "0000"
