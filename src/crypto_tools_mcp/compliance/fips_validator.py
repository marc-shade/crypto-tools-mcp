"""
FIPS 140-3 Compliance Validator

Validates cryptographic algorithms, key lengths, and configurations against
Federal Information Processing Standards (FIPS) 140-3 approved lists.

References:
- FIPS 140-3: Security Requirements for Cryptographic Modules
- NIST SP 800-131A Rev 2: Transitioning the Use of Cryptographic Algorithms
- NIST SP 800-57 Part 1 Rev 5: Recommendation for Key Management
- NIST SP 800-53 Rev 5: SC-12 (Key Establishment), SC-13 (Cryptographic Protection)
"""

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class FIPSStatus(Enum):
    """FIPS algorithm approval status."""
    APPROVED = "approved"
    DEPRECATED = "deprecated"
    DISALLOWED = "disallowed"
    LEGACY_USE_ONLY = "legacy_use_only"
    NOT_RECOGNIZED = "not_recognized"


class SecurityStrength(Enum):
    """Security strength levels per SP 800-57 Part 1."""
    BITS_80 = 80
    BITS_112 = 112
    BITS_128 = 128
    BITS_192 = 192
    BITS_256 = 256


@dataclass
class AlgorithmInfo:
    """Metadata for a cryptographic algorithm."""
    name: str
    category: str  # symmetric, hash, mac, signature, kdf, drbg, kex, key_wrap
    fips_status: FIPSStatus
    security_bits: int
    min_key_length: Optional[int] = None
    max_key_length: Optional[int] = None
    fips_standard: str = ""
    deprecation_date: Optional[str] = None
    notes: str = ""
    nist_800_53_controls: list = field(default_factory=list)


@dataclass
class ValidationResult:
    """Result of a single algorithm validation check."""
    algorithm: str
    status: str  # pass, fail, warning
    fips_status: FIPSStatus
    security_bits: int
    message: str
    remediation: str = ""
    control_mappings: list = field(default_factory=list)
    deprecation_info: str = ""


class FIPSValidator:
    """
    FIPS 140-3 compliance validator for cryptographic algorithms.

    Checks algorithms against FIPS 140-3 approved lists, validates key lengths
    per NIST SP 800-131A Rev 2, assesses security strength per SP 800-57,
    and maps findings to NIST 800-53 controls.
    """

    APPROVED_ALGORITHMS: dict[str, AlgorithmInfo] = {
        # Symmetric Encryption (FIPS 197)
        "AES-128": AlgorithmInfo(
            name="AES-128", category="symmetric", fips_status=FIPSStatus.APPROVED,
            security_bits=128, min_key_length=128, max_key_length=128,
            fips_standard="FIPS 197", notes="Approved for all uses",
            nist_800_53_controls=["SC-13", "SC-28"],
        ),
        "AES-192": AlgorithmInfo(
            name="AES-192", category="symmetric", fips_status=FIPSStatus.APPROVED,
            security_bits=192, min_key_length=192, max_key_length=192,
            fips_standard="FIPS 197", notes="Approved for all uses",
            nist_800_53_controls=["SC-13", "SC-28"],
        ),
        "AES-256": AlgorithmInfo(
            name="AES-256", category="symmetric", fips_status=FIPSStatus.APPROVED,
            security_bits=256, min_key_length=256, max_key_length=256,
            fips_standard="FIPS 197", notes="Highest AES strength; required for CNSA 2.0",
            nist_800_53_controls=["SC-13", "SC-28"],
        ),
        # Hash Functions (FIPS 180-4, FIPS 202)
        "SHA-224": AlgorithmInfo(
            name="SHA-224", category="hash", fips_status=FIPSStatus.APPROVED,
            security_bits=112, fips_standard="FIPS 180-4",
            notes="Acceptable but SHA-256+ preferred",
            nist_800_53_controls=["SC-13"],
        ),
        "SHA-256": AlgorithmInfo(
            name="SHA-256", category="hash", fips_status=FIPSStatus.APPROVED,
            security_bits=128, fips_standard="FIPS 180-4",
            notes="Widely used; minimum for most applications",
            nist_800_53_controls=["SC-13"],
        ),
        "SHA-384": AlgorithmInfo(
            name="SHA-384", category="hash", fips_status=FIPSStatus.APPROVED,
            security_bits=192, fips_standard="FIPS 180-4",
            notes="Required minimum for CNSA 2.0",
            nist_800_53_controls=["SC-13"],
        ),
        "SHA-512": AlgorithmInfo(
            name="SHA-512", category="hash", fips_status=FIPSStatus.APPROVED,
            security_bits=256, fips_standard="FIPS 180-4",
            notes="Highest SHA-2 strength",
            nist_800_53_controls=["SC-13"],
        ),
        "SHA-512/256": AlgorithmInfo(
            name="SHA-512/256", category="hash", fips_status=FIPSStatus.APPROVED,
            security_bits=128, fips_standard="FIPS 180-4",
            notes="Truncated SHA-512 variant",
            nist_800_53_controls=["SC-13"],
        ),
        "SHA3-224": AlgorithmInfo(
            name="SHA3-224", category="hash", fips_status=FIPSStatus.APPROVED,
            security_bits=112, fips_standard="FIPS 202",
            notes="SHA-3 family",
            nist_800_53_controls=["SC-13"],
        ),
        "SHA3-256": AlgorithmInfo(
            name="SHA3-256", category="hash", fips_status=FIPSStatus.APPROVED,
            security_bits=128, fips_standard="FIPS 202",
            notes="SHA-3 family",
            nist_800_53_controls=["SC-13"],
        ),
        "SHA3-384": AlgorithmInfo(
            name="SHA3-384", category="hash", fips_status=FIPSStatus.APPROVED,
            security_bits=192, fips_standard="FIPS 202",
            notes="SHA-3 family",
            nist_800_53_controls=["SC-13"],
        ),
        "SHA3-512": AlgorithmInfo(
            name="SHA3-512", category="hash", fips_status=FIPSStatus.APPROVED,
            security_bits=256, fips_standard="FIPS 202",
            notes="SHA-3 family; highest SHA-3 strength",
            nist_800_53_controls=["SC-13"],
        ),
        "SHAKE128": AlgorithmInfo(
            name="SHAKE128", category="hash", fips_status=FIPSStatus.APPROVED,
            security_bits=128, fips_standard="FIPS 202",
            notes="Extendable-output function (XOF)",
            nist_800_53_controls=["SC-13"],
        ),
        "SHAKE256": AlgorithmInfo(
            name="SHAKE256", category="hash", fips_status=FIPSStatus.APPROVED,
            security_bits=256, fips_standard="FIPS 202",
            notes="Extendable-output function (XOF)",
            nist_800_53_controls=["SC-13"],
        ),
        # MACs
        "HMAC-SHA-256": AlgorithmInfo(
            name="HMAC-SHA-256", category="mac", fips_status=FIPSStatus.APPROVED,
            security_bits=128, min_key_length=256, fips_standard="FIPS 198-1",
            notes="HMAC with SHA-256",
            nist_800_53_controls=["SC-13"],
        ),
        "HMAC-SHA-384": AlgorithmInfo(
            name="HMAC-SHA-384", category="mac", fips_status=FIPSStatus.APPROVED,
            security_bits=192, min_key_length=384, fips_standard="FIPS 198-1",
            notes="HMAC with SHA-384",
            nist_800_53_controls=["SC-13"],
        ),
        "HMAC-SHA-512": AlgorithmInfo(
            name="HMAC-SHA-512", category="mac", fips_status=FIPSStatus.APPROVED,
            security_bits=256, min_key_length=512, fips_standard="FIPS 198-1",
            notes="HMAC with SHA-512",
            nist_800_53_controls=["SC-13"],
        ),
        "CMAC-AES": AlgorithmInfo(
            name="CMAC-AES", category="mac", fips_status=FIPSStatus.APPROVED,
            security_bits=128, min_key_length=128, fips_standard="SP 800-38B",
            notes="Cipher-based MAC using AES",
            nist_800_53_controls=["SC-13"],
        ),
        "GMAC-AES": AlgorithmInfo(
            name="GMAC-AES", category="mac", fips_status=FIPSStatus.APPROVED,
            security_bits=128, min_key_length=128, fips_standard="SP 800-38D",
            notes="Galois MAC using AES",
            nist_800_53_controls=["SC-13"],
        ),
        # Digital Signatures
        "RSA-2048": AlgorithmInfo(
            name="RSA-2048", category="signature", fips_status=FIPSStatus.APPROVED,
            security_bits=112, min_key_length=2048, fips_standard="FIPS 186-5",
            deprecation_date="2030-12-31",
            notes="Acceptable through 2030; migrate to 3072+ or ECDSA",
            nist_800_53_controls=["SC-12", "SC-13", "SC-17"],
        ),
        "RSA-3072": AlgorithmInfo(
            name="RSA-3072", category="signature", fips_status=FIPSStatus.APPROVED,
            security_bits=128, min_key_length=3072, fips_standard="FIPS 186-5",
            notes="Recommended minimum RSA key size",
            nist_800_53_controls=["SC-12", "SC-13", "SC-17"],
        ),
        "RSA-4096": AlgorithmInfo(
            name="RSA-4096", category="signature", fips_status=FIPSStatus.APPROVED,
            security_bits=152, min_key_length=4096, fips_standard="FIPS 186-5",
            notes="Strong RSA; performance trade-off",
            nist_800_53_controls=["SC-12", "SC-13", "SC-17"],
        ),
        "RSA-7680": AlgorithmInfo(
            name="RSA-7680", category="signature", fips_status=FIPSStatus.APPROVED,
            security_bits=192, min_key_length=7680, fips_standard="FIPS 186-5",
            notes="Very strong RSA; significant performance impact",
            nist_800_53_controls=["SC-12", "SC-13", "SC-17"],
        ),
        "RSA-15360": AlgorithmInfo(
            name="RSA-15360", category="signature", fips_status=FIPSStatus.APPROVED,
            security_bits=256, min_key_length=15360, fips_standard="FIPS 186-5",
            notes="Maximum RSA strength; extreme performance impact",
            nist_800_53_controls=["SC-12", "SC-13", "SC-17"],
        ),
        "ECDSA-P256": AlgorithmInfo(
            name="ECDSA-P256", category="signature", fips_status=FIPSStatus.APPROVED,
            security_bits=128, min_key_length=256, fips_standard="FIPS 186-5",
            notes="NIST P-256 curve; widely deployed",
            nist_800_53_controls=["SC-12", "SC-13", "SC-17"],
        ),
        "ECDSA-P384": AlgorithmInfo(
            name="ECDSA-P384", category="signature", fips_status=FIPSStatus.APPROVED,
            security_bits=192, min_key_length=384, fips_standard="FIPS 186-5",
            notes="NIST P-384 curve; CNSA 2.0 approved",
            nist_800_53_controls=["SC-12", "SC-13", "SC-17"],
        ),
        "ECDSA-P521": AlgorithmInfo(
            name="ECDSA-P521", category="signature", fips_status=FIPSStatus.APPROVED,
            security_bits=256, min_key_length=521, fips_standard="FIPS 186-5",
            notes="NIST P-521 curve; highest ECDSA strength",
            nist_800_53_controls=["SC-12", "SC-13", "SC-17"],
        ),
        "EdDSA-Ed25519": AlgorithmInfo(
            name="EdDSA-Ed25519", category="signature", fips_status=FIPSStatus.APPROVED,
            security_bits=128, min_key_length=256, fips_standard="FIPS 186-5",
            notes="Edwards curve; high performance",
            nist_800_53_controls=["SC-12", "SC-13", "SC-17"],
        ),
        "EdDSA-Ed448": AlgorithmInfo(
            name="EdDSA-Ed448", category="signature", fips_status=FIPSStatus.APPROVED,
            security_bits=224, min_key_length=448, fips_standard="FIPS 186-5",
            notes="Edwards curve; higher security than Ed25519",
            nist_800_53_controls=["SC-12", "SC-13", "SC-17"],
        ),
        # Post-Quantum (FIPS 203, 204, 205)
        "ML-KEM-512": AlgorithmInfo(
            name="ML-KEM-512", category="kex", fips_status=FIPSStatus.APPROVED,
            security_bits=128, fips_standard="FIPS 203",
            notes="Module-Lattice KEM; NIST Level 1",
            nist_800_53_controls=["SC-12", "SC-13"],
        ),
        "ML-KEM-768": AlgorithmInfo(
            name="ML-KEM-768", category="kex", fips_status=FIPSStatus.APPROVED,
            security_bits=192, fips_standard="FIPS 203",
            notes="Module-Lattice KEM; NIST Level 3",
            nist_800_53_controls=["SC-12", "SC-13"],
        ),
        "ML-KEM-1024": AlgorithmInfo(
            name="ML-KEM-1024", category="kex", fips_status=FIPSStatus.APPROVED,
            security_bits=256, fips_standard="FIPS 203",
            notes="Module-Lattice KEM; NIST Level 5; CNSA 2.0 required",
            nist_800_53_controls=["SC-12", "SC-13"],
        ),
        "ML-DSA-44": AlgorithmInfo(
            name="ML-DSA-44", category="signature", fips_status=FIPSStatus.APPROVED,
            security_bits=128, fips_standard="FIPS 204",
            notes="Module-Lattice Digital Signature; NIST Level 2",
            nist_800_53_controls=["SC-12", "SC-13", "SC-17"],
        ),
        "ML-DSA-65": AlgorithmInfo(
            name="ML-DSA-65", category="signature", fips_status=FIPSStatus.APPROVED,
            security_bits=192, fips_standard="FIPS 204",
            notes="Module-Lattice Digital Signature; NIST Level 3",
            nist_800_53_controls=["SC-12", "SC-13", "SC-17"],
        ),
        "ML-DSA-87": AlgorithmInfo(
            name="ML-DSA-87", category="signature", fips_status=FIPSStatus.APPROVED,
            security_bits=256, fips_standard="FIPS 204",
            notes="Module-Lattice Digital Signature; NIST Level 5; CNSA 2.0 required",
            nist_800_53_controls=["SC-12", "SC-13", "SC-17"],
        ),
        "SLH-DSA-128s": AlgorithmInfo(
            name="SLH-DSA-128s", category="signature", fips_status=FIPSStatus.APPROVED,
            security_bits=128, fips_standard="FIPS 205",
            notes="Stateless Hash-Based Signature; NIST Level 1; small signatures",
            nist_800_53_controls=["SC-12", "SC-13", "SC-17"],
        ),
        "SLH-DSA-128f": AlgorithmInfo(
            name="SLH-DSA-128f", category="signature", fips_status=FIPSStatus.APPROVED,
            security_bits=128, fips_standard="FIPS 205",
            notes="Stateless Hash-Based Signature; NIST Level 1; fast signing",
            nist_800_53_controls=["SC-12", "SC-13", "SC-17"],
        ),
        "SLH-DSA-192s": AlgorithmInfo(
            name="SLH-DSA-192s", category="signature", fips_status=FIPSStatus.APPROVED,
            security_bits=192, fips_standard="FIPS 205",
            notes="Stateless Hash-Based Signature; NIST Level 3; small signatures",
            nist_800_53_controls=["SC-12", "SC-13", "SC-17"],
        ),
        "SLH-DSA-192f": AlgorithmInfo(
            name="SLH-DSA-192f", category="signature", fips_status=FIPSStatus.APPROVED,
            security_bits=192, fips_standard="FIPS 205",
            notes="Stateless Hash-Based Signature; NIST Level 3; fast signing",
            nist_800_53_controls=["SC-12", "SC-13", "SC-17"],
        ),
        "SLH-DSA-256s": AlgorithmInfo(
            name="SLH-DSA-256s", category="signature", fips_status=FIPSStatus.APPROVED,
            security_bits=256, fips_standard="FIPS 205",
            notes="Stateless Hash-Based Signature; NIST Level 5; small signatures; CNSA 2.0",
            nist_800_53_controls=["SC-12", "SC-13", "SC-17"],
        ),
        "SLH-DSA-256f": AlgorithmInfo(
            name="SLH-DSA-256f", category="signature", fips_status=FIPSStatus.APPROVED,
            security_bits=256, fips_standard="FIPS 205",
            notes="Stateless Hash-Based Signature; NIST Level 5; fast signing; CNSA 2.0",
            nist_800_53_controls=["SC-12", "SC-13", "SC-17"],
        ),
        # DRBGs (SP 800-90A Rev 1)
        "CTR_DRBG": AlgorithmInfo(
            name="CTR_DRBG", category="drbg", fips_status=FIPSStatus.APPROVED,
            security_bits=256, fips_standard="SP 800-90A Rev 1",
            notes="Counter-mode DRBG; uses AES internally",
            nist_800_53_controls=["SC-13"],
        ),
        "Hash_DRBG": AlgorithmInfo(
            name="Hash_DRBG", category="drbg", fips_status=FIPSStatus.APPROVED,
            security_bits=256, fips_standard="SP 800-90A Rev 1",
            notes="Hash-based DRBG; uses SHA-2/SHA-3",
            nist_800_53_controls=["SC-13"],
        ),
        "HMAC_DRBG": AlgorithmInfo(
            name="HMAC_DRBG", category="drbg", fips_status=FIPSStatus.APPROVED,
            security_bits=256, fips_standard="SP 800-90A Rev 1",
            notes="HMAC-based DRBG; uses HMAC-SHA-2",
            nist_800_53_controls=["SC-13"],
        ),
        # KDFs
        "SP800-108-KDF": AlgorithmInfo(
            name="SP800-108-KDF", category="kdf", fips_status=FIPSStatus.APPROVED,
            security_bits=256, fips_standard="SP 800-108 Rev 1",
            notes="KDF in Counter/Feedback/Pipeline mode",
            nist_800_53_controls=["SC-12", "SC-13"],
        ),
        "SP800-56C-KDF": AlgorithmInfo(
            name="SP800-56C-KDF", category="kdf", fips_status=FIPSStatus.APPROVED,
            security_bits=256, fips_standard="SP 800-56C Rev 2",
            notes="Two-step key derivation (extract-then-expand)",
            nist_800_53_controls=["SC-12", "SC-13"],
        ),
        "HKDF": AlgorithmInfo(
            name="HKDF", category="kdf", fips_status=FIPSStatus.APPROVED,
            security_bits=256, fips_standard="SP 800-56C Rev 2",
            notes="HMAC-based KDF (RFC 5869); approved under SP 800-56C",
            nist_800_53_controls=["SC-12", "SC-13"],
        ),
        "PBKDF2": AlgorithmInfo(
            name="PBKDF2", category="kdf", fips_status=FIPSStatus.APPROVED,
            security_bits=128, fips_standard="SP 800-132",
            notes="Password-Based KDF; use with high iteration count",
            nist_800_53_controls=["SC-12", "SC-13"],
        ),
        # Key Wrapping (SP 800-38F)
        "AES-KW": AlgorithmInfo(
            name="AES-KW", category="key_wrap", fips_status=FIPSStatus.APPROVED,
            security_bits=128, min_key_length=128, fips_standard="SP 800-38F",
            notes="AES Key Wrap (RFC 3394)",
            nist_800_53_controls=["SC-12", "SC-13"],
        ),
        "AES-KWP": AlgorithmInfo(
            name="AES-KWP", category="key_wrap", fips_status=FIPSStatus.APPROVED,
            security_bits=128, min_key_length=128, fips_standard="SP 800-38F",
            notes="AES Key Wrap with Padding (RFC 5649)",
            nist_800_53_controls=["SC-12", "SC-13"],
        ),
        # Authenticated Encryption
        "AES-GCM": AlgorithmInfo(
            name="AES-GCM", category="symmetric", fips_status=FIPSStatus.APPROVED,
            security_bits=128, min_key_length=128, fips_standard="SP 800-38D",
            notes="Galois/Counter Mode; provides confidentiality + authentication",
            nist_800_53_controls=["SC-13", "SC-28"],
        ),
        "AES-CCM": AlgorithmInfo(
            name="AES-CCM", category="symmetric", fips_status=FIPSStatus.APPROVED,
            security_bits=128, min_key_length=128, fips_standard="SP 800-38C",
            notes="Counter with CBC-MAC; provides confidentiality + authentication",
            nist_800_53_controls=["SC-13", "SC-28"],
        ),
        # Key Exchange
        "ECDH-P256": AlgorithmInfo(
            name="ECDH-P256", category="kex", fips_status=FIPSStatus.APPROVED,
            security_bits=128, min_key_length=256, fips_standard="SP 800-56A Rev 3",
            notes="Elliptic Curve Diffie-Hellman on P-256",
            nist_800_53_controls=["SC-12", "SC-13"],
        ),
        "ECDH-P384": AlgorithmInfo(
            name="ECDH-P384", category="kex", fips_status=FIPSStatus.APPROVED,
            security_bits=192, min_key_length=384, fips_standard="SP 800-56A Rev 3",
            notes="Elliptic Curve Diffie-Hellman on P-384; CNSA 2.0 approved",
            nist_800_53_controls=["SC-12", "SC-13"],
        ),
        "ECDH-P521": AlgorithmInfo(
            name="ECDH-P521", category="kex", fips_status=FIPSStatus.APPROVED,
            security_bits=256, min_key_length=521, fips_standard="SP 800-56A Rev 3",
            notes="Elliptic Curve Diffie-Hellman on P-521",
            nist_800_53_controls=["SC-12", "SC-13"],
        ),
        "DH-2048": AlgorithmInfo(
            name="DH-2048", category="kex", fips_status=FIPSStatus.APPROVED,
            security_bits=112, min_key_length=2048, fips_standard="SP 800-56A Rev 3",
            deprecation_date="2030-12-31",
            notes="Finite-field DH; transitioning away",
            nist_800_53_controls=["SC-12", "SC-13"],
        ),
    }

    NON_FIPS_ALGORITHMS: dict[str, AlgorithmInfo] = {
        "MD5": AlgorithmInfo(
            name="MD5", category="hash", fips_status=FIPSStatus.DISALLOWED,
            security_bits=0, fips_standard="RFC 1321",
            notes="Collision attacks demonstrated; NEVER use for security",
            nist_800_53_controls=["SC-13"],
        ),
        "MD4": AlgorithmInfo(
            name="MD4", category="hash", fips_status=FIPSStatus.DISALLOWED,
            security_bits=0, fips_standard="RFC 1320",
            notes="Severely broken; trivial collision attacks",
            nist_800_53_controls=["SC-13"],
        ),
        "SHA-1": AlgorithmInfo(
            name="SHA-1", category="hash", fips_status=FIPSStatus.DISALLOWED,
            security_bits=0, fips_standard="FIPS 180-4",
            deprecation_date="2013-12-31",
            notes="Collision attacks practical (SHAttered, 2017); disallowed for digital signatures",
            nist_800_53_controls=["SC-13"],
        ),
        "DES": AlgorithmInfo(
            name="DES", category="symmetric", fips_status=FIPSStatus.DISALLOWED,
            security_bits=56, min_key_length=56, max_key_length=56,
            fips_standard="FIPS 46-3 (withdrawn)",
            deprecation_date="2005-05-19",
            notes="56-bit key; brute-forceable since 1998; withdrawn from FIPS",
            nist_800_53_controls=["SC-13"],
        ),
        "3DES": AlgorithmInfo(
            name="3DES", category="symmetric", fips_status=FIPSStatus.DEPRECATED,
            security_bits=112, min_key_length=168, max_key_length=168,
            fips_standard="SP 800-67 Rev 2",
            deprecation_date="2023-12-31",
            notes="Deprecated due to 64-bit block size (Sweet32 attack); disallowed after 2023",
            nist_800_53_controls=["SC-13"],
        ),
        "TDEA": AlgorithmInfo(
            name="TDEA", category="symmetric", fips_status=FIPSStatus.DEPRECATED,
            security_bits=112, min_key_length=168, max_key_length=168,
            fips_standard="SP 800-67 Rev 2",
            deprecation_date="2023-12-31",
            notes="Same as 3DES; deprecated",
            nist_800_53_controls=["SC-13"],
        ),
        "RC4": AlgorithmInfo(
            name="RC4", category="symmetric", fips_status=FIPSStatus.DISALLOWED,
            security_bits=0,
            notes="Statistical biases exploitable; banned in TLS (RFC 7465)",
            nist_800_53_controls=["SC-13"],
        ),
        "RC2": AlgorithmInfo(
            name="RC2", category="symmetric", fips_status=FIPSStatus.DISALLOWED,
            security_bits=0,
            notes="Vulnerable to related-key attacks; never FIPS approved",
            nist_800_53_controls=["SC-13"],
        ),
        "Blowfish": AlgorithmInfo(
            name="Blowfish", category="symmetric", fips_status=FIPSStatus.NOT_RECOGNIZED,
            security_bits=0, min_key_length=32, max_key_length=448,
            notes="64-bit block size; never FIPS approved; use AES instead",
            nist_800_53_controls=["SC-13"],
        ),
        "Twofish": AlgorithmInfo(
            name="Twofish", category="symmetric", fips_status=FIPSStatus.NOT_RECOGNIZED,
            security_bits=128, min_key_length=128, max_key_length=256,
            notes="AES finalist; not FIPS approved; use AES",
            nist_800_53_controls=["SC-13"],
        ),
        "CAST5": AlgorithmInfo(
            name="CAST5", category="symmetric", fips_status=FIPSStatus.NOT_RECOGNIZED,
            security_bits=0, min_key_length=40, max_key_length=128,
            notes="64-bit block size; not FIPS approved",
            nist_800_53_controls=["SC-13"],
        ),
        "IDEA": AlgorithmInfo(
            name="IDEA", category="symmetric", fips_status=FIPSStatus.NOT_RECOGNIZED,
            security_bits=0, min_key_length=128, max_key_length=128,
            notes="64-bit block size; patent expired; not FIPS approved",
            nist_800_53_controls=["SC-13"],
        ),
        "RSA-1024": AlgorithmInfo(
            name="RSA-1024", category="signature", fips_status=FIPSStatus.DISALLOWED,
            security_bits=80, min_key_length=1024,
            deprecation_date="2013-12-31",
            notes="80-bit security; factorable; disallowed since 2014",
            nist_800_53_controls=["SC-12", "SC-13"],
        ),
        "RSA-512": AlgorithmInfo(
            name="RSA-512", category="signature", fips_status=FIPSStatus.DISALLOWED,
            security_bits=56, min_key_length=512,
            notes="Trivially factorable; completely insecure",
            nist_800_53_controls=["SC-12", "SC-13"],
        ),
        "DSA-1024": AlgorithmInfo(
            name="DSA-1024", category="signature", fips_status=FIPSStatus.DISALLOWED,
            security_bits=80, min_key_length=1024,
            deprecation_date="2013-12-31",
            notes="Disallowed; use ECDSA instead",
            nist_800_53_controls=["SC-12", "SC-13"],
        ),
        "HMAC-SHA-1": AlgorithmInfo(
            name="HMAC-SHA-1", category="mac", fips_status=FIPSStatus.LEGACY_USE_ONLY,
            security_bits=80, fips_standard="FIPS 198-1",
            notes="Legacy use only for HMAC; do not use for new systems",
            nist_800_53_controls=["SC-13"],
        ),
        "HMAC-MD5": AlgorithmInfo(
            name="HMAC-MD5", category="mac", fips_status=FIPSStatus.DISALLOWED,
            security_bits=0,
            notes="MD5-based; disallowed",
            nist_800_53_controls=["SC-13"],
        ),
        "Dual_EC_DRBG": AlgorithmInfo(
            name="Dual_EC_DRBG", category="drbg", fips_status=FIPSStatus.DISALLOWED,
            security_bits=0,
            notes="Backdoored (NSA); withdrawn from SP 800-90A",
            nist_800_53_controls=["SC-13"],
        ),
    }

    # Regex patterns to detect algorithms in code/config
    DETECTION_PATTERNS: dict[str, list[str]] = {
        "MD5": [
            r"\bmd5\b", r"\bMD5\b", r"hashlib\.md5", r"MD5Digest",
            r"MessageDigest\.getInstance\s*\(\s*[\"']MD5[\"']\s*\)",
            r"EVP_md5", r"CALG_MD5",
        ],
        "MD4": [r"\bmd4\b", r"\bMD4\b", r"EVP_md4"],
        "SHA-1": [
            r"\bsha[-_]?1\b", r"\bSHA[-_]?1\b", r"hashlib\.sha1",
            r"MessageDigest\.getInstance\s*\(\s*[\"']SHA-?1[\"']\s*\)",
            r"EVP_sha1", r"CALG_SHA1",
        ],
        "DES": [
            r"\bDES\b(?!C|A)", r"Cipher\.getInstance.*DES(?!ede)",
            r"EVP_des_", r"CALG_DES\b", r"DES_ecb_encrypt",
        ],
        "3DES": [
            r"\b3DES\b", r"\bTripleDES\b", r"\bDESede\b", r"\bTDEA\b",
            r"EVP_des_ede3", r"CALG_3DES",
        ],
        "RC4": [
            r"\bRC4\b", r"\bARCFOUR\b", r"\barc4\b",
            r"EVP_rc4", r"CALG_RC4",
        ],
        "RC2": [r"\bRC2\b", r"EVP_rc2", r"CALG_RC2"],
        "Blowfish": [
            r"\bBlowfish\b", r"\bBF_", r"EVP_bf_",
            r"Cipher\.getInstance.*Blowfish",
        ],
        "AES-128": [
            r"AES[-_]?128", r"aes[-_]?128",
            r"CALG_AES_128",
        ],
        "AES-192": [r"AES[-_]?192", r"aes[-_]?192"],
        "AES-256": [
            r"AES[-_]?256", r"aes[-_]?256",
            r"CALG_AES_256",
        ],
        "AES-GCM": [
            r"AES[/-]GCM", r"aes[/-]gcm", r"GCM",
            r"Cipher\.getInstance.*AES/GCM",
        ],
        "AES-CCM": [r"AES[/-]CCM", r"aes[/-]ccm"],
        "SHA-256": [
            r"\bsha[-_]?256\b", r"\bSHA[-_]?256\b", r"hashlib\.sha256",
            r"EVP_sha256",
        ],
        "SHA-384": [r"\bsha[-_]?384\b", r"\bSHA[-_]?384\b", r"hashlib\.sha384"],
        "SHA-512": [r"\bsha[-_]?512\b", r"\bSHA[-_]?512\b", r"hashlib\.sha512"],
        "SHA3-256": [r"\bsha3[-_]?256\b", r"\bSHA3[-_]?256\b"],
        "SHA3-384": [r"\bsha3[-_]?384\b", r"\bSHA3[-_]?384\b"],
        "SHA3-512": [r"\bsha3[-_]?512\b", r"\bSHA3[-_]?512\b"],
        "RSA-1024": [r"RSA.*1024", r"rsa.*1024", r"key.?size.*1024"],
        "RSA-2048": [r"RSA.*2048", r"rsa.*2048", r"key.?size.*2048"],
        "RSA-3072": [r"RSA.*3072", r"rsa.*3072"],
        "RSA-4096": [r"RSA.*4096", r"rsa.*4096", r"key.?size.*4096"],
        "ECDSA-P256": [
            r"ECDSA.*P-?256", r"ecdsa.*p-?256", r"secp256r1",
            r"prime256v1", r"NIST.*P-?256",
        ],
        "ECDSA-P384": [
            r"ECDSA.*P-?384", r"ecdsa.*p-?384", r"secp384r1",
            r"NIST.*P-?384",
        ],
        "ECDSA-P521": [
            r"ECDSA.*P-?521", r"ecdsa.*p-?521", r"secp521r1",
            r"NIST.*P-?521",
        ],
        "EdDSA-Ed25519": [r"Ed25519", r"ed25519", r"ED25519"],
        "EdDSA-Ed448": [r"Ed448", r"ed448"],
        "HMAC-SHA-256": [r"HMAC.*SHA[-_]?256", r"hmac.*sha[-_]?256"],
        "HMAC-SHA-384": [r"HMAC.*SHA[-_]?384", r"hmac.*sha[-_]?384"],
        "HMAC-SHA-512": [r"HMAC.*SHA[-_]?512", r"hmac.*sha[-_]?512"],
        "HMAC-SHA-1": [r"HMAC.*SHA[-_]?1\b", r"hmac.*sha[-_]?1\b"],
        "HMAC-MD5": [r"HMAC.*MD5", r"hmac.*md5"],
        "ML-KEM-512": [r"ML[-_]KEM[-_]512", r"Kyber[-_]?512"],
        "ML-KEM-768": [r"ML[-_]KEM[-_]768", r"Kyber[-_]?768"],
        "ML-KEM-1024": [r"ML[-_]KEM[-_]1024", r"Kyber[-_]?1024"],
        "ML-DSA-44": [r"ML[-_]DSA[-_]44", r"Dilithium[-_]?2"],
        "ML-DSA-65": [r"ML[-_]DSA[-_]65", r"Dilithium[-_]?3"],
        "ML-DSA-87": [r"ML[-_]DSA[-_]87", r"Dilithium[-_]?5"],
        "PBKDF2": [r"\bPBKDF2\b", r"\bpbkdf2\b", r"PBKDF2WithHmac"],
        "HKDF": [r"\bHKDF\b", r"\bhkdf\b"],
        "CTR_DRBG": [r"CTR[-_]?DRBG", r"ctr[-_]?drbg"],
        "Hash_DRBG": [r"Hash[-_]?DRBG", r"hash[-_]?drbg"],
        "HMAC_DRBG": [r"HMAC[-_]?DRBG", r"hmac[-_]?drbg"],
        "Dual_EC_DRBG": [r"Dual[-_]?EC[-_]?DRBG", r"dual[-_]?ec[-_]?drbg"],
    }

    # Minimum security strength thresholds per SP 800-131A Rev 2
    MIN_SECURITY_BITS_2024: int = 112
    MIN_SECURITY_BITS_2031: int = 128

    def __init__(self) -> None:
        self._all_algorithms = {**self.APPROVED_ALGORITHMS, **self.NON_FIPS_ALGORITHMS}

    def validate_algorithm(self, algorithm_name: str, key_length_bits: int = 0) -> ValidationResult:
        """
        Validate a single algorithm against FIPS 140-3 requirements.

        Args:
            algorithm_name: Name of the algorithm to validate (e.g., "AES-256", "MD5").
            key_length_bits: Key length in bits, if applicable.

        Returns:
            ValidationResult with pass/fail status and remediation guidance.
        """
        normalized = self._normalize_algorithm_name(algorithm_name)
        info = self._all_algorithms.get(normalized)

        if info is None:
            return ValidationResult(
                algorithm=algorithm_name,
                status="warning",
                fips_status=FIPSStatus.NOT_RECOGNIZED,
                security_bits=0,
                message=f"Algorithm '{algorithm_name}' is not recognized in the FIPS algorithm database. "
                        "This may indicate a proprietary or non-standard algorithm.",
                remediation="Verify the algorithm name. Use only FIPS-approved algorithms for federal systems.",
                control_mappings=["SC-13"],
            )

        if info.fips_status == FIPSStatus.DISALLOWED:
            return ValidationResult(
                algorithm=info.name,
                status="fail",
                fips_status=FIPSStatus.DISALLOWED,
                security_bits=info.security_bits,
                message=f"{info.name} is DISALLOWED under FIPS 140-3. {info.notes}",
                remediation=self._get_remediation(info),
                control_mappings=info.nist_800_53_controls,
                deprecation_info=f"Deprecated since {info.deprecation_date}" if info.deprecation_date else "Never approved or withdrawn",
            )

        if info.fips_status == FIPSStatus.DEPRECATED:
            return ValidationResult(
                algorithm=info.name,
                status="fail",
                fips_status=FIPSStatus.DEPRECATED,
                security_bits=info.security_bits,
                message=f"{info.name} is DEPRECATED. {info.notes}",
                remediation=self._get_remediation(info),
                control_mappings=info.nist_800_53_controls,
                deprecation_info=f"Deprecated since {info.deprecation_date}" if info.deprecation_date else "",
            )

        if info.fips_status == FIPSStatus.NOT_RECOGNIZED:
            return ValidationResult(
                algorithm=info.name,
                status="fail",
                fips_status=FIPSStatus.NOT_RECOGNIZED,
                security_bits=info.security_bits,
                message=f"{info.name} is NOT a FIPS-recognized algorithm. {info.notes}",
                remediation=self._get_remediation(info),
                control_mappings=info.nist_800_53_controls,
            )

        if info.fips_status == FIPSStatus.LEGACY_USE_ONLY:
            return ValidationResult(
                algorithm=info.name,
                status="warning",
                fips_status=FIPSStatus.LEGACY_USE_ONLY,
                security_bits=info.security_bits,
                message=f"{info.name} is approved for LEGACY USE ONLY. {info.notes}",
                remediation=self._get_remediation(info),
                control_mappings=info.nist_800_53_controls,
            )

        # Check key length if provided and applicable
        if key_length_bits > 0 and info.min_key_length is not None:
            if key_length_bits < info.min_key_length:
                return ValidationResult(
                    algorithm=info.name,
                    status="fail",
                    fips_status=info.fips_status,
                    security_bits=info.security_bits,
                    message=f"{info.name} requires minimum key length of {info.min_key_length} bits, "
                            f"but {key_length_bits} bits provided.",
                    remediation=f"Increase key length to at least {info.min_key_length} bits.",
                    control_mappings=info.nist_800_53_controls,
                )

        # Check security strength thresholds
        if info.security_bits < self.MIN_SECURITY_BITS_2024:
            return ValidationResult(
                algorithm=info.name,
                status="warning",
                fips_status=info.fips_status,
                security_bits=info.security_bits,
                message=f"{info.name} provides only {info.security_bits}-bit security. "
                        f"Minimum {self.MIN_SECURITY_BITS_2024}-bit security required per SP 800-131A Rev 2.",
                remediation=self._get_strength_upgrade(info),
                control_mappings=info.nist_800_53_controls,
            )

        # Check deprecation timeline
        deprecation_info = ""
        if info.deprecation_date:
            deprecation_info = f"Scheduled for deprecation: {info.deprecation_date}"

        return ValidationResult(
            algorithm=info.name,
            status="pass",
            fips_status=FIPSStatus.APPROVED,
            security_bits=info.security_bits,
            message=f"{info.name} is FIPS 140-3 APPROVED ({info.fips_standard}). "
                    f"Security strength: {info.security_bits} bits. {info.notes}",
            control_mappings=info.nist_800_53_controls,
            deprecation_info=deprecation_info,
        )

    def validate_multiple(self, algorithms: list[str]) -> dict:
        """
        Validate a list of algorithms and produce a summary report.

        Args:
            algorithms: List of algorithm names to validate.

        Returns:
            Dictionary with individual results and overall compliance status.
        """
        results = []
        passed = 0
        failed = 0
        warnings = 0

        for algo in algorithms:
            result = self.validate_algorithm(algo)
            results.append({
                "algorithm": result.algorithm,
                "status": result.status,
                "fips_status": result.fips_status.value,
                "security_bits": result.security_bits,
                "message": result.message,
                "remediation": result.remediation,
                "control_mappings": result.control_mappings,
                "deprecation_info": result.deprecation_info,
            })
            if result.status == "pass":
                passed += 1
            elif result.status == "fail":
                failed += 1
            else:
                warnings += 1

        overall = "COMPLIANT" if failed == 0 and warnings == 0 else (
            "NON-COMPLIANT" if failed > 0 else "COMPLIANT_WITH_WARNINGS"
        )

        return {
            "report_type": "FIPS 140-3 Compliance Report",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "standard": "FIPS 140-3 / NIST SP 800-131A Rev 2",
            "overall_status": overall,
            "summary": {
                "total_algorithms": len(algorithms),
                "passed": passed,
                "failed": failed,
                "warnings": warnings,
            },
            "results": results,
            "references": [
                "FIPS 140-3: Security Requirements for Cryptographic Modules",
                "NIST SP 800-131A Rev 2: Transitioning the Use of Cryptographic Algorithms",
                "NIST SP 800-57 Part 1 Rev 5: Recommendation for Key Management",
                "NIST SP 800-53 Rev 5: Security and Privacy Controls",
            ],
        }

    def scan_text_for_algorithms(self, text: str) -> dict:
        """
        Scan text/code for cryptographic algorithm usage and validate each.

        Args:
            text: Source code, configuration, or documentation text to scan.

        Returns:
            Dictionary with detected algorithms, their FIPS status, and findings.
        """
        detected: dict[str, list[dict]] = {}

        lines = text.split("\n")
        for line_num, line in enumerate(lines, start=1):
            for algo_name, patterns in self.DETECTION_PATTERNS.items():
                for pattern in patterns:
                    matches = list(re.finditer(pattern, line, re.IGNORECASE))
                    if matches:
                        if algo_name not in detected:
                            detected[algo_name] = []
                        for match in matches:
                            detected[algo_name].append({
                                "line": line_num,
                                "column": match.start() + 1,
                                "match": match.group(),
                                "context": line.strip()[:120],
                            })

        # Validate each detected algorithm
        findings = []
        for algo_name, locations in detected.items():
            result = self.validate_algorithm(algo_name)
            findings.append({
                "algorithm": algo_name,
                "occurrences": len(locations),
                "locations": locations[:10],  # Limit to first 10
                "fips_status": result.fips_status.value,
                "status": result.status,
                "security_bits": result.security_bits,
                "message": result.message,
                "remediation": result.remediation,
            })

        # Sort: failures first, then warnings, then passes
        status_order = {"fail": 0, "warning": 1, "pass": 2}
        findings.sort(key=lambda f: status_order.get(f["status"], 3))

        non_compliant = [f for f in findings if f["status"] == "fail"]
        compliant = [f for f in findings if f["status"] == "pass"]
        legacy = [f for f in findings if f["status"] == "warning"]

        return {
            "report_type": "FIPS 140-3 Code Scan Report",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "total_algorithms_detected": len(detected),
            "summary": {
                "compliant": len(compliant),
                "non_compliant": len(non_compliant),
                "legacy_warnings": len(legacy),
            },
            "overall_status": "NON-COMPLIANT" if non_compliant else (
                "COMPLIANT_WITH_WARNINGS" if legacy else "COMPLIANT"
            ),
            "findings": findings,
        }

    def get_approved_algorithms_by_category(self) -> dict:
        """
        Return all FIPS-approved algorithms organized by category.

        Returns:
            Dictionary mapping categories to lists of approved algorithm details.
        """
        categories: dict[str, list[dict]] = {}
        for algo in self.APPROVED_ALGORITHMS.values():
            cat = algo.category
            if cat not in categories:
                categories[cat] = []
            categories[cat].append({
                "name": algo.name,
                "security_bits": algo.security_bits,
                "fips_standard": algo.fips_standard,
                "min_key_length": algo.min_key_length,
                "notes": algo.notes,
                "deprecation_date": algo.deprecation_date,
            })
        return {
            "report_type": "FIPS 140-3 Approved Algorithm Catalog",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "categories": categories,
            "total_approved": len(self.APPROVED_ALGORITHMS),
        }

    def assess_security_strength(self, algorithm_name: str, key_length_bits: int = 0) -> dict:
        """
        Assess security strength of an algorithm per SP 800-57 Part 1.

        Args:
            algorithm_name: Algorithm to assess.
            key_length_bits: Key length in bits.

        Returns:
            Security strength assessment with recommendations.
        """
        normalized = self._normalize_algorithm_name(algorithm_name)
        info = self._all_algorithms.get(normalized)

        if info is None:
            return {
                "algorithm": algorithm_name,
                "status": "unknown",
                "message": f"Algorithm '{algorithm_name}' not found in database",
            }

        bits = info.security_bits

        # Determine strength level
        if bits >= 256:
            level = "MAXIMUM"
            description = "Provides 256-bit security; resistant to known quantum attacks for symmetric"
        elif bits >= 192:
            level = "HIGH"
            description = "Provides 192-bit security; exceeds most current requirements"
        elif bits >= 128:
            level = "STANDARD"
            description = "Provides 128-bit security; meets current minimum for most applications"
        elif bits >= 112:
            level = "ACCEPTABLE"
            description = "Provides 112-bit security; meets current minimum but upgrade recommended"
        elif bits >= 80:
            level = "LEGACY"
            description = "Provides only 80-bit security; below current minimums"
        else:
            level = "BROKEN"
            description = "Insufficient security; algorithm is broken or provides negligible protection"

        # Equivalent strengths across algorithm types
        equivalents = {
            80: {"symmetric": 80, "rsa_dh": 1024, "ecc": 160, "hash": 160},
            112: {"symmetric": 112, "rsa_dh": 2048, "ecc": 224, "hash": 224},
            128: {"symmetric": 128, "rsa_dh": 3072, "ecc": 256, "hash": 256},
            192: {"symmetric": 192, "rsa_dh": 7680, "ecc": 384, "hash": 384},
            256: {"symmetric": 256, "rsa_dh": 15360, "ecc": 521, "hash": 512},
        }

        closest_level = min(equivalents.keys(), key=lambda k: abs(k - bits))

        return {
            "algorithm": info.name,
            "category": info.category,
            "security_bits": bits,
            "strength_level": level,
            "description": description,
            "fips_standard": info.fips_standard,
            "meets_2024_minimum": bits >= self.MIN_SECURITY_BITS_2024,
            "meets_2031_minimum": bits >= self.MIN_SECURITY_BITS_2031,
            "equivalent_strengths": equivalents.get(closest_level, {}),
            "quantum_impact": self._quantum_impact(info),
            "recommendation": self._get_strength_upgrade(info) if bits < 128 else "Strength is adequate",
        }

    def get_deprecation_timeline(self) -> dict:
        """
        Get the full algorithm deprecation timeline per SP 800-131A Rev 2.

        Returns:
            Timeline of algorithm deprecations with dates and replacements.
        """
        timeline = []

        deprecated_entries = [
            {
                "date": "2005-05-19",
                "algorithm": "DES",
                "action": "Withdrawn from FIPS",
                "replacement": "AES (FIPS 197)",
            },
            {
                "date": "2013-12-31",
                "algorithm": "RSA-1024, DSA-1024, SHA-1 (signatures)",
                "action": "Disallowed for digital signatures",
                "replacement": "RSA-2048+, ECDSA-P256+, SHA-256+",
            },
            {
                "date": "2023-12-31",
                "algorithm": "3DES / TDEA",
                "action": "Disallowed for encryption",
                "replacement": "AES-128/192/256",
            },
            {
                "date": "2025-12-31",
                "algorithm": "Software/firmware signing (classical only)",
                "action": "Must begin PQC transition (CNSA 2.0)",
                "replacement": "ML-DSA-87, SLH-DSA-256",
            },
            {
                "date": "2026-12-31",
                "algorithm": "Network equipment (classical only)",
                "action": "Must support PQC (CNSA 2.0)",
                "replacement": "ML-KEM-1024 + ML-DSA-87",
            },
            {
                "date": "2030-12-31",
                "algorithm": "RSA-2048, DH-2048",
                "action": "Disallowed (SP 800-131A Rev 2)",
                "replacement": "RSA-3072+, ECDH-P384+, ML-KEM",
            },
            {
                "date": "2033-12-31",
                "algorithm": "All classical-only NSS systems",
                "action": "Must complete PQC migration (CNSA 2.0)",
                "replacement": "ML-KEM-1024, ML-DSA-87, AES-256, SHA-384",
            },
        ]

        current_year = int(time.strftime("%Y"))
        for entry in deprecated_entries:
            dep_year = int(entry["date"][:4])
            if dep_year <= current_year:
                entry["urgency"] = "OVERDUE" if dep_year < current_year else "DUE_NOW"
            elif dep_year <= current_year + 2:
                entry["urgency"] = "IMMINENT"
            else:
                entry["urgency"] = "PLANNED"
            timeline.append(entry)

        return {
            "report_type": "Algorithm Deprecation Timeline",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "reference": "NIST SP 800-131A Rev 2, CNSA 2.0",
            "timeline": timeline,
        }

    def generate_compliance_report(
        self, algorithms: list[str], include_scan: bool = False, scan_text: str = ""
    ) -> dict:
        """
        Generate a comprehensive FIPS 140-3 compliance report.

        Args:
            algorithms: List of algorithm names to validate.
            include_scan: Whether to include a code scan.
            scan_text: Text to scan if include_scan is True.

        Returns:
            Full compliance report with all assessments.
        """
        report = {
            "report_type": "Comprehensive FIPS 140-3 Compliance Report",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "standards_checked": [
                "FIPS 140-3",
                "NIST SP 800-131A Rev 2",
                "NIST SP 800-57 Part 1 Rev 5",
            ],
            "nist_800_53_controls": {
                "SC-12": "Cryptographic Key Establishment and Management",
                "SC-13": "Cryptographic Protection",
                "SC-17": "Public Key Infrastructure Certificates",
                "SC-28": "Protection of Information at Rest",
            },
        }

        # Algorithm validation
        validation = self.validate_multiple(algorithms)
        report["algorithm_validation"] = validation

        # Security strength assessments
        strengths = []
        for algo in algorithms:
            strengths.append(self.assess_security_strength(algo))
        report["security_strength_assessments"] = strengths

        # Deprecation timeline
        report["deprecation_timeline"] = self.get_deprecation_timeline()

        # Code scan
        if include_scan and scan_text:
            report["code_scan"] = self.scan_text_for_algorithms(scan_text)

        # Overall compliance determination
        overall = validation["overall_status"]
        report["overall_compliance"] = overall
        report["executive_summary"] = self._generate_executive_summary(validation, strengths)

        return report

    def _normalize_algorithm_name(self, name: str) -> str:
        """Normalize algorithm name for lookup."""
        # Direct lookup first
        if name in self._all_algorithms:
            return name

        # Case-insensitive search
        name_upper = name.upper().replace(" ", "-").replace("_", "-")
        for key in self._all_algorithms:
            if key.upper().replace("_", "-") == name_upper:
                return key

        # Common aliases
        aliases = {
            "AES": "AES-128",
            "SHA2-256": "SHA-256",
            "SHA2-384": "SHA-384",
            "SHA2-512": "SHA-512",
            "SHA256": "SHA-256",
            "SHA384": "SHA-384",
            "SHA512": "SHA-512",
            "SHA1": "SHA-1",
            "TRIPLEDES": "3DES",
            "TRIPLE-DES": "3DES",
            "DESEDE": "3DES",
            "P256": "ECDSA-P256",
            "P384": "ECDSA-P384",
            "P521": "ECDSA-P521",
            "P-256": "ECDSA-P256",
            "P-384": "ECDSA-P384",
            "P-521": "ECDSA-P521",
            "CURVE25519": "EdDSA-Ed25519",
            "ED25519": "EdDSA-Ed25519",
            "ED448": "EdDSA-Ed448",
            "KYBER512": "ML-KEM-512",
            "KYBER768": "ML-KEM-768",
            "KYBER1024": "ML-KEM-1024",
            "DILITHIUM2": "ML-DSA-44",
            "DILITHIUM3": "ML-DSA-65",
            "DILITHIUM5": "ML-DSA-87",
            "CRYSTALS-KYBER": "ML-KEM-1024",
            "CRYSTALS-DILITHIUM": "ML-DSA-87",
        }

        return aliases.get(name_upper, name)

    def _get_remediation(self, info: AlgorithmInfo) -> str:
        """Get remediation advice for a non-compliant algorithm."""
        remediations = {
            "MD5": "Replace with SHA-256 or SHA-3. MD5 is cryptographically broken.",
            "MD4": "Replace with SHA-256 or SHA-3. MD4 is severely broken.",
            "SHA-1": "Replace with SHA-256 (minimum) or SHA-384/SHA-512. SHA-1 has practical collision attacks.",
            "DES": "Replace with AES-128 (minimum) or AES-256. DES has a 56-bit key, brute-forceable.",
            "3DES": "Replace with AES-128 (minimum) or AES-256. 3DES has a 64-bit block size vulnerability.",
            "TDEA": "Replace with AES-128 (minimum) or AES-256. TDEA/3DES is deprecated.",
            "RC4": "Replace with AES-GCM or ChaCha20-Poly1305. RC4 has severe statistical biases.",
            "RC2": "Replace with AES. RC2 is not FIPS approved.",
            "Blowfish": "Replace with AES. Blowfish has a 64-bit block size and is not FIPS approved.",
            "Twofish": "Replace with AES. Twofish is not FIPS approved.",
            "CAST5": "Replace with AES. CAST5 has a 64-bit block size.",
            "IDEA": "Replace with AES. IDEA has a 64-bit block size.",
            "RSA-1024": "Increase to RSA-3072 (minimum) or migrate to ECDSA-P384.",
            "RSA-512": "Immediately replace. RSA-512 is trivially factorable. Use RSA-3072+ or ECDSA-P384.",
            "DSA-1024": "Replace with ECDSA-P256+ or EdDSA.",
            "HMAC-SHA-1": "Upgrade to HMAC-SHA-256 or HMAC-SHA-384.",
            "HMAC-MD5": "Replace with HMAC-SHA-256 or HMAC-SHA-384.",
            "Dual_EC_DRBG": "Immediately replace with CTR_DRBG, Hash_DRBG, or HMAC_DRBG.",
        }
        return remediations.get(info.name, f"Replace {info.name} with a FIPS-approved algorithm.")

    def _get_strength_upgrade(self, info: AlgorithmInfo) -> str:
        """Get upgrade recommendation for weak security strength."""
        upgrades = {
            "symmetric": "Use AES-128 (128-bit) or AES-256 (256-bit)",
            "hash": "Use SHA-256 (128-bit) or SHA-384 (192-bit)",
            "mac": "Use HMAC-SHA-256 or HMAC-SHA-384",
            "signature": "Use ECDSA-P256 (128-bit) or ECDSA-P384 (192-bit)",
            "kex": "Use ECDH-P256 (128-bit) or ECDH-P384 (192-bit)",
        }
        return upgrades.get(info.category, "Upgrade to an algorithm with at least 128-bit security")

    def _quantum_impact(self, info: AlgorithmInfo) -> str:
        """Assess quantum computing impact on algorithm security."""
        if info.category in ("symmetric", "hash", "mac", "kdf", "drbg", "key_wrap"):
            return (
                f"Grover's algorithm halves effective key size to ~{info.security_bits // 2} bits. "
                "AES-256 remains secure against quantum attacks."
            )
        if info.category in ("signature", "kex"):
            if info.name.startswith(("ML-KEM", "ML-DSA", "SLH-DSA")):
                return "Post-quantum algorithm; designed to resist quantum attacks."
            return (
                "Shor's algorithm can break RSA/ECC/DH in polynomial time on a "
                "cryptographically relevant quantum computer. Migrate to ML-KEM/ML-DSA."
            )
        return "Quantum impact assessment not available for this algorithm type."

    def _generate_executive_summary(self, validation: dict, strengths: list) -> str:
        """Generate an executive summary of compliance findings."""
        summary = validation["summary"]
        total = summary["total_algorithms"]
        passed = summary["passed"]
        failed = summary["failed"]
        warnings = summary["warnings"]

        lines = [
            f"Evaluated {total} cryptographic algorithm(s) against FIPS 140-3.",
            f"Results: {passed} PASSED, {failed} FAILED, {warnings} WARNING(s).",
        ]

        if failed > 0:
            lines.append(
                "IMMEDIATE ACTION REQUIRED: Non-compliant algorithms detected. "
                "Replace all DISALLOWED and DEPRECATED algorithms before deployment."
            )

        weak = [s for s in strengths if not s.get("meets_2024_minimum", True)]
        if weak:
            names = ", ".join(s["algorithm"] for s in weak)
            lines.append(
                f"STRENGTH WARNING: {names} do not meet minimum 112-bit security "
                "requirement per SP 800-131A Rev 2."
            )

        pqc_vulnerable = [
            s for s in strengths
            if s.get("quantum_impact", "").startswith("Shor")
        ]
        if pqc_vulnerable:
            names = ", ".join(s["algorithm"] for s in pqc_vulnerable)
            lines.append(
                f"QUANTUM RISK: {names} are vulnerable to quantum attacks. "
                "Plan migration to FIPS 203/204/205 post-quantum algorithms."
            )

        return " ".join(lines)
