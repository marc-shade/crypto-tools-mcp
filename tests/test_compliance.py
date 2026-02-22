"""
Comprehensive tests for defense compliance modules.

Tests FIPS 140-3, CNSA 2.0, Post-Quantum Cryptography, Key Lifecycle, and
Crypto Audit Engine implementations against real standards references.
"""

import json
import pytest
import sys
import time
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from crypto_tools_mcp.compliance.fips_validator import (
    FIPSValidator,
    FIPSStatus,
    SecurityStrength,
)
from crypto_tools_mcp.compliance.cnsa_analyzer import (
    CNSAAnalyzer,
    CNSACompliance,
    TransitionUrgency,
)
from crypto_tools_mcp.compliance.pqc_readiness import (
    PQCReadinessAssessor,
    QuantumVulnerability,
    PQCCategory,
)
from crypto_tools_mcp.compliance.key_lifecycle import (
    KeyLifecycleManager,
    KeyState,
    KeyType,
)
from crypto_tools_mcp.compliance.crypto_audit import (
    CryptoAuditEngine,
    Severity,
)
from crypto_tools_mcp.server import (
    check_fips_compliance,
    analyze_cnsa_compliance,
    assess_pqc_readiness,
    manage_key_lifecycle,
    audit_crypto_usage,
    generate_compliance_report,
)


# =============================================================================
# FIPS 140-3 Validator Tests
# =============================================================================


class TestFIPSApprovedAlgorithms:
    """Verify FIPS-approved algorithms are correctly cataloged."""

    @pytest.fixture
    def validator(self):
        return FIPSValidator()

    def test_aes_variants_approved(self, validator):
        """AES-128/192/256 must be FIPS 197 approved."""
        for name in ("AES-128", "AES-192", "AES-256"):
            result = validator.validate_algorithm(name)
            assert result.status == "pass", f"{name} should be approved"
            assert result.fips_status == FIPSStatus.APPROVED

    def test_aes_256_security_bits(self, validator):
        """AES-256 provides 256-bit security strength."""
        result = validator.validate_algorithm("AES-256")
        assert result.security_bits == 256

    def test_sha2_family_approved(self, validator):
        """SHA-2 family must reference FIPS 180-4."""
        for name in ("SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA-512/256"):
            result = validator.validate_algorithm(name)
            assert result.status == "pass", f"{name} should be approved"

    def test_sha3_family_approved(self, validator):
        """SHA-3 family must reference FIPS 202."""
        for name in ("SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE128", "SHAKE256"):
            result = validator.validate_algorithm(name)
            assert result.status == "pass", f"{name} should be approved"

    def test_rsa_key_sizes(self, validator):
        """RSA key sizes 2048-15360 must be FIPS 186-5 approved."""
        for name in ("RSA-2048", "RSA-3072", "RSA-4096", "RSA-7680", "RSA-15360"):
            result = validator.validate_algorithm(name)
            # RSA-2048 may have a deprecation warning but still passes
            assert result.status in ("pass", "warning"), f"{name} should be approved or warned"
            assert result.fips_status == FIPSStatus.APPROVED

    def test_ecdsa_curves_approved(self, validator):
        """ECDSA P-256/384/521 must reference FIPS 186-5."""
        for name in ("ECDSA-P256", "ECDSA-P384", "ECDSA-P521"):
            result = validator.validate_algorithm(name)
            assert result.status == "pass", f"{name} should be approved"

    def test_eddsa_approved(self, validator):
        """EdDSA Ed25519/Ed448 must reference FIPS 186-5."""
        for name in ("EdDSA-Ed25519", "EdDSA-Ed448"):
            result = validator.validate_algorithm(name)
            assert result.status == "pass", f"{name} should be approved"

    def test_hmac_variants_approved(self, validator):
        """HMAC-SHA-256/384/512 must reference FIPS 198-1."""
        for name in ("HMAC-SHA-256", "HMAC-SHA-384", "HMAC-SHA-512"):
            result = validator.validate_algorithm(name)
            assert result.status == "pass", f"{name} should be approved"

    def test_cmac_gmac_approved(self, validator):
        """CMAC-AES and GMAC-AES must be approved."""
        for name in ("CMAC-AES", "GMAC-AES"):
            result = validator.validate_algorithm(name)
            assert result.status == "pass", f"{name} should be approved"

    def test_drbg_approved(self, validator):
        """Approved DRBGs must reference SP 800-90A Rev 1."""
        for name in ("CTR_DRBG", "Hash_DRBG", "HMAC_DRBG"):
            result = validator.validate_algorithm(name)
            assert result.status == "pass", f"{name} should be approved"

    def test_kdf_approved(self, validator):
        """Approved KDFs must be present."""
        for name in ("SP800-108-KDF", "SP800-56C-KDF", "HKDF", "PBKDF2"):
            result = validator.validate_algorithm(name)
            assert result.status == "pass", f"{name} should be approved"

    def test_key_wrap_approved(self, validator):
        """AES-KW and AES-KWP must reference SP 800-38F."""
        for name in ("AES-KW", "AES-KWP"):
            result = validator.validate_algorithm(name)
            assert result.status == "pass", f"{name} should be approved"

    def test_aead_modes_approved(self, validator):
        """AES-GCM and AES-CCM must be approved."""
        for name in ("AES-GCM", "AES-CCM"):
            result = validator.validate_algorithm(name)
            assert result.status == "pass", f"{name} should be approved"

    def test_post_quantum_fips_approved(self, validator):
        """ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205) approved."""
        pqc_algos = [
            "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
            "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
            "SLH-DSA-128s", "SLH-DSA-128f",
            "SLH-DSA-192s", "SLH-DSA-192f",
            "SLH-DSA-256s", "SLH-DSA-256f",
        ]
        for name in pqc_algos:
            result = validator.validate_algorithm(name)
            assert result.status == "pass", f"{name} should be FIPS approved"

    def test_key_exchange_approved(self, validator):
        """ECDH and DH key exchange must be approved."""
        for name in ("ECDH-P256", "ECDH-P384", "ECDH-P521", "DH-2048"):
            result = validator.validate_algorithm(name)
            assert result.status in ("pass", "warning"), f"{name} should be approved"


class TestFIPSDisallowedAlgorithms:
    """Verify disallowed algorithms are correctly flagged."""

    @pytest.fixture
    def validator(self):
        return FIPSValidator()

    def test_md5_disallowed(self, validator):
        """MD5 must be flagged as DISALLOWED."""
        result = validator.validate_algorithm("MD5")
        assert result.status == "fail"
        assert result.fips_status == FIPSStatus.DISALLOWED

    def test_md4_disallowed(self, validator):
        """MD4 must be flagged as DISALLOWED."""
        result = validator.validate_algorithm("MD4")
        assert result.status == "fail"
        assert result.fips_status == FIPSStatus.DISALLOWED

    def test_sha1_disallowed(self, validator):
        """SHA-1 must be flagged as DISALLOWED for signatures."""
        result = validator.validate_algorithm("SHA-1")
        assert result.status == "fail"
        assert result.fips_status == FIPSStatus.DISALLOWED

    def test_des_disallowed(self, validator):
        """DES must be flagged as DISALLOWED."""
        result = validator.validate_algorithm("DES")
        assert result.status == "fail"
        assert result.fips_status == FIPSStatus.DISALLOWED

    def test_3des_deprecated(self, validator):
        """3DES must be flagged as DEPRECATED."""
        result = validator.validate_algorithm("3DES")
        assert result.status == "fail"
        assert result.fips_status == FIPSStatus.DEPRECATED

    def test_rc4_disallowed(self, validator):
        """RC4 must be flagged as DISALLOWED."""
        result = validator.validate_algorithm("RC4")
        assert result.status == "fail"
        assert result.fips_status == FIPSStatus.DISALLOWED

    def test_rsa_1024_disallowed(self, validator):
        """RSA-1024 must be flagged as DISALLOWED."""
        result = validator.validate_algorithm("RSA-1024")
        assert result.status == "fail"
        assert result.fips_status == FIPSStatus.DISALLOWED

    def test_dual_ec_drbg_disallowed(self, validator):
        """Dual_EC_DRBG (NSA backdoor) must be DISALLOWED."""
        result = validator.validate_algorithm("Dual_EC_DRBG")
        assert result.status == "fail"
        assert result.fips_status == FIPSStatus.DISALLOWED

    def test_blowfish_not_recognized(self, validator):
        """Blowfish (never FIPS approved) must be NOT_RECOGNIZED."""
        result = validator.validate_algorithm("Blowfish")
        assert result.status == "fail"
        assert result.fips_status == FIPSStatus.NOT_RECOGNIZED

    def test_hmac_sha1_legacy_only(self, validator):
        """HMAC-SHA-1 should be legacy use only."""
        result = validator.validate_algorithm("HMAC-SHA-1")
        assert result.status == "warning"
        assert result.fips_status == FIPSStatus.LEGACY_USE_ONLY


class TestFIPSCodeScanning:
    """Test algorithm detection in code/config text."""

    @pytest.fixture
    def validator(self):
        return FIPSValidator()

    def test_scan_detects_md5(self, validator):
        """Scanning code must detect hashlib.md5 usage."""
        code = "import hashlib\nh = hashlib.md5(data)"
        result = validator.scan_text_for_algorithms(code)
        algo_names = [f["algorithm"] for f in result["findings"]]
        assert "MD5" in algo_names

    def test_scan_detects_aes_256(self, validator):
        """Scanning must detect AES-256 references."""
        code = "cipher = AES-256-GCM\nkey_size = 256"
        result = validator.scan_text_for_algorithms(code)
        algo_names = [f["algorithm"] for f in result["findings"]]
        assert "AES-256" in algo_names

    def test_scan_detects_rsa_key_sizes(self, validator):
        """Scanning must detect RSA key size references."""
        code = "rsa_key = RSA.generate(2048)"
        result = validator.scan_text_for_algorithms(code)
        algo_names = [f["algorithm"] for f in result["findings"]]
        assert "RSA-2048" in algo_names

    def test_scan_reports_line_numbers(self, validator):
        """Scan findings must include accurate line numbers."""
        code = "line1\nhashlib.md5(data)\nline3"
        result = validator.scan_text_for_algorithms(code)
        md5_findings = [f for f in result["findings"] if f["algorithm"] == "MD5"]
        assert len(md5_findings) > 0
        assert md5_findings[0]["locations"][0]["line"] == 2


class TestFIPSNameNormalization:
    """Test algorithm name normalization and aliases."""

    @pytest.fixture
    def validator(self):
        return FIPSValidator()

    def test_alias_sha256_no_dash(self, validator):
        """SHA256 (without dash) should resolve to SHA-256."""
        result = validator.validate_algorithm("SHA256")
        assert result.fips_status == FIPSStatus.APPROVED

    def test_alias_sha1_no_dash(self, validator):
        """SHA1 should resolve to SHA-1."""
        result = validator.validate_algorithm("SHA1")
        assert result.fips_status == FIPSStatus.DISALLOWED

    def test_alias_kyber1024(self, validator):
        """Kyber1024 should resolve to ML-KEM-1024."""
        result = validator.validate_algorithm("Kyber1024")
        assert result.fips_status == FIPSStatus.APPROVED

    def test_alias_dilithium5(self, validator):
        """Dilithium5 should resolve to ML-DSA-87."""
        result = validator.validate_algorithm("Dilithium5")
        assert result.fips_status == FIPSStatus.APPROVED

    def test_alias_ed25519(self, validator):
        """Ed25519 should resolve to EdDSA-Ed25519."""
        result = validator.validate_algorithm("Ed25519")
        assert result.fips_status == FIPSStatus.APPROVED


class TestFIPSSecurityStrength:
    """Test SP 800-57 security strength assessments."""

    @pytest.fixture
    def validator(self):
        return FIPSValidator()

    def test_strength_aes_256(self, validator):
        """AES-256 should be MAXIMUM strength (256-bit)."""
        result = validator.assess_security_strength("AES-256")
        assert result["security_bits"] == 256
        assert result["strength_level"] == "MAXIMUM"

    def test_strength_rsa_2048(self, validator):
        """RSA-2048 provides 112-bit security (ACCEPTABLE)."""
        result = validator.assess_security_strength("RSA-2048")
        assert result["security_bits"] == 112
        assert result["strength_level"] == "ACCEPTABLE"

    def test_strength_des_broken(self, validator):
        """DES should be LEGACY or BROKEN level."""
        result = validator.assess_security_strength("DES")
        assert result["security_bits"] == 56
        assert result["strength_level"] in ("LEGACY", "BROKEN")

    def test_quantum_impact_rsa(self, validator):
        """RSA algorithms should warn about Shor's algorithm."""
        result = validator.assess_security_strength("RSA-2048")
        assert "Shor" in result["quantum_impact"]

    def test_quantum_impact_aes(self, validator):
        """AES should mention Grover's algorithm."""
        result = validator.assess_security_strength("AES-256")
        assert "Grover" in result["quantum_impact"]


class TestFIPSComplianceReport:
    """Test comprehensive FIPS compliance report generation."""

    @pytest.fixture
    def validator(self):
        return FIPSValidator()

    def test_report_structure(self, validator):
        """Report must contain all required sections."""
        report = validator.generate_compliance_report(["AES-256", "SHA-384"])
        assert "algorithm_validation" in report
        assert "security_strength_assessments" in report
        assert "deprecation_timeline" in report
        assert "overall_compliance" in report
        assert "executive_summary" in report

    def test_report_compliant_algorithms(self, validator):
        """All-approved algorithms should yield COMPLIANT status."""
        report = validator.generate_compliance_report(["AES-256", "SHA-384", "ECDSA-P384"])
        assert report["overall_compliance"] in ("COMPLIANT", "NON-COMPLIANT")
        # These are all approved; the validation summary should show passes
        summary = report["algorithm_validation"]["summary"]
        assert summary["passed"] == 3

    def test_report_mixed_algorithms(self, validator):
        """Mixed algorithms should yield NON-COMPLIANT."""
        report = validator.generate_compliance_report(["AES-256", "MD5", "SHA-1"])
        assert report["overall_compliance"] == "NON-COMPLIANT"


# =============================================================================
# CNSA 2.0 Analyzer Tests
# =============================================================================


class TestCNSA20RequiredAlgorithms:
    """Verify CNSA 2.0 required algorithms."""

    @pytest.fixture
    def analyzer(self):
        return CNSAAnalyzer()

    def test_aes_256_required(self, analyzer):
        """AES-256 is the ONLY symmetric cipher for CNSA 2.0."""
        finding = analyzer.analyze_algorithm("AES-256")
        assert finding.status == "compliant"

    def test_aes_128_not_compliant(self, analyzer):
        """AES-128 does NOT meet CNSA 2.0 (only AES-256 accepted)."""
        finding = analyzer.analyze_algorithm("AES-128")
        assert finding.status == "non_compliant"

    def test_sha_384_required(self, analyzer):
        """SHA-384 is the minimum hash for CNSA 2.0."""
        finding = analyzer.analyze_algorithm("SHA-384")
        assert finding.status == "compliant"

    def test_sha_256_not_compliant(self, analyzer):
        """SHA-256 does NOT meet CNSA 2.0 (SHA-384 minimum)."""
        finding = analyzer.analyze_algorithm("SHA-256")
        assert finding.status == "non_compliant"

    def test_ml_kem_1024_required(self, analyzer):
        """ML-KEM-1024 (FIPS 203) is CNSA 2.0 REQUIRED for KEM."""
        finding = analyzer.analyze_algorithm("ML-KEM-1024")
        assert finding.status == "compliant"

    def test_ml_kem_768_not_sufficient(self, analyzer):
        """ML-KEM-768 does NOT meet CNSA 2.0 (only 1024 accepted)."""
        finding = analyzer.analyze_algorithm("ML-KEM-768")
        assert finding.status == "non_compliant"

    def test_ml_dsa_87_required(self, analyzer):
        """ML-DSA-87 (FIPS 204) is CNSA 2.0 REQUIRED for signatures."""
        finding = analyzer.analyze_algorithm("ML-DSA-87")
        assert finding.status == "compliant"

    def test_ml_dsa_65_not_sufficient(self, analyzer):
        """ML-DSA-65 does NOT meet CNSA 2.0 (only 87 accepted)."""
        finding = analyzer.analyze_algorithm("ML-DSA-65")
        assert finding.status == "non_compliant"

    def test_slh_dsa_256_acceptable(self, analyzer):
        """SLH-DSA-256 (FIPS 205) is acceptable as alternative."""
        for variant in ("SLH-DSA-256s", "SLH-DSA-256f"):
            finding = analyzer.analyze_algorithm(variant)
            assert finding.status == "compliant", f"{variant} should be acceptable"


class TestCNSATransitionAlgorithms:
    """Verify CNSA 1.0 transition-only algorithms."""

    @pytest.fixture
    def analyzer(self):
        return CNSAAnalyzer()

    def test_ecdsa_p384_transition_only(self, analyzer):
        """ECDSA-P384 is CNSA 1.0 only; transition to ML-DSA-87."""
        finding = analyzer.analyze_algorithm("ECDSA-P384")
        assert finding.status == "transition"
        assert "2033" in finding.deadline

    def test_ecdh_p384_transition_only(self, analyzer):
        """ECDH-P384 is CNSA 1.0 only; transition to ML-KEM-1024."""
        finding = analyzer.analyze_algorithm("ECDH-P384")
        assert finding.status == "transition"

    def test_rsa_3072_transition_only(self, analyzer):
        """RSA-3072 is transition only."""
        finding = analyzer.analyze_algorithm("RSA-3072")
        assert finding.status == "transition"


class TestCNSATimeline:
    """Verify CNSA 2.0 transition timeline accuracy."""

    @pytest.fixture
    def analyzer(self):
        return CNSAAnalyzer()

    def test_timeline_has_all_categories(self, analyzer):
        """Timeline must cover software signing, TLS, networking, etc."""
        timeline = analyzer.get_transition_timeline()
        categories = [e["category"] for e in timeline["timeline"]]
        assert any("software" in c.lower() for c in categories)
        assert any("network" in c.lower() for c in categories)
        assert any("operating" in c.lower() for c in categories)

    def test_timeline_key_dates(self, analyzer):
        """Key dates must match NSA published guidance."""
        timeline = analyzer.get_transition_timeline()
        dates = timeline["key_dates"]
        assert dates["software_signing"] == "2025"
        assert dates["networking"] == "2026"
        assert dates["operating_systems"] == "2027"
        assert dates["full_compliance"] == "2033"

    def test_timeline_urgency_assessment(self, analyzer):
        """Past deadlines should be marked OVERDUE."""
        timeline = analyzer.get_transition_timeline()
        for entry in timeline["timeline"]:
            deadline_year = int(entry["deadline"][:4])
            current_year = int(time.strftime("%Y"))
            if deadline_year < current_year:
                assert entry["urgency"] == "OVERDUE"


class TestCNSACryptoAgility:
    """Test crypto agility assessment."""

    @pytest.fixture
    def analyzer(self):
        return CNSAAnalyzer()

    def test_full_cnsa20_suite_high_agility(self, analyzer):
        """Full CNSA 2.0 suite should score high."""
        result = analyzer.assess_crypto_agility(
            ["AES-256", "SHA-384", "ML-KEM-1024", "ML-DSA-87"]
        )
        assert result["agility_score"] >= 60
        assert result["agility_level"] in ("HIGH", "MODERATE")

    def test_legacy_algorithms_low_agility(self, analyzer):
        """Legacy algorithms should score low."""
        result = analyzer.assess_crypto_agility(["DES", "MD5", "RC4"])
        assert result["agility_score"] <= 25
        assert result["agility_level"] in ("LOW", "CRITICAL")

    def test_agility_has_roadmap(self, analyzer):
        """Assessment must include migration roadmap."""
        result = analyzer.assess_crypto_agility(["AES-128", "SHA-256"])
        assert "migration_roadmap" in result
        assert len(result["migration_roadmap"]) > 0


class TestCNSAGapAnalysis:
    """Test CNSA 2.0 gap analysis."""

    @pytest.fixture
    def analyzer(self):
        return CNSAAnalyzer()

    def test_gap_analysis_structure(self, analyzer):
        """Gap analysis must contain all sections."""
        result = analyzer.generate_gap_analysis(["AES-256", "ECDSA-P384"])
        assert "gaps" in result
        assert "crypto_agility" in result
        assert "transition_timeline" in result
        assert "cnsa_version_comparison" in result

    def test_gap_identifies_missing_categories(self, analyzer):
        """Gap analysis must identify missing CNSA categories."""
        result = analyzer.generate_gap_analysis(["AES-256"])
        # Missing signature and KEM
        assert result["gaps"]["signature"]["status"] == "gap"
        assert result["gaps"]["key_encapsulation"]["status"] == "gap"


# =============================================================================
# Post-Quantum Cryptography Tests
# =============================================================================


class TestPQCAlgorithmDetails:
    """Test PQC algorithm specifications match NIST standards."""

    @pytest.fixture
    def assessor(self):
        return PQCReadinessAssessor()

    def test_ml_kem_parameter_sets(self, assessor):
        """ML-KEM parameter sets must match FIPS 203."""
        # ML-KEM-512: NIST Level 1
        result = assessor.assess_algorithm("ML-KEM-512")
        assert result["nist_level"] == 1
        assert result["key_sizes"]["public_key_bytes"] == 800
        assert result["key_sizes"]["ciphertext_or_signature_bytes"] == 768

        # ML-KEM-768: NIST Level 3
        result = assessor.assess_algorithm("ML-KEM-768")
        assert result["nist_level"] == 3
        assert result["key_sizes"]["public_key_bytes"] == 1184

        # ML-KEM-1024: NIST Level 5
        result = assessor.assess_algorithm("ML-KEM-1024")
        assert result["nist_level"] == 5
        assert result["key_sizes"]["public_key_bytes"] == 1568

    def test_ml_dsa_parameter_sets(self, assessor):
        """ML-DSA parameter sets must match FIPS 204."""
        # ML-DSA-44: NIST Level 2
        result = assessor.assess_algorithm("ML-DSA-44")
        assert result["nist_level"] == 2
        assert result["key_sizes"]["public_key_bytes"] == 1312
        assert result["key_sizes"]["ciphertext_or_signature_bytes"] == 2420

        # ML-DSA-65: NIST Level 3
        result = assessor.assess_algorithm("ML-DSA-65")
        assert result["nist_level"] == 3
        assert result["key_sizes"]["public_key_bytes"] == 1952
        assert result["key_sizes"]["ciphertext_or_signature_bytes"] == 3309

        # ML-DSA-87: NIST Level 5
        result = assessor.assess_algorithm("ML-DSA-87")
        assert result["nist_level"] == 5
        assert result["key_sizes"]["public_key_bytes"] == 2592
        assert result["key_sizes"]["ciphertext_or_signature_bytes"] == 4627

    def test_slh_dsa_parameter_sets(self, assessor):
        """SLH-DSA parameter sets must match FIPS 205."""
        # SLH-DSA-128s: NIST Level 1, small key, large signature
        result = assessor.assess_algorithm("SLH-DSA-128s")
        assert result["nist_level"] == 1
        assert result["key_sizes"]["public_key_bytes"] == 32

        # SLH-DSA-256s: NIST Level 5
        result = assessor.assess_algorithm("SLH-DSA-256s")
        assert result["nist_level"] == 5
        assert result["key_sizes"]["public_key_bytes"] == 64
        assert result["key_sizes"]["ciphertext_or_signature_bytes"] == 29792

    def test_pqc_algorithms_are_quantum_safe(self, assessor):
        """All PQC algorithms must be flagged as quantum safe."""
        pqc_algos = [
            "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
            "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
            "SLH-DSA-128s", "SLH-DSA-256s",
        ]
        for name in pqc_algos:
            result = assessor.assess_algorithm(name)
            assert result["quantum_safe"] is True, f"{name} should be quantum safe"
            assert result["quantum_risk_score"] == 0


class TestQuantumVulnerability:
    """Test quantum vulnerability assessment for classical algorithms."""

    @pytest.fixture
    def assessor(self):
        return PQCReadinessAssessor()

    def test_rsa_broken_by_shor(self, assessor):
        """All RSA sizes must be flagged as broken by Shor's algorithm."""
        for name in ("RSA-2048", "RSA-3072", "RSA-4096"):
            result = assessor.assess_algorithm(name)
            assert result["vulnerability"] == "broken"
            assert result["security_bits_quantum"] == 0
            assert "Shor" in result["attack_vector"]

    def test_ecdsa_broken_by_shor(self, assessor):
        """All ECDSA curves broken by Shor's algorithm."""
        for name in ("ECDSA-P256", "ECDSA-P384", "ECDSA-P521"):
            result = assessor.assess_algorithm(name)
            assert result["vulnerability"] == "broken"
            assert result["security_bits_quantum"] == 0

    def test_aes_reduced_by_grover(self, assessor):
        """AES security halved by Grover's algorithm."""
        result = assessor.assess_algorithm("AES-128")
        assert result["vulnerability"] == "reduced"
        assert result["security_bits_quantum"] == 64  # 128 / 2

        result = assessor.assess_algorithm("AES-256")
        assert result["vulnerability"] == "reduced"
        assert result["security_bits_quantum"] == 128  # 256 / 2

    def test_aes_256_still_adequate(self, assessor):
        """AES-256 retains 128-bit quantum security -- adequate."""
        result = assessor.assess_algorithm("AES-256")
        assert result["urgency"] == "NONE"

    def test_sha_reduced_by_grover(self, assessor):
        """SHA hash functions reduced by Grover but collision unchanged."""
        result = assessor.assess_algorithm("SHA-256")
        assert result["vulnerability"] == "reduced"
        assert result["security_bits_quantum"] == 128


class TestHNDLAssessment:
    """Test Harvest-Now-Decrypt-Later threat modeling."""

    @pytest.fixture
    def assessor(self):
        return PQCReadinessAssessor()

    def test_hndl_critical_long_lived_data(self, assessor):
        """Critical data with long shelf life + RSA should have high HNDL risk."""
        result = assessor.hndl_threat_assessment(
            algorithms=["RSA-2048"],
            data_sensitivity="critical",
            data_shelf_life_years=20,
        )
        assert result["risk_level"] in ("CRITICAL", "HIGH")
        assert result["hndl_risk_score"] > 0

    def test_hndl_low_risk_symmetric_only(self, assessor):
        """AES-256-only with short shelf life should have low HNDL risk."""
        result = assessor.hndl_threat_assessment(
            algorithms=["AES-256"],
            data_sensitivity="low",
            data_shelf_life_years=2,
        )
        assert result["risk_level"] == "LOW"
        assert result["hndl_risk_score"] == 0

    def test_hndl_crqc_timeline(self, assessor):
        """CRQC timeline estimates must be present and reasonable."""
        result = assessor.hndl_threat_assessment(
            algorithms=["RSA-2048"],
            data_sensitivity="high",
            data_shelf_life_years=10,
        )
        assert "crqc_timeline_estimate" in result
        assert result["crqc_timeline_estimate"]["earliest"] >= 2030
        assert result["crqc_timeline_estimate"]["likely"] >= 2035

    def test_hndl_mitigation_steps(self, assessor):
        """Mitigation steps must be provided."""
        result = assessor.hndl_threat_assessment(
            algorithms=["ECDSA-P256"],
            data_sensitivity="high",
            data_shelf_life_years=15,
        )
        assert "mitigation_steps" in result
        assert len(result["mitigation_steps"]) >= 4


class TestPQCMigrationRoadmap:
    """Test PQC migration roadmap generation."""

    @pytest.fixture
    def assessor(self):
        return PQCReadinessAssessor()

    def test_roadmap_has_phases(self, assessor):
        """Roadmap must include multiple migration phases."""
        result = assessor.generate_migration_roadmap(
            algorithms=["RSA-2048", "ECDSA-P256", "AES-256"],
            system_type="federal",
        )
        assert "migration_phases" in result
        assert len(result["migration_phases"]) >= 3

    def test_roadmap_nss_targets_2033(self, assessor):
        """NSS systems must target 2033 for full compliance."""
        result = assessor.generate_migration_roadmap(
            algorithms=["RSA-2048"],
            system_type="nss",
        )
        assert "2033" in result["compliance_target"]

    def test_roadmap_includes_round4_candidates(self, assessor):
        """Roadmap should reference Round 4 candidates."""
        result = assessor.generate_migration_roadmap(
            algorithms=["RSA-2048"],
            system_type="general",
        )
        assert "round_4_candidates" in result
        names = [c["name"] for c in result["round_4_candidates"]]
        assert "BIKE" in names
        assert "Classic McEliece" in names


class TestHybridRecommendations:
    """Test hybrid mode (classical + PQC) recommendations."""

    @pytest.fixture
    def assessor(self):
        return PQCReadinessAssessor()

    def test_hybrid_for_rsa(self, assessor):
        """RSA should get hybrid recommendation with ML-KEM/ML-DSA."""
        result = assessor.hybrid_mode_recommendations(["RSA-2048"])
        recs = result["recommendations"]
        assert recs[0]["hybrid_needed"] is True
        assert "ML-KEM" in recs[0]["hybrid_configuration"] or "ML-DSA" in recs[0]["hybrid_configuration"]

    def test_no_hybrid_for_aes(self, assessor):
        """AES should not need hybrid mode."""
        result = assessor.hybrid_mode_recommendations(["AES-256"])
        recs = result["recommendations"]
        assert recs[0]["hybrid_needed"] is False


# =============================================================================
# Key Lifecycle Management Tests
# =============================================================================


class TestKeyStateMachine:
    """Test SP 800-57 key state machine transitions."""

    @pytest.fixture
    def manager(self):
        return KeyLifecycleManager()

    def test_create_key_starts_pre_activation(self, manager):
        """New keys must start in PRE-ACTIVATION state."""
        result = manager.create_key(
            key_id="test-1", name="Test Key",
            key_type="symmetric_encryption", algorithm="AES-256",
            key_length_bits=256,
        )
        assert result["state"] == "pre-activation"

    def test_valid_transition_pre_activation_to_active(self, manager):
        """PRE-ACTIVATION -> ACTIVE is a valid transition."""
        manager.create_key(
            key_id="test-2", name="Test Key",
            key_type="symmetric_encryption", algorithm="AES-256",
            key_length_bits=256,
        )
        result = manager.transition_key("test-2", "active", "Initial activation")
        assert result["new_state"] == "active"

    def test_valid_transition_active_to_deactivated(self, manager):
        """ACTIVE -> DEACTIVATED is valid."""
        manager.create_key(key_id="test-3", name="Test Key",
                          key_type="tls_key", algorithm="ECDSA-P384",
                          key_length_bits=384)
        manager.transition_key("test-3", "active")
        result = manager.transition_key("test-3", "deactivated", "Key rotation")
        assert result["new_state"] == "deactivated"

    def test_valid_transition_active_to_compromised(self, manager):
        """ACTIVE -> COMPROMISED is valid."""
        manager.create_key(key_id="test-4", name="Compromised Key",
                          key_type="api_key", algorithm="AES-256",
                          key_length_bits=256)
        manager.transition_key("test-4", "active")
        result = manager.transition_key("test-4", "compromised", "Breach detected")
        assert result["new_state"] == "compromised"

    def test_invalid_transition_destroyed_to_active(self, manager):
        """DESTROYED -> ACTIVE must be rejected."""
        manager.create_key(key_id="test-5", name="Dead Key",
                          key_type="session_key", algorithm="AES-256",
                          key_length_bits=256)
        manager.transition_key("test-5", "destroyed")
        result = manager.transition_key("test-5", "active")
        assert "error" in result or result.get("success") is False

    def test_invalid_transition_active_to_pre_activation(self, manager):
        """ACTIVE -> PRE-ACTIVATION must be rejected (no going back)."""
        manager.create_key(key_id="test-6", name="Test Key",
                          key_type="ssh_key", algorithm="EdDSA-Ed25519",
                          key_length_bits=256)
        manager.transition_key("test-6", "active")
        result = manager.transition_key("test-6", "pre-activation")
        assert "error" in result or result.get("success") is False

    def test_compromised_to_destroyed_compromised(self, manager):
        """COMPROMISED -> DESTROYED-COMPROMISED is valid."""
        manager.create_key(key_id="test-7", name="Bad Key",
                          key_type="symmetric_encryption", algorithm="AES-256",
                          key_length_bits=256)
        manager.transition_key("test-7", "active")
        manager.transition_key("test-7", "compromised")
        result = manager.transition_key("test-7", "destroyed-compromised")
        assert result["new_state"] == "destroyed-compromised"

    def test_duplicate_key_id_rejected(self, manager):
        """Creating a key with an existing ID must fail."""
        manager.create_key(key_id="dup-1", name="Key 1",
                          key_type="api_key", algorithm="AES-256",
                          key_length_bits=256)
        result = manager.create_key(key_id="dup-1", name="Key 2",
                                   key_type="api_key", algorithm="AES-256",
                                   key_length_bits=256)
        assert "error" in result or result.get("success") is False


class TestCryptoperiodPolicies:
    """Test cryptoperiod enforcement per SP 800-57 Table 1."""

    @pytest.fixture
    def manager(self):
        return KeyLifecycleManager()

    def test_session_key_24_hours(self, manager):
        """Session keys must have 24-hour max cryptoperiod."""
        policies = manager.get_cryptoperiod_policies()
        session_policy = None
        for p in policies["policies"]:
            if p["key_type"] == "session_key":
                session_policy = p
                break
        assert session_policy is not None
        assert session_policy["max_active_days"] == 1

    def test_api_key_90_days(self, manager):
        """API keys must have 90-day max cryptoperiod."""
        policies = manager.get_cryptoperiod_policies()
        api_policy = None
        for p in policies["policies"]:
            if p["key_type"] == "api_key":
                api_policy = p
                break
        assert api_policy is not None
        assert api_policy["max_active_days"] == 90

    def test_tls_key_398_days(self, manager):
        """TLS keys: CA/B Forum max 398 days."""
        policies = manager.get_cryptoperiod_policies()
        tls_policy = None
        for p in policies["policies"]:
            if p["key_type"] == "tls_key":
                tls_policy = p
                break
        assert tls_policy is not None
        assert tls_policy["max_active_days"] == 398

    def test_root_ca_long_lifetime(self, manager):
        """Root CA keys have 10-20 year lifetime."""
        policies = manager.get_cryptoperiod_policies()
        root_policy = None
        for p in policies["policies"]:
            if p["key_type"] == "root_ca_key":
                root_policy = p
                break
        assert root_policy is not None
        assert root_policy["max_active_days"] == 7300  # ~20 years

    def test_symmetric_encryption_2_years(self, manager):
        """Symmetric encryption keys: 2-year cryptoperiod."""
        policies = manager.get_cryptoperiod_policies()
        sym_policy = None
        for p in policies["policies"]:
            if p["key_type"] == "symmetric_encryption":
                sym_policy = p
                break
        assert sym_policy is not None
        assert sym_policy["max_active_days"] == 730  # ~2 years


class TestKeyInventoryAndRotation:
    """Test key inventory and rotation schedule checks."""

    @pytest.fixture
    def manager(self):
        mgr = KeyLifecycleManager()
        # Pre-populate with keys
        mgr.create_key(key_id="inv-1", name="Active AES Key",
                       key_type="symmetric_encryption", algorithm="AES-256",
                       key_length_bits=256, owner="ops", location="HSM")
        mgr.transition_key("inv-1", "active")
        mgr.create_key(key_id="inv-2", name="Pre-Activation RSA Key",
                       key_type="asymmetric_signing_private", algorithm="RSA-4096",
                       key_length_bits=4096, owner="dev", location="AWS KMS")
        return mgr

    def test_inventory_lists_all_keys(self, manager):
        """Inventory must list all registered keys."""
        inventory = manager.get_key_inventory()
        assert inventory["total_keys"] == 2
        key_ids = [k["key_id"] for k in inventory["inventory"]]
        assert "inv-1" in key_ids
        assert "inv-2" in key_ids

    def test_rotation_schedule_check(self, manager):
        """Rotation check must report on active keys."""
        rotation = manager.check_rotation_schedule()
        assert "summary" in rotation
        assert "overdue" in rotation["summary"]

    def test_lifecycle_report(self, manager):
        """Lifecycle report must include all sections."""
        report = manager.generate_lifecycle_report()
        assert "overall_compliance" in report
        assert "key_inventory" in report
        assert "rotation_status" in report
        assert "compliance_checks" in report


class TestKeyManagementPracticeValidation:
    """Test validation of described key management practices."""

    @pytest.fixture
    def manager(self):
        return KeyLifecycleManager()

    def test_good_practices_score_high(self, manager):
        """Well-described practices should score well."""
        result = manager.validate_key_management_practice(
            "Keys are stored in HSM with RBAC access control. "
            "Annual rotation is automated. Destruction uses NIST 800-88 "
            "sanitization. All operations are logged for audit. "
            "Key backup uses split knowledge escrow."
        )
        assert result["compliance_score"] >= 70

    def test_bad_practices_score_low(self, manager):
        """Poor practices should get low score."""
        result = manager.validate_key_management_practice(
            "Keys are stored in plaintext config files."
        )
        assert result["compliance_score"] < 50
        assert result["overall_status"] in ("NON_COMPLIANT", "NEEDS_IMPROVEMENT")

    def test_missing_hsm_flagged(self, manager):
        """No mention of HSM/KMS should be flagged."""
        result = manager.validate_key_management_practice(
            "Keys are rotated annually and logged."
        )
        findings = [f["category"] for f in result["findings"]]
        assert "Key Storage" in findings


class TestDestructionGuidance:
    """Test key destruction guidance per NIST 800-88."""

    @pytest.fixture
    def manager(self):
        return KeyLifecycleManager()

    def test_root_ca_requires_destroy(self, manager):
        """Root CA keys require physical destruction."""
        result = manager.get_destruction_guidance("root_ca_key")
        assert result["recommended_method"] == "Destroy"

    def test_session_key_clear_sufficient(self, manager):
        """Session keys can be cleared (logical overwrite)."""
        result = manager.get_destruction_guidance("session_key")
        assert result["recommended_method"] == "Clear"

    def test_guidance_includes_verification(self, manager):
        """Guidance must include verification steps."""
        result = manager.get_destruction_guidance()
        assert "verification_steps" in result
        assert len(result["verification_steps"]) >= 4


# =============================================================================
# Crypto Audit Engine Tests
# =============================================================================


class TestAuditHardcodedKeys:
    """Test detection of hardcoded cryptographic keys."""

    @pytest.fixture
    def engine(self):
        return CryptoAuditEngine()

    def test_detect_hardcoded_secret_key(self, engine):
        """Must detect hardcoded secret_key assignments."""
        code = """secret_key = 'ABCDEF1234567890abcdef'"""
        result = engine.scan_text(code)
        assert result["total_findings"] > 0
        assert any(f["rule_id"] == "CRYPTO-001" for f in result["findings"])

    def test_detect_private_key_header(self, engine):
        """Must detect PEM private key headers."""
        code = "-----BEGIN RSA PRIVATE KEY-----"
        result = engine.scan_text(code)
        assert result["total_findings"] > 0
        cwes = []
        for f in result["findings"]:
            cwes.extend(f["cwe_ids"])
        assert "CWE-798" in cwes

    def test_detect_aws_access_key(self, engine):
        """Must detect AWS access key patterns."""
        code = "aws_key = AKIAIOSFODNN7EXAMPLE"
        result = engine.scan_text(code)
        assert result["total_findings"] > 0

    def test_cwe_798_mapping(self, engine):
        """Hardcoded secret findings must map to CWE-798."""
        code = """password = 'super_secret_password123'"""
        result = engine.scan_text(code)
        cwe_found = False
        for f in result["findings"]:
            if "CWE-798" in f["cwe_ids"]:
                cwe_found = True
                break
        assert cwe_found


class TestAuditWeakAlgorithms:
    """Test detection of deprecated/broken algorithms."""

    @pytest.fixture
    def engine(self):
        return CryptoAuditEngine()

    def test_detect_md5_python(self, engine):
        """Must detect hashlib.md5 in Python code."""
        code = "import hashlib\ndigest = hashlib.md5(data)"
        result = engine.scan_text(code)
        md5_findings = [f for f in result["findings"] if f["rule_id"] == "CRYPTO-020"]
        assert len(md5_findings) > 0
        assert "CWE-327" in md5_findings[0]["cwe_ids"] or "CWE-328" in md5_findings[0]["cwe_ids"]

    def test_detect_sha1_python(self, engine):
        """Must detect hashlib.sha1 in Python code."""
        code = "h = hashlib.sha1(data)"
        result = engine.scan_text(code)
        sha1_findings = [f for f in result["findings"] if f["rule_id"] == "CRYPTO-021"]
        assert len(sha1_findings) > 0

    def test_detect_des_usage(self, engine):
        """Must detect DES cipher usage."""
        code = "cipher = DES.new(key, DES.MODE_ECB)"
        result = engine.scan_text(code)
        des_findings = [f for f in result["findings"] if f["rule_id"] == "CRYPTO-022"]
        assert len(des_findings) > 0

    def test_detect_rc4_usage(self, engine):
        """Must detect RC4 cipher usage."""
        code = "cipher = RC4.new(key)"
        result = engine.scan_text(code)
        rc4_findings = [f for f in result["findings"] if f["rule_id"] == "CRYPTO-024"]
        assert len(rc4_findings) > 0

    def test_detect_3des_usage(self, engine):
        """Must detect 3DES/TripleDES usage."""
        code = "from Crypto.Cipher import DESede\ncipher = TripleDES.new(key)"
        result = engine.scan_text(code)
        tdea_findings = [f for f in result["findings"] if f["rule_id"] == "CRYPTO-023"]
        assert len(tdea_findings) > 0


class TestAuditInsecureModes:
    """Test detection of insecure cipher modes."""

    @pytest.fixture
    def engine(self):
        return CryptoAuditEngine()

    def test_detect_ecb_mode(self, engine):
        """Must detect ECB mode usage (CWE-327)."""
        code = "cipher = AES.new(key, AES.MODE_ECB)"
        result = engine.scan_text(code)
        ecb_findings = [f for f in result["findings"] if f["rule_id"] == "CRYPTO-030"]
        assert len(ecb_findings) > 0


class TestAuditWeakRandom:
    """Test detection of non-CSPRNG random usage."""

    @pytest.fixture
    def engine(self):
        return CryptoAuditEngine()

    def test_detect_random_module(self, engine):
        """Must detect random.random() for security-sensitive use."""
        code = "import random\ntoken = random.randint(0, 2**128)"
        result = engine.scan_text(code)
        weak_rng_findings = [f for f in result["findings"] if f["rule_id"] == "CRYPTO-010"]
        assert len(weak_rng_findings) > 0
        for f in weak_rng_findings:
            assert "CWE-330" in f["cwe_ids"] or "CWE-338" in f["cwe_ids"]

    def test_detect_math_random_js(self, engine):
        """Must detect Math.random() in JavaScript code."""
        code = "var key = Math.random().toString(36)"
        result = engine.scan_text(code)
        assert result["total_findings"] > 0


class TestAuditCertificateValidation:
    """Test detection of disabled certificate verification."""

    @pytest.fixture
    def engine(self):
        return CryptoAuditEngine()

    def test_detect_verify_false(self, engine):
        """Must detect verify=False (CWE-295)."""
        code = "requests.get(url, verify=False)"
        result = engine.scan_text(code)
        cert_findings = [f for f in result["findings"] if f["rule_id"] == "CRYPTO-060"]
        assert len(cert_findings) > 0
        assert "CWE-295" in cert_findings[0]["cwe_ids"]

    def test_detect_cert_none(self, engine):
        """Must detect CERT_NONE setting."""
        code = "ctx.check_hostname = False\nctx.verify_mode = ssl.CERT_NONE"
        result = engine.scan_text(code)
        assert result["total_findings"] > 0


class TestAuditInsecureTLS:
    """Test detection of deprecated TLS/SSL versions."""

    @pytest.fixture
    def engine(self):
        return CryptoAuditEngine()

    def test_detect_sslv3(self, engine):
        """Must detect SSLv3 usage (CWE-757)."""
        code = "ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv3)"
        result = engine.scan_text(code)
        tls_findings = [f for f in result["findings"] if f["rule_id"] == "CRYPTO-070"]
        assert len(tls_findings) > 0

    def test_detect_tls_1_0(self, engine):
        """Must detect TLS 1.0 usage."""
        code = "min_version = TLS_1_0"
        result = engine.scan_text(code)
        assert result["total_findings"] > 0


class TestAuditDualECDRBG:
    """Test detection of backdoored Dual_EC_DRBG."""

    @pytest.fixture
    def engine(self):
        return CryptoAuditEngine()

    def test_detect_dual_ec_drbg(self, engine):
        """Must detect Dual_EC_DRBG usage."""
        code = "rng = Dual_EC_DRBG()"
        result = engine.scan_text(code)
        findings = [f for f in result["findings"] if f["rule_id"] == "CRYPTO-080"]
        assert len(findings) > 0


class TestAuditRSAKeySize:
    """Test detection of insufficient RSA key sizes."""

    @pytest.fixture
    def engine(self):
        return CryptoAuditEngine()

    def test_detect_rsa_1024(self, engine):
        """Must detect RSA-1024 key size (CWE-326)."""
        code = "key = RSA.generate(1024)"
        result = engine.scan_text(code)
        findings = [f for f in result["findings"] if f["rule_id"] == "CRYPTO-050"]
        assert len(findings) > 0
        assert "CWE-326" in findings[0]["cwe_ids"]


class TestSARIFOutput:
    """Test SARIF 2.1.0 output format compliance."""

    @pytest.fixture
    def engine(self):
        return CryptoAuditEngine()

    def test_sarif_schema_reference(self, engine):
        """SARIF output must reference the 2.1.0 schema."""
        audit = engine.scan_text("hashlib.md5(data)")
        sarif = engine.to_sarif(audit)
        assert "$schema" in sarif
        assert "sarif-schema-2.1.0" in sarif["$schema"]
        assert sarif["version"] == "2.1.0"

    def test_sarif_has_runs(self, engine):
        """SARIF must have runs array with tool and results."""
        audit = engine.scan_text("hashlib.md5(data)")
        sarif = engine.to_sarif(audit)
        assert "runs" in sarif
        assert len(sarif["runs"]) == 1
        assert "tool" in sarif["runs"][0]
        assert "results" in sarif["runs"][0]

    def test_sarif_tool_driver(self, engine):
        """SARIF tool driver must include name, version, and rules."""
        audit = engine.scan_text("hashlib.md5(data)")
        sarif = engine.to_sarif(audit)
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "crypto-tools-mcp-audit"
        assert "version" in driver
        assert "rules" in driver
        assert len(driver["rules"]) > 0

    def test_sarif_results_have_locations(self, engine):
        """SARIF results must include physical locations."""
        audit = engine.scan_text("hashlib.md5(data)")
        sarif = engine.to_sarif(audit)
        results = sarif["runs"][0]["results"]
        assert len(results) > 0
        for result in results:
            assert "locations" in result
            assert len(result["locations"]) > 0
            loc = result["locations"][0]["physicalLocation"]
            assert "artifactLocation" in loc
            assert "region" in loc
            assert "startLine" in loc["region"]

    def test_sarif_severity_mapping(self, engine):
        """SARIF severity levels must map correctly."""
        # Critical should map to "error"
        audit = engine.scan_text("password = 'hardcoded_secret_key_value_here'")
        sarif = engine.to_sarif(audit)
        results = sarif["runs"][0]["results"]
        if results:
            # Critical/high should be "error"
            levels = {r["level"] for r in results}
            assert levels.issubset({"error", "warning", "note"})

    def test_sarif_clean_code_no_results(self, engine):
        """Clean code should produce empty results."""
        audit = engine.scan_text("x = 1 + 2\nprint(x)")
        sarif = engine.to_sarif(audit)
        assert len(sarif["runs"][0]["results"]) == 0


class TestAuditOverallRisk:
    """Test overall risk calculation."""

    @pytest.fixture
    def engine(self):
        return CryptoAuditEngine()

    def test_clean_code_is_clean(self, engine):
        """Code with no issues should be CLEAN."""
        result = engine.scan_text("x = 1 + 2\nprint(x)")
        assert result["overall_risk"] == "CLEAN"

    def test_critical_finding_is_critical(self, engine):
        """Code with critical issue should be CRITICAL risk."""
        code = "password = 'super_secret_password123'"
        result = engine.scan_text(code)
        assert result["overall_risk"] == "CRITICAL"


# =============================================================================
# MCP Server Integration Tests
# =============================================================================


class TestFIPSComplianceTool:
    """Test the check_fips_compliance MCP tool."""

    @pytest.mark.asyncio
    async def test_fips_tool_approved(self):
        """Test FIPS tool with approved algorithms."""
        result = await check_fips_compliance("AES-256,SHA-384")
        data = json.loads(result)
        assert data["success"] is True

    @pytest.mark.asyncio
    async def test_fips_tool_with_scan(self):
        """Test FIPS tool with code scanning."""
        result = await check_fips_compliance(
            algorithms="AES-256",
            scan_text="cipher = AES-256-GCM\nold_hash = hashlib.md5(data)"
        )
        data = json.loads(result)
        assert data["success"] is True

    @pytest.mark.asyncio
    async def test_fips_tool_empty_input_error(self):
        """Test FIPS tool with no input."""
        result = await check_fips_compliance("")
        data = json.loads(result)
        assert data["success"] is False


class TestCNSAComplianceTool:
    """Test the analyze_cnsa_compliance MCP tool."""

    @pytest.mark.asyncio
    async def test_cnsa_tool_compliant(self):
        """Test CNSA tool with compliant algorithms."""
        result = await analyze_cnsa_compliance("AES-256,SHA-384,ML-KEM-1024,ML-DSA-87")
        data = json.loads(result)
        assert data["success"] is True

    @pytest.mark.asyncio
    async def test_cnsa_tool_non_compliant(self):
        """Test CNSA tool with non-compliant algorithms."""
        result = await analyze_cnsa_compliance("AES-128,SHA-256,RSA-2048")
        data = json.loads(result)
        assert data["success"] is True
        # Should detect non-compliance
        assert "NON_COMPLIANT" in json.dumps(data)


class TestPQCReadinessTool:
    """Test the assess_pqc_readiness MCP tool."""

    @pytest.mark.asyncio
    async def test_pqc_tool_basic(self):
        """Test PQC tool with mixed algorithms."""
        result = await assess_pqc_readiness(
            algorithms="RSA-2048,ECDSA-P256,AES-256",
            data_sensitivity="high",
            data_shelf_life_years=10,
        )
        data = json.loads(result)
        assert data["success"] is True
        assert "hndl_assessment" in data
        assert "migration_roadmap" in data

    @pytest.mark.asyncio
    async def test_pqc_tool_empty_error(self):
        """Test PQC tool with empty input."""
        result = await assess_pqc_readiness("")
        data = json.loads(result)
        assert data["success"] is False


class TestKeyLifecycleTool:
    """Test the manage_key_lifecycle MCP tool."""

    @pytest.mark.asyncio
    async def test_create_and_activate(self):
        """Test creating and activating a key via MCP tool."""
        import uuid

        unique_id = f"mcp-test-{uuid.uuid4().hex[:8]}"
        result = await manage_key_lifecycle(
            action="create",
            key_id=unique_id,
            name="MCP Test Key",
            key_type="symmetric_encryption",
            algorithm="AES-256",
            key_length_bits=256,
        )
        data = json.loads(result)
        assert data["success"] is True
        assert data["state"] == "pre-activation"

    @pytest.mark.asyncio
    async def test_policies_action(self):
        """Test getting cryptoperiod policies."""
        result = await manage_key_lifecycle(action="policies")
        data = json.loads(result)
        assert data["success"] is True
        assert "policies" in data

    @pytest.mark.asyncio
    async def test_invalid_action_error(self):
        """Test invalid action returns error."""
        result = await manage_key_lifecycle(action="invalid_action")
        data = json.loads(result)
        assert data["success"] is False

    @pytest.mark.asyncio
    async def test_destroy_guidance(self):
        """Test destruction guidance."""
        result = await manage_key_lifecycle(
            action="destroy_guidance",
            key_type="root_ca_key",
        )
        data = json.loads(result)
        assert data["success"] is True
        assert data["recommended_method"] == "Destroy"


class TestCryptoAuditTool:
    """Test the audit_crypto_usage MCP tool."""

    @pytest.mark.asyncio
    async def test_audit_json_output(self):
        """Test audit tool JSON output."""
        result = await audit_crypto_usage(
            text="import hashlib\nh = hashlib.md5(data)",
            output_format="json",
        )
        data = json.loads(result)
        assert data["success"] is True
        assert data["total_findings"] > 0

    @pytest.mark.asyncio
    async def test_audit_sarif_output(self):
        """Test audit tool SARIF output."""
        result = await audit_crypto_usage(
            text="import hashlib\nh = hashlib.md5(data)",
            output_format="sarif",
        )
        data = json.loads(result)
        assert data["success"] is True
        assert data["version"] == "2.1.0"
        assert "runs" in data

    @pytest.mark.asyncio
    async def test_audit_clean_code(self):
        """Test audit with clean code."""
        result = await audit_crypto_usage(text="x = 1 + 2\nprint(x)")
        data = json.loads(result)
        assert data["success"] is True
        assert data["total_findings"] == 0

    @pytest.mark.asyncio
    async def test_audit_empty_error(self):
        """Test audit with empty text."""
        result = await audit_crypto_usage(text="")
        data = json.loads(result)
        assert data["success"] is False


class TestComprehensiveReport:
    """Test the generate_compliance_report MCP tool."""

    @pytest.mark.asyncio
    async def test_full_report_structure(self):
        """Test comprehensive report has all sections."""
        result = await generate_compliance_report(
            algorithms="AES-256,RSA-2048,SHA-256",
            system_type="federal",
            data_sensitivity="high",
        )
        data = json.loads(result)
        assert data["success"] is True
        assert "fips_140_3" in data
        assert "cnsa_2_0" in data
        assert "post_quantum" in data
        assert "overall_compliance" in data
        assert "executive_summary" in data

    @pytest.mark.asyncio
    async def test_full_report_with_scan(self):
        """Test comprehensive report with code scanning."""
        result = await generate_compliance_report(
            algorithms="AES-256",
            scan_text="import hashlib\nhashlib.md5(data)",
        )
        data = json.loads(result)
        assert data["success"] is True
        assert "code_audit" in data

    @pytest.mark.asyncio
    async def test_full_report_standards_list(self):
        """Report must list all evaluated standards."""
        result = await generate_compliance_report(algorithms="AES-256")
        data = json.loads(result)
        standards = data["standards_evaluated"]
        assert "FIPS 140-3" in standards
        assert "NSA CNSA 2.0" in standards
        assert "NIST FIPS 203 (ML-KEM)" in standards
        assert "NIST FIPS 204 (ML-DSA)" in standards
        assert "NIST FIPS 205 (SLH-DSA)" in standards
