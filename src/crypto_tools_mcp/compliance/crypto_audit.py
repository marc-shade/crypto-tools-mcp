"""
Crypto Audit Engine

Scans code and configuration for cryptographic security issues.
Maps findings to CWE IDs and generates SARIF-compatible output.

References:
- CWE-326: Inadequate Encryption Strength
- CWE-327: Use of a Broken or Risky Cryptographic Algorithm
- CWE-328: Use of Weak Hash
- CWE-330: Use of Insufficiently Random Values
- CWE-338: Use of Cryptographically Weak PRNG
- CWE-798: Use of Hard-coded Credentials
- CWE-295: Improper Certificate Validation
- CWE-757: Selection of Less-Secure Algorithm During Negotiation
"""

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class AuditPattern:
    """Detection pattern for crypto audit."""
    id: str
    name: str
    description: str
    patterns: list[str]
    severity: Severity
    cwe_ids: list[str]
    remediation: str
    false_positive_notes: str = ""
    category: str = ""


@dataclass
class AuditFinding:
    """Individual audit finding."""
    rule_id: str
    rule_name: str
    severity: Severity
    message: str
    line: int
    column: int
    context: str
    cwe_ids: list[str]
    remediation: str
    file_path: str = ""


class CryptoAuditEngine:
    """
    Cryptographic audit engine for scanning code and configuration.

    Detects hardcoded secrets, weak algorithms, insecure configurations,
    and other cryptographic issues. Maps findings to CWE IDs and generates
    reports compatible with SARIF format for CI/CD integration.
    """

    AUDIT_RULES: list[AuditPattern] = [
        # Hardcoded Keys and Secrets (CWE-798)
        AuditPattern(
            id="CRYPTO-001",
            name="Hardcoded Cryptographic Key",
            description="Cryptographic key material appears to be hardcoded in source code",
            patterns=[
                r"""(?:secret|api)[-_]?key\s*[=:]\s*['"][A-Za-z0-9+/=]{16,}['"]""",
                r"""(?:private|secret)[-_]?key\s*[=:]\s*['"][A-Za-z0-9+/=]{16,}['"]""",
                r"""PRIVATE KEY-----""",
                r"""(?:password|passwd|pwd)\s*[=:]\s*['"][^'"]{8,}['"]""",
                r"""(?:token|auth[-_]?token)\s*[=:]\s*['"][A-Za-z0-9._-]{20,}['"]""",
            ],
            severity=Severity.CRITICAL,
            cwe_ids=["CWE-798"],
            remediation="Remove hardcoded keys. Use environment variables, secret management "
                        "systems (HashiCorp Vault, AWS Secrets Manager), or key management "
                        "services (KMS) instead.",
            category="hardcoded_secrets",
        ),
        AuditPattern(
            id="CRYPTO-002",
            name="Hardcoded AWS Credentials",
            description="AWS access key or secret key appears hardcoded",
            patterns=[
                r"""AKIA[0-9A-Z]{16}""",
                r"""aws[-_]?secret[-_]?access[-_]?key\s*[=:]\s*['"][A-Za-z0-9+/]{40}['"]""",
                r"""aws[-_]?access[-_]?key[-_]?id\s*[=:]\s*['"]AKIA[0-9A-Z]{16}['"]""",
            ],
            severity=Severity.CRITICAL,
            cwe_ids=["CWE-798"],
            remediation="Use AWS IAM roles, instance profiles, or AWS Secrets Manager. "
                        "Rotate compromised credentials immediately.",
            category="hardcoded_secrets",
        ),
        AuditPattern(
            id="CRYPTO-003",
            name="Hardcoded Hex Key Material",
            description="Potential cryptographic key in hexadecimal format",
            patterns=[
                r"""(?:key|iv|nonce|salt)\s*[=:]\s*(?:b['"]|bytes\.fromhex\s*\(\s*['"])[0-9a-fA-F]{32,}""",
                r"""(?:key|iv|nonce|salt)\s*[=:]\s*['"]\\x[0-9a-fA-F]{32,}['"]""",
                r"""\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){15,}""",
            ],
            severity=Severity.HIGH,
            cwe_ids=["CWE-798"],
            remediation="Generate keys at runtime using a CSPRNG (os.urandom, secrets module) "
                        "or retrieve from secure key storage.",
            false_positive_notes="May flag test vectors or example code. Verify context.",
            category="hardcoded_secrets",
        ),

        # Weak Random Number Generation (CWE-330, CWE-338)
        AuditPattern(
            id="CRYPTO-010",
            name="Non-CSPRNG Random Number Generator",
            description="Using non-cryptographic random number generator for security-sensitive operation",
            patterns=[
                r"""\brandom\.(?:random|randint|choice|sample|randrange|getrandbits|shuffle)\b""",
                r"""\bMath\.random\s*\(""",
                r"""\brand\s*\(\s*\)""",
                r"""\bsrand\s*\(""",
                r"""\bmt_rand\s*\(""",
                r"""\bmt19937\b""",
                r"""\bRandom\s*\(\s*\)""",
                r"""\bjava\.util\.Random\b""",
            ],
            severity=Severity.HIGH,
            cwe_ids=["CWE-330", "CWE-338"],
            remediation="Use cryptographically secure PRNGs: Python secrets module, "
                        "os.urandom(), Java SecureRandom, Node.js crypto.randomBytes(), "
                        "or C/C++ RAND_bytes() from OpenSSL.",
            false_positive_notes="random module is acceptable for non-security uses (shuffling UI, simulations).",
            category="weak_random",
        ),

        # Deprecated/Broken Algorithms (CWE-327, CWE-328)
        AuditPattern(
            id="CRYPTO-020",
            name="MD5 Hash Usage",
            description="MD5 is cryptographically broken; collision attacks are trivial",
            patterns=[
                r"""\bhashlib\.md5\b""",
                r"""\bMD5\b\.(?:new|digest|hexdigest|Create)""",
                r"""MessageDigest\.getInstance\s*\(\s*['"]MD5['"]""",
                r"""\bmd5\s*\(""",
                r"""\bEVP_md5\b""",
                r"""\bcrypto\.createHash\s*\(\s*['"]md5['"]""",
            ],
            severity=Severity.HIGH,
            cwe_ids=["CWE-327", "CWE-328"],
            remediation="Replace MD5 with SHA-256 (minimum) or SHA-384/SHA-512. "
                        "MD5 is acceptable ONLY for non-security checksums (file integrity "
                        "where adversarial modification is not a threat).",
            category="weak_algorithm",
        ),
        AuditPattern(
            id="CRYPTO-021",
            name="SHA-1 Hash Usage",
            description="SHA-1 has practical collision attacks (SHAttered, 2017)",
            patterns=[
                r"""\bhashlib\.sha1\b""",
                r"""\bSHA1\b""",
                r"""MessageDigest\.getInstance\s*\(\s*['"]SHA-?1['"]""",
                r"""\bEVP_sha1\b""",
                r"""\bcrypto\.createHash\s*\(\s*['"]sha1['"]""",
            ],
            severity=Severity.HIGH,
            cwe_ids=["CWE-327", "CWE-328"],
            remediation="Replace SHA-1 with SHA-256 or stronger. SHA-1 is disallowed "
                        "for digital signatures per NIST SP 800-131A Rev 2.",
            category="weak_algorithm",
        ),
        AuditPattern(
            id="CRYPTO-022",
            name="DES Cipher Usage",
            description="DES has a 56-bit key, trivially brute-forceable since 1998",
            patterns=[
                r"""\bDES\b(?!ede|C[A-Z])""",
                r"""Cipher\.getInstance.*\bDES\b(?!/|ede)""",
                r"""\bEVP_des_\b""",
                r"""\bDES_(?:ecb|cbc|cfb|ofb)_encrypt\b""",
                r"""\bcrypto\.createCipher(?:iv)?\s*\(\s*['"]des['"]""",
            ],
            severity=Severity.CRITICAL,
            cwe_ids=["CWE-327"],
            remediation="Replace DES with AES-256. DES was withdrawn from FIPS in 2005.",
            category="weak_algorithm",
        ),
        AuditPattern(
            id="CRYPTO-023",
            name="3DES / Triple DES Usage",
            description="3DES is deprecated; 64-bit block size enables Sweet32 attack",
            patterns=[
                r"""\b3DES\b""",
                r"""\bTripleDES\b""",
                r"""\bDESede\b""",
                r"""\bTDEA\b""",
                r"""\bEVP_des_ede3\b""",
                r"""\bcrypto\.createCipher(?:iv)?\s*\(\s*['"]des-ede3['"]""",
            ],
            severity=Severity.HIGH,
            cwe_ids=["CWE-327"],
            remediation="Replace 3DES with AES-256. 3DES was disallowed after 2023 per SP 800-67 Rev 2.",
            category="weak_algorithm",
        ),
        AuditPattern(
            id="CRYPTO-024",
            name="RC4 Cipher Usage",
            description="RC4 has severe statistical biases; banned in TLS (RFC 7465)",
            patterns=[
                r"""\bRC4\b""",
                r"""\bARCFOUR\b""",
                r"""\barc4\b""",
                r"""\bEVP_rc4\b""",
            ],
            severity=Severity.CRITICAL,
            cwe_ids=["CWE-327"],
            remediation="Replace RC4 with AES-GCM or ChaCha20-Poly1305.",
            category="weak_algorithm",
        ),
        AuditPattern(
            id="CRYPTO-025",
            name="Blowfish Cipher Usage",
            description="Blowfish has a 64-bit block size and is not FIPS approved",
            patterns=[
                r"""\bBlowfish\b""",
                r"""\bBF_(?:ecb|cbc|cfb|ofb)_encrypt\b""",
                r"""\bEVP_bf_\b""",
            ],
            severity=Severity.MEDIUM,
            cwe_ids=["CWE-327"],
            remediation="Replace Blowfish with AES-256.",
            category="weak_algorithm",
        ),

        # Insecure Cipher Modes (CWE-327)
        AuditPattern(
            id="CRYPTO-030",
            name="ECB Mode Usage",
            description="ECB mode reveals patterns in ciphertext; identical plaintext blocks produce identical ciphertext",
            patterns=[
                r"""\bECB\b""",
                r"""AES/ECB""",
                r"""\bMODE_ECB\b""",
                r"""mode\s*[=:]\s*['"]?ecb['"]?""",
                r"""\bcrypto\.createCipher(?:iv)?\s*\(\s*['"]aes-\d+-ecb['"]""",
            ],
            severity=Severity.HIGH,
            cwe_ids=["CWE-327"],
            remediation="Use authenticated encryption: AES-GCM (preferred) or AES-CCM. "
                        "If AEAD is not possible, use CBC with HMAC or CTR mode.",
            category="insecure_mode",
        ),
        AuditPattern(
            id="CRYPTO-031",
            name="CBC Mode Without Authentication",
            description="CBC without HMAC is vulnerable to padding oracle attacks (POODLE, Lucky13)",
            patterns=[
                r"""(?:MODE_CBC|AES\.MODE_CBC|\.new\(.*\bCBC\b|AES/CBC)(?!.*(?:HMAC|hmac|MAC|mac|tag|authenticate))""",
                r"""AES/CBC/PKCS[57]Padding""",
                r"""(?:createCipher(?:iv)?|Cipher\.getInstance)\s*\(.*\bcbc\b""",
            ],
            severity=Severity.MEDIUM,
            cwe_ids=["CWE-327"],
            remediation="Use AES-GCM for authenticated encryption, or add HMAC-SHA-256 "
                        "authentication (Encrypt-then-MAC) to CBC mode.",
            false_positive_notes="May flag CBC used with separate HMAC. Verify authentication is present.",
            category="insecure_mode",
        ),

        # Missing Key Derivation (CWE-327)
        AuditPattern(
            id="CRYPTO-040",
            name="Raw Password as Encryption Key",
            description="Using a password directly as an encryption key without key derivation",
            patterns=[
                r"""(?:password|passphrase|passwd)\s*\.encode\s*\([^)]*\)\s*(?:[:])""",
                r"""AES\.new\s*\(\s*(?:password|passphrase|passwd)""",
                r"""Cipher\.getInstance.*\.init\s*\([^,]*,\s*new\s*SecretKeySpec\s*\(\s*(?:password|passphrase)""",
                r"""key\s*=\s*(?:password|passphrase|passwd)""",
            ],
            severity=Severity.HIGH,
            cwe_ids=["CWE-327"],
            remediation="Derive encryption keys from passwords using PBKDF2 (minimum 600,000 iterations), "
                        "Argon2id (preferred), or scrypt. Never use raw passwords as keys.",
            category="missing_kdf",
        ),

        # Insufficient Key Length (CWE-326)
        AuditPattern(
            id="CRYPTO-050",
            name="RSA Key Size Below 2048 Bits",
            description="RSA keys smaller than 2048 bits are insecure",
            patterns=[
                r"""(?:key[-_]?size|key[-_]?length|bits)\s*[=:]\s*(?:512|768|1024)\b""",
                r"""generate[-_]?(?:rsa|key)\s*\([^)]*(?:512|768|1024)\b""",
                r"""RSA\.generate\s*\(\s*(?:512|768|1024)\b""",
            ],
            severity=Severity.CRITICAL,
            cwe_ids=["CWE-326"],
            remediation="Use RSA-3072 minimum (recommended) or RSA-4096. "
                        "Consider migrating to ECDSA-P384 or ML-DSA-87 (post-quantum).",
            category="weak_key_length",
        ),
        AuditPattern(
            id="CRYPTO-051",
            name="Short Symmetric Key",
            description="Symmetric key length appears insufficient",
            patterns=[
                r"""(?:key|secret)\s*=\s*['"][^'"]{1,7}['"]""",
                r"""(?:key[-_]?length|key[-_]?size)\s*[=:]\s*(?:40|56|64)\b""",
            ],
            severity=Severity.HIGH,
            cwe_ids=["CWE-326"],
            remediation="Use AES-256 (256-bit key) for symmetric encryption. "
                        "Minimum acceptable is AES-128 (128-bit key).",
            false_positive_notes="May flag short variable names. Check if the value is actually a crypto key.",
            category="weak_key_length",
        ),

        # Certificate Validation Issues (CWE-295)
        AuditPattern(
            id="CRYPTO-060",
            name="Disabled Certificate Verification",
            description="TLS/SSL certificate verification is disabled, enabling MITM attacks",
            patterns=[
                r"""verify\s*=\s*False""",
                r"""CERT_NONE""",
                r"""SSL_VERIFY_NONE""",
                r"""ssl[-_]?verify\s*[=:]\s*(?:false|0|no|off)""",
                r"""InsecureRequestWarning""",
                r"""urllib3\.disable_warnings""",
                r"""NODE_TLS_REJECT_UNAUTHORIZED.*['"]0['"]""",
                r"""rejectUnauthorized\s*:\s*false""",
                r"""setDefaultSSLSocketFactory""",
            ],
            severity=Severity.CRITICAL,
            cwe_ids=["CWE-295"],
            remediation="Always verify TLS certificates. Use proper CA bundles. "
                        "If using self-signed certs in development, use a custom CA trust store.",
            category="certificate_validation",
        ),

        # Insecure TLS Versions (CWE-757)
        AuditPattern(
            id="CRYPTO-070",
            name="Insecure TLS/SSL Version",
            description="Using deprecated SSL/TLS version vulnerable to known attacks",
            patterns=[
                r"""\bSSLv2\b""",
                r"""\bSSLv3\b""",
                r"""\bTLSv1(?:\.0)?\b(?!\.?[12])""",
                r"""\bTLSv1\.1\b""",
                r"""PROTOCOL_SSLv2""",
                r"""PROTOCOL_SSLv3""",
                r"""PROTOCOL_TLSv1\b(?!_[12])""",
                r"""PROTOCOL_TLSv1_1""",
                r"""ssl\.PROTOCOL_TLS\b(?!v1_2)""",
                r"""TLS_1_0""",
                r"""TLS_1_1""",
                r"""MinVersion.*tls\.VersionTLS10""",
                r"""MinVersion.*tls\.VersionTLS11""",
            ],
            severity=Severity.CRITICAL,
            cwe_ids=["CWE-757"],
            remediation="Use TLS 1.2 minimum (TLS 1.3 preferred). SSLv2, SSLv3, TLS 1.0, "
                        "and TLS 1.1 are deprecated and have known vulnerabilities "
                        "(POODLE, BEAST, CRIME, etc.).",
            category="insecure_tls",
        ),

        # Dual_EC_DRBG (backdoored)
        AuditPattern(
            id="CRYPTO-080",
            name="Dual_EC_DRBG Usage",
            description="Dual_EC_DRBG has a known NSA backdoor; withdrawn from NIST standards",
            patterns=[
                r"""\bDual[-_]?EC[-_]?DRBG\b""",
                r"""\bdual[-_]?ec\b""",
            ],
            severity=Severity.CRITICAL,
            cwe_ids=["CWE-327"],
            remediation="Replace with CTR_DRBG, Hash_DRBG, or HMAC_DRBG per SP 800-90A Rev 1.",
            category="weak_algorithm",
        ),

        # Null/Empty Crypto Parameters
        AuditPattern(
            id="CRYPTO-090",
            name="Empty or Null IV/Nonce",
            description="Using empty, null, or all-zero IV/nonce, which destroys security guarantees",
            patterns=[
                r"""iv\s*=\s*(?:b['"]\\x00+['"]|bytes\s*\(\s*\d+\s*\)|b['"]\\0+['"]|['"]\\0+['"]|None|null|b['"]["'])""",
                r"""nonce\s*=\s*(?:b['"]\\x00+['"]|bytes\s*\(\s*\d+\s*\)|None|null|b['"]["'])""",
                r"""iv\s*=\s*(?:\\x00+|['"]{2}|b['"]{2})""",
            ],
            severity=Severity.HIGH,
            cwe_ids=["CWE-1204"],
            remediation="Generate a unique random IV/nonce for each encryption operation "
                        "using os.urandom() or secrets.token_bytes(). Never reuse IVs with "
                        "the same key, especially in CTR or GCM mode.",
            category="weak_parameter",
        ),

        # Timing Attack Vulnerability
        AuditPattern(
            id="CRYPTO-100",
            name="Non-Constant-Time Comparison",
            description="Using standard string/bytes comparison for secrets, enabling timing attacks",
            patterns=[
                r"""(?:mac|digest|hash|hmac|signature|token|secret|password).*==\s*""",
                r"""==.*(?:mac|digest|hash|hmac|signature|token|secret)""",
                r"""\.verify\s*\(\s*\).*==""",
            ],
            severity=Severity.MEDIUM,
            cwe_ids=["CWE-208"],
            remediation="Use constant-time comparison: hmac.compare_digest() in Python, "
                        "crypto.timingSafeEqual() in Node.js, or MessageDigest.isEqual() in Java.",
            false_positive_notes="May flag legitimate comparisons. Check if security-sensitive values are involved.",
            category="timing_attack",
        ),

        # Deprecated Python SSL
        AuditPattern(
            id="CRYPTO-110",
            name="Deprecated SSL/TLS API",
            description="Using deprecated SSL/TLS API that may default to insecure settings",
            patterns=[
                r"""\bssl\.wrap_socket\b""",
                r"""\bssl\.SSLContext\s*\(\s*ssl\.PROTOCOL_TLS\s*\)""",
                r"""\bhttplib\.HTTPSConnection\b(?!.*context)""",
            ],
            severity=Severity.MEDIUM,
            cwe_ids=["CWE-757"],
            remediation="Use ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT) or "
                        "ssl.create_default_context() which enforces certificate validation "
                        "and modern TLS versions by default.",
            category="insecure_tls",
        ),
    ]

    def __init__(self) -> None:
        self._compiled_patterns: dict[str, list[re.Pattern]] = {}
        for rule in self.AUDIT_RULES:
            self._compiled_patterns[rule.id] = [
                re.compile(p, re.IGNORECASE) for p in rule.patterns
            ]

    def scan_text(self, text: str, file_path: str = "<input>") -> dict:
        """
        Scan text for cryptographic security issues.

        Args:
            text: Source code, configuration, or documentation text.
            file_path: Optional file path for reporting.

        Returns:
            Audit report with findings, severity counts, and remediation.
        """
        findings: list[dict] = []
        lines = text.split("\n")

        for rule in self.AUDIT_RULES:
            compiled = self._compiled_patterns[rule.id]
            for line_num, line in enumerate(lines, start=1):
                for pattern in compiled:
                    matches = list(pattern.finditer(line))
                    for match in matches:
                        finding = AuditFinding(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            message=rule.description,
                            line=line_num,
                            column=match.start() + 1,
                            context=line.strip()[:200],
                            cwe_ids=rule.cwe_ids,
                            remediation=rule.remediation,
                            file_path=file_path,
                        )
                        findings.append(self._finding_to_dict(finding))

        # Deduplicate findings on same line for same rule
        seen = set()
        unique_findings = []
        for f in findings:
            key = (f["rule_id"], f["line"])
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        severity_counts = {s.value: 0 for s in Severity}
        for f in unique_findings:
            severity_counts[f["severity"]] += 1

        cwe_summary: dict[str, int] = {}
        for f in unique_findings:
            for cwe in f["cwe_ids"]:
                cwe_summary[cwe] = cwe_summary.get(cwe, 0) + 1

        # Sort by severity (critical first)
        severity_order = {s.value: i for i, s in enumerate(Severity)}
        unique_findings.sort(key=lambda f: severity_order.get(f["severity"], 99))

        return {
            "report_type": "Crypto Audit Report",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "file": file_path,
            "total_findings": len(unique_findings),
            "severity_summary": severity_counts,
            "cwe_summary": cwe_summary,
            "overall_risk": self._overall_risk(severity_counts),
            "findings": unique_findings,
            "cwe_reference": {
                "CWE-208": "Observable Timing Discrepancy",
                "CWE-295": "Improper Certificate Validation",
                "CWE-326": "Inadequate Encryption Strength",
                "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
                "CWE-328": "Use of Weak Hash",
                "CWE-1204": "Generation of Weak Initialization Vector (IV)",
                "CWE-330": "Use of Insufficiently Random Values",
                "CWE-338": "Use of Cryptographically Weak PRNG",
                "CWE-757": "Selection of Less-Secure Algorithm During Negotiation",
                "CWE-798": "Use of Hard-coded Credentials",
            },
        }

    def scan_multiple_texts(self, texts: dict[str, str]) -> dict:
        """
        Scan multiple files/texts for crypto issues.

        Args:
            texts: Dictionary mapping file paths to file contents.

        Returns:
            Combined audit report across all files.
        """
        all_findings = []
        file_summaries = []

        for file_path, content in texts.items():
            result = self.scan_text(content, file_path)
            all_findings.extend(result["findings"])
            file_summaries.append({
                "file": file_path,
                "findings": result["total_findings"],
                "severity_summary": result["severity_summary"],
            })

        severity_counts = {s.value: 0 for s in Severity}
        cwe_summary: dict[str, int] = {}
        for f in all_findings:
            severity_counts[f["severity"]] += 1
            for cwe in f["cwe_ids"]:
                cwe_summary[cwe] = cwe_summary.get(cwe, 0) + 1

        severity_order = {s.value: i for i, s in enumerate(Severity)}
        all_findings.sort(key=lambda f: severity_order.get(f["severity"], 99))

        return {
            "report_type": "Multi-File Crypto Audit Report",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "files_scanned": len(texts),
            "total_findings": len(all_findings),
            "severity_summary": severity_counts,
            "cwe_summary": cwe_summary,
            "overall_risk": self._overall_risk(severity_counts),
            "file_summaries": file_summaries,
            "findings": all_findings,
        }

    def to_sarif(self, audit_result: dict) -> dict:
        """
        Convert audit results to SARIF format for CI/CD integration.

        SARIF (Static Analysis Results Interchange Format) is the standard
        format for static analysis tools, supported by GitHub, Azure DevOps,
        and other CI/CD platforms.

        Args:
            audit_result: Result from scan_text() or scan_multiple_texts().

        Returns:
            SARIF-compliant JSON structure.
        """
        rules = []
        rule_ids_seen = set()
        for rule in self.AUDIT_RULES:
            if rule.id not in rule_ids_seen:
                rule_ids_seen.add(rule.id)
                sarif_level = {
                    Severity.CRITICAL: "error",
                    Severity.HIGH: "error",
                    Severity.MEDIUM: "warning",
                    Severity.LOW: "note",
                    Severity.INFO: "note",
                }.get(rule.severity, "warning")

                rules.append({
                    "id": rule.id,
                    "name": rule.name,
                    "shortDescription": {"text": rule.name},
                    "fullDescription": {"text": rule.description},
                    "help": {
                        "text": rule.remediation,
                        "markdown": f"**Remediation:** {rule.remediation}",
                    },
                    "defaultConfiguration": {"level": sarif_level},
                    "properties": {
                        "tags": rule.cwe_ids + [rule.category] if rule.category else rule.cwe_ids,
                    },
                })

        results = []
        for finding in audit_result.get("findings", []):
            sarif_level = {
                "critical": "error",
                "high": "error",
                "medium": "warning",
                "low": "note",
                "info": "note",
            }.get(finding["severity"], "warning")

            result = {
                "ruleId": finding["rule_id"],
                "level": sarif_level,
                "message": {"text": finding["message"]},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.get("file", "<input>"),
                            },
                            "region": {
                                "startLine": finding["line"],
                                "startColumn": finding["column"],
                            },
                        },
                    }
                ],
                "fixes": [
                    {
                        "description": {"text": finding["remediation"]},
                    }
                ] if finding.get("remediation") else [],
            }
            results.append(result)

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "crypto-tools-mcp-audit",
                            "version": "0.3.0",
                            "informationUri": "https://github.com/marc-shade/crypto-tools-mcp",
                            "rules": rules,
                        },
                    },
                    "results": results,
                },
            ],
        }

    def get_rules(self) -> dict:
        """
        Get all audit rules with descriptions and CWE mappings.

        Returns:
            Complete list of audit rules.
        """
        rules = []
        for rule in self.AUDIT_RULES:
            rules.append({
                "id": rule.id,
                "name": rule.name,
                "description": rule.description,
                "severity": rule.severity.value,
                "cwe_ids": rule.cwe_ids,
                "category": rule.category,
                "remediation": rule.remediation,
                "pattern_count": len(rule.patterns),
                "false_positive_notes": rule.false_positive_notes,
            })

        categories: dict[str, int] = {}
        for rule in self.AUDIT_RULES:
            cat = rule.category or "uncategorized"
            categories[cat] = categories.get(cat, 0) + 1

        return {
            "report_type": "Crypto Audit Rules Catalog",
            "total_rules": len(self.AUDIT_RULES),
            "categories": categories,
            "rules": rules,
        }

    def _finding_to_dict(self, finding: AuditFinding) -> dict:
        """Convert AuditFinding to dictionary."""
        return {
            "rule_id": finding.rule_id,
            "rule_name": finding.rule_name,
            "severity": finding.severity.value,
            "message": finding.message,
            "line": finding.line,
            "column": finding.column,
            "context": finding.context,
            "cwe_ids": finding.cwe_ids,
            "remediation": finding.remediation,
            "file": finding.file_path,
        }

    def _overall_risk(self, severity_counts: dict[str, int]) -> str:
        """Calculate overall risk level from severity counts."""
        if severity_counts.get("critical", 0) > 0:
            return "CRITICAL"
        if severity_counts.get("high", 0) > 0:
            return "HIGH"
        if severity_counts.get("medium", 0) > 0:
            return "MEDIUM"
        if severity_counts.get("low", 0) > 0:
            return "LOW"
        return "CLEAN"
