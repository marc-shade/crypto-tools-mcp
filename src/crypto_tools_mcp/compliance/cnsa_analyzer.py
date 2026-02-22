"""
NSA CNSA 2.0 Compliance Analyzer

Analyzes cryptographic configurations against the Commercial National Security
Algorithm Suite 2.0 requirements for National Security Systems (NSS).

References:
- CNSA 2.0: Commercial National Security Algorithm Suite 2.0 (September 2022)
- CNSSP 15: National Policy on the Use of the Advanced Encryption Standard
- NSA Cybersecurity Advisory: CNSA 2.0 and Quantum Readiness FAQ
"""

import re
import time
from dataclasses import dataclass, field
from enum import Enum


class CNSACompliance(Enum):
    """CNSA 2.0 compliance status."""
    REQUIRED = "required"
    ACCEPTABLE = "acceptable"
    TRANSITION_ONLY = "transition_only"
    NOT_COMPLIANT = "not_compliant"


class TransitionUrgency(Enum):
    """Urgency level for CNSA 2.0 transition."""
    OVERDUE = "overdue"
    IMMEDIATE = "immediate"
    NEAR_TERM = "near_term"
    PLANNED = "planned"


@dataclass
class CNSAAlgorithm:
    """CNSA 2.0 algorithm specification."""
    name: str
    category: str  # symmetric, hash, signature, kex, kem
    cnsa_version: str  # "1.0", "2.0", "both"
    compliance: CNSACompliance
    min_parameter: str = ""
    notes: str = ""
    replaces: list = field(default_factory=list)
    transition_deadline: str = ""


@dataclass
class CNSAFinding:
    """Result of a CNSA compliance check."""
    algorithm: str
    status: str  # compliant, non_compliant, transition, deprecated
    cnsa_version: str
    message: str
    remediation: str = ""
    deadline: str = ""
    urgency: str = ""


class CNSAAnalyzer:
    """
    NSA CNSA 2.0 compliance analyzer.

    Evaluates cryptographic algorithms and configurations against CNSA 2.0
    requirements for National Security Systems. Tracks transition timelines
    and provides migration guidance.
    """

    CNSA_2_0_ALGORITHMS: dict[str, CNSAAlgorithm] = {
        # Symmetric Encryption
        "AES-256": CNSAAlgorithm(
            name="AES-256", category="symmetric", cnsa_version="both",
            compliance=CNSACompliance.REQUIRED, min_parameter="256-bit key",
            notes="ONLY AES-256 is CNSA 2.0 compliant. AES-128 and AES-192 are NOT sufficient.",
        ),
        # Hash Functions
        "SHA-384": CNSAAlgorithm(
            name="SHA-384", category="hash", cnsa_version="both",
            compliance=CNSACompliance.REQUIRED, min_parameter="384-bit output",
            notes="Minimum hash for CNSA 2.0. SHA-256 is NOT sufficient for NSS.",
        ),
        "SHA-512": CNSAAlgorithm(
            name="SHA-512", category="hash", cnsa_version="2.0",
            compliance=CNSACompliance.ACCEPTABLE,
            notes="Acceptable but SHA-384 is the specified minimum.",
        ),
        # Digital Signatures (Classical - CNSA 1.0, transition)
        "ECDSA-P384": CNSAAlgorithm(
            name="ECDSA-P384", category="signature", cnsa_version="1.0",
            compliance=CNSACompliance.TRANSITION_ONLY,
            min_parameter="P-384 curve",
            notes="CNSA 1.0 approved. Being replaced by ML-DSA-87 in CNSA 2.0.",
            replaces=["ECDSA-P256", "RSA-2048"],
            transition_deadline="2033-12-31",
        ),
        "RSA-3072": CNSAAlgorithm(
            name="RSA-3072", category="signature", cnsa_version="1.0",
            compliance=CNSACompliance.TRANSITION_ONLY,
            min_parameter="3072-bit modulus",
            notes="CNSA 1.0 minimum RSA for legacy transition only. Prefer ECDSA-P384 or ML-DSA-87.",
            transition_deadline="2033-12-31",
        ),
        "RSA-4096": CNSAAlgorithm(
            name="RSA-4096", category="signature", cnsa_version="1.0",
            compliance=CNSACompliance.TRANSITION_ONLY,
            min_parameter="4096-bit modulus",
            notes="Acceptable for legacy transition only.",
            transition_deadline="2033-12-31",
        ),
        # Key Exchange (Classical - CNSA 1.0, transition)
        "ECDH-P384": CNSAAlgorithm(
            name="ECDH-P384", category="kex", cnsa_version="1.0",
            compliance=CNSACompliance.TRANSITION_ONLY,
            min_parameter="P-384 curve",
            notes="CNSA 1.0 approved. Being replaced by ML-KEM-1024 in CNSA 2.0.",
            transition_deadline="2033-12-31",
        ),
        "DH-3072": CNSAAlgorithm(
            name="DH-3072", category="kex", cnsa_version="1.0",
            compliance=CNSACompliance.TRANSITION_ONLY,
            min_parameter="3072-bit group",
            notes="Legacy transition only.",
            transition_deadline="2033-12-31",
        ),
        # Post-Quantum KEM (CNSA 2.0)
        "ML-KEM-1024": CNSAAlgorithm(
            name="ML-KEM-1024", category="kem", cnsa_version="2.0",
            compliance=CNSACompliance.REQUIRED,
            min_parameter="NIST Level 5",
            notes="Module-Lattice KEM (CRYSTALS-Kyber). ONLY ML-KEM-1024 for CNSA 2.0. "
                  "ML-KEM-512 and ML-KEM-768 are NOT sufficient.",
            replaces=["ECDH-P384", "DH-3072", "RSA key exchange"],
        ),
        # Post-Quantum Digital Signatures (CNSA 2.0)
        "ML-DSA-87": CNSAAlgorithm(
            name="ML-DSA-87", category="signature", cnsa_version="2.0",
            compliance=CNSACompliance.REQUIRED,
            min_parameter="NIST Level 5",
            notes="Module-Lattice Digital Signature (CRYSTALS-Dilithium). ONLY ML-DSA-87 "
                  "for CNSA 2.0. ML-DSA-44 and ML-DSA-65 are NOT sufficient.",
            replaces=["ECDSA-P384", "RSA-3072", "RSA-4096", "EdDSA"],
        ),
        "SLH-DSA-256s": CNSAAlgorithm(
            name="SLH-DSA-256s", category="signature", cnsa_version="2.0",
            compliance=CNSACompliance.ACCEPTABLE,
            min_parameter="NIST Level 5",
            notes="Stateless Hash-Based Signature (SPHINCS+). Alternative to ML-DSA-87. "
                  "Conservative choice based on hash function security. Small signature variant.",
        ),
        "SLH-DSA-256f": CNSAAlgorithm(
            name="SLH-DSA-256f", category="signature", cnsa_version="2.0",
            compliance=CNSACompliance.ACCEPTABLE,
            min_parameter="NIST Level 5",
            notes="Stateless Hash-Based Signature (SPHINCS+). Fast signing variant.",
        ),
    }

    # Algorithms explicitly NOT compliant with CNSA 2.0
    NON_COMPLIANT_ALGORITHMS: dict[str, dict] = {
        "AES-128": {
            "reason": "CNSA 2.0 requires AES-256. AES-128 does not provide sufficient security margin.",
            "upgrade_to": "AES-256",
        },
        "AES-192": {
            "reason": "CNSA 2.0 requires AES-256. AES-192 does not meet the requirement.",
            "upgrade_to": "AES-256",
        },
        "SHA-256": {
            "reason": "CNSA 2.0 requires SHA-384 minimum. SHA-256 output is too short for NSS.",
            "upgrade_to": "SHA-384",
        },
        "SHA-224": {
            "reason": "Insufficient for CNSA. Well below SHA-384 minimum.",
            "upgrade_to": "SHA-384",
        },
        "SHA-1": {
            "reason": "Cryptographically broken. Far below CNSA requirements.",
            "upgrade_to": "SHA-384",
        },
        "MD5": {
            "reason": "Cryptographically broken. Not acceptable for any security purpose.",
            "upgrade_to": "SHA-384",
        },
        "ECDSA-P256": {
            "reason": "P-256 does NOT meet CNSA requirements. P-384 is the minimum.",
            "upgrade_to": "ECDSA-P384 (transition) or ML-DSA-87 (target)",
        },
        "ECDH-P256": {
            "reason": "P-256 does NOT meet CNSA requirements. P-384 is the minimum.",
            "upgrade_to": "ECDH-P384 (transition) or ML-KEM-1024 (target)",
        },
        "RSA-2048": {
            "reason": "RSA-2048 is below CNSA minimum of RSA-3072.",
            "upgrade_to": "RSA-3072 (transition) or ML-DSA-87 (target)",
        },
        "RSA-1024": {
            "reason": "Completely inadequate. Well below any security threshold.",
            "upgrade_to": "ML-DSA-87",
        },
        "EdDSA-Ed25519": {
            "reason": "Ed25519 provides 128-bit security; CNSA 2.0 requires 192+ bit security.",
            "upgrade_to": "ML-DSA-87",
        },
        "DES": {
            "reason": "Broken cipher. 56-bit key.",
            "upgrade_to": "AES-256",
        },
        "3DES": {
            "reason": "Deprecated. 64-bit block size vulnerability.",
            "upgrade_to": "AES-256",
        },
        "RC4": {
            "reason": "Broken cipher. Statistical biases.",
            "upgrade_to": "AES-256-GCM",
        },
        "ML-KEM-512": {
            "reason": "CNSA 2.0 requires ML-KEM-1024. Lower parameter sets are NOT sufficient for NSS.",
            "upgrade_to": "ML-KEM-1024",
        },
        "ML-KEM-768": {
            "reason": "CNSA 2.0 requires ML-KEM-1024. ML-KEM-768 is NOT sufficient for NSS.",
            "upgrade_to": "ML-KEM-1024",
        },
        "ML-DSA-44": {
            "reason": "CNSA 2.0 requires ML-DSA-87. Lower parameter sets are NOT sufficient for NSS.",
            "upgrade_to": "ML-DSA-87",
        },
        "ML-DSA-65": {
            "reason": "CNSA 2.0 requires ML-DSA-87. ML-DSA-65 is NOT sufficient for NSS.",
            "upgrade_to": "ML-DSA-87",
        },
    }

    # CNSA 2.0 Transition Timeline
    TRANSITION_TIMELINE: list[dict] = [
        {
            "category": "Software and firmware signing",
            "deadline": "2025-12-31",
            "requirement": "Prefer ML-DSA-87; use SLH-DSA-256 as fallback",
            "details": "New software/firmware must be signed with PQC algorithms. "
                       "Dual-sign (classical + PQC) acceptable during transition.",
        },
        {
            "category": "Web browsers and servers (TLS)",
            "deadline": "2025-12-31",
            "requirement": "ML-KEM-1024 for key exchange; ML-DSA-87 for authentication",
            "details": "TLS 1.3 with PQC key exchange. Hybrid (X25519+ML-KEM) acceptable.",
        },
        {
            "category": "Cloud services and infrastructure",
            "deadline": "2025-12-31",
            "requirement": "Full CNSA 2.0 suite",
            "details": "Cloud providers must support PQC for NSS workloads.",
        },
        {
            "category": "Networking equipment (routers, switches, VPN)",
            "deadline": "2026-12-31",
            "requirement": "ML-KEM-1024 + ML-DSA-87 for IKEv2/IPsec",
            "details": "Network infrastructure must support PQC key exchange and auth.",
        },
        {
            "category": "Operating systems",
            "deadline": "2027-12-31",
            "requirement": "Native PQC support in cryptographic libraries",
            "details": "OS crypto stacks must implement FIPS 203/204/205.",
        },
        {
            "category": "Custom and niche applications",
            "deadline": "2030-12-31",
            "requirement": "Complete PQC migration",
            "details": "All remaining systems complete transition.",
        },
        {
            "category": "Full CNSA 2.0 compliance (all NSS)",
            "deadline": "2033-12-31",
            "requirement": "Classical-only algorithms fully retired",
            "details": "No classical-only cryptography in National Security Systems.",
        },
    ]

    # CNSA 1.0 vs 2.0 comparison
    CNSA_COMPARISON: list[dict] = [
        {
            "use_case": "Symmetric encryption",
            "cnsa_1_0": "AES-256",
            "cnsa_2_0": "AES-256",
            "change": "No change",
        },
        {
            "use_case": "Hashing",
            "cnsa_1_0": "SHA-384",
            "cnsa_2_0": "SHA-384",
            "change": "No change",
        },
        {
            "use_case": "Digital signatures",
            "cnsa_1_0": "ECDSA-P384, RSA-3072+",
            "cnsa_2_0": "ML-DSA-87, SLH-DSA-256",
            "change": "Classical replaced by post-quantum lattice/hash-based",
        },
        {
            "use_case": "Key exchange",
            "cnsa_1_0": "ECDH-P384, DH-3072+",
            "cnsa_2_0": "ML-KEM-1024",
            "change": "Classical DH/ECDH replaced by lattice-based KEM",
        },
        {
            "use_case": "Key encapsulation",
            "cnsa_1_0": "RSA key transport, ECDH",
            "cnsa_2_0": "ML-KEM-1024",
            "change": "New paradigm: KEM replaces key transport/agreement",
        },
    ]

    # Detection patterns for code/config scanning
    DETECTION_PATTERNS: dict[str, list[str]] = {
        "AES-128": [r"AES[-_]?128", r"aes[-_]?128", r"CALG_AES_128"],
        "AES-192": [r"AES[-_]?192", r"aes[-_]?192"],
        "AES-256": [r"AES[-_]?256", r"aes[-_]?256", r"CALG_AES_256"],
        "SHA-256": [r"\bsha[-_]?256\b", r"\bSHA[-_]?256\b", r"hashlib\.sha256"],
        "SHA-384": [r"\bsha[-_]?384\b", r"\bSHA[-_]?384\b", r"hashlib\.sha384"],
        "SHA-512": [r"\bsha[-_]?512\b", r"\bSHA[-_]?512\b"],
        "SHA-1": [r"\bsha[-_]?1\b", r"\bSHA[-_]?1\b", r"hashlib\.sha1"],
        "MD5": [r"\bmd5\b", r"\bMD5\b", r"hashlib\.md5"],
        "ECDSA-P256": [r"P-?256", r"secp256r1", r"prime256v1"],
        "ECDSA-P384": [r"P-?384", r"secp384r1"],
        "ECDH-P256": [r"ECDH.*P-?256", r"ecdh.*p-?256"],
        "ECDH-P384": [r"ECDH.*P-?384", r"ecdh.*p-?384"],
        "RSA-1024": [r"RSA.*1024", r"rsa.*1024"],
        "RSA-2048": [r"RSA.*2048", r"rsa.*2048"],
        "RSA-3072": [r"RSA.*3072", r"rsa.*3072"],
        "RSA-4096": [r"RSA.*4096", r"rsa.*4096"],
        "EdDSA-Ed25519": [r"Ed25519", r"ed25519"],
        "DES": [r"\bDES\b(?!ede|C)", r"EVP_des_"],
        "3DES": [r"\b3DES\b", r"\bTripleDES\b", r"\bDESede\b"],
        "RC4": [r"\bRC4\b", r"\barc4\b"],
        "ML-KEM-512": [r"ML[-_]KEM[-_]512", r"Kyber[-_]?512"],
        "ML-KEM-768": [r"ML[-_]KEM[-_]768", r"Kyber[-_]?768"],
        "ML-KEM-1024": [r"ML[-_]KEM[-_]1024", r"Kyber[-_]?1024"],
        "ML-DSA-44": [r"ML[-_]DSA[-_]44", r"Dilithium[-_]?2"],
        "ML-DSA-65": [r"ML[-_]DSA[-_]65", r"Dilithium[-_]?3"],
        "ML-DSA-87": [r"ML[-_]DSA[-_]87", r"Dilithium[-_]?5"],
    }

    def __init__(self) -> None:
        self._current_year = int(time.strftime("%Y"))

    def analyze_algorithm(self, algorithm_name: str) -> CNSAFinding:
        """
        Analyze a single algorithm for CNSA 2.0 compliance.

        Args:
            algorithm_name: Name of the algorithm to analyze.

        Returns:
            CNSAFinding with compliance status and guidance.
        """
        normalized = self._normalize_name(algorithm_name)

        # Check CNSA 2.0 approved algorithms
        if normalized in self.CNSA_2_0_ALGORITHMS:
            algo = self.CNSA_2_0_ALGORITHMS[normalized]
            if algo.compliance == CNSACompliance.REQUIRED:
                return CNSAFinding(
                    algorithm=algo.name,
                    status="compliant",
                    cnsa_version=algo.cnsa_version,
                    message=f"{algo.name} is CNSA 2.0 REQUIRED. {algo.notes}",
                )
            elif algo.compliance == CNSACompliance.ACCEPTABLE:
                return CNSAFinding(
                    algorithm=algo.name,
                    status="compliant",
                    cnsa_version=algo.cnsa_version,
                    message=f"{algo.name} is CNSA 2.0 ACCEPTABLE. {algo.notes}",
                )
            elif algo.compliance == CNSACompliance.TRANSITION_ONLY:
                urgency = self._calculate_urgency(algo.transition_deadline)
                return CNSAFinding(
                    algorithm=algo.name,
                    status="transition",
                    cnsa_version=algo.cnsa_version,
                    message=f"{algo.name} is CNSA 1.0 only; acceptable for TRANSITION. {algo.notes}",
                    remediation=f"Migrate to: {', '.join(algo.replaces) if algo.replaces else 'PQC equivalent'}",
                    deadline=algo.transition_deadline,
                    urgency=urgency.value,
                )

        # Check non-compliant algorithms
        if normalized in self.NON_COMPLIANT_ALGORITHMS:
            info = self.NON_COMPLIANT_ALGORITHMS[normalized]
            return CNSAFinding(
                algorithm=normalized,
                status="non_compliant",
                cnsa_version="neither",
                message=f"{normalized} is NOT CNSA compliant. {info['reason']}",
                remediation=f"Replace with: {info['upgrade_to']}",
                urgency="immediate",
            )

        return CNSAFinding(
            algorithm=algorithm_name,
            status="non_compliant",
            cnsa_version="unknown",
            message=f"Algorithm '{algorithm_name}' is not recognized in the CNSA database.",
            remediation="Use only CNSA 2.0 approved algorithms for National Security Systems.",
        )

    def analyze_multiple(self, algorithms: list[str]) -> dict:
        """
        Analyze multiple algorithms for CNSA 2.0 compliance.

        Args:
            algorithms: List of algorithm names.

        Returns:
            Comprehensive CNSA compliance analysis.
        """
        findings = []
        compliant_count = 0
        transition_count = 0
        non_compliant_count = 0

        for algo in algorithms:
            finding = self.analyze_algorithm(algo)
            findings.append({
                "algorithm": finding.algorithm,
                "status": finding.status,
                "cnsa_version": finding.cnsa_version,
                "message": finding.message,
                "remediation": finding.remediation,
                "deadline": finding.deadline,
                "urgency": finding.urgency,
            })
            if finding.status == "compliant":
                compliant_count += 1
            elif finding.status == "transition":
                transition_count += 1
            else:
                non_compliant_count += 1

        overall = "COMPLIANT"
        if non_compliant_count > 0:
            overall = "NON_COMPLIANT"
        elif transition_count > 0:
            overall = "TRANSITION_REQUIRED"

        return {
            "report_type": "CNSA 2.0 Compliance Analysis",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "standard": "NSA CNSA 2.0 (Commercial National Security Algorithm Suite)",
            "overall_status": overall,
            "summary": {
                "total_algorithms": len(algorithms),
                "compliant": compliant_count,
                "transition_only": transition_count,
                "non_compliant": non_compliant_count,
            },
            "findings": findings,
            "references": [
                "CNSA 2.0 (NSA, September 2022)",
                "CNSSP 15: National Policy on AES Usage",
                "NSA Cybersecurity Advisory: CNSA 2.0 FAQ",
            ],
        }

    def scan_text(self, text: str) -> dict:
        """
        Scan text/code for algorithm usage and check CNSA 2.0 compliance.

        Args:
            text: Source code, configuration, or documentation text.

        Returns:
            CNSA compliance scan results.
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

        findings = []
        for algo_name, locations in detected.items():
            result = self.analyze_algorithm(algo_name)
            findings.append({
                "algorithm": algo_name,
                "occurrences": len(locations),
                "locations": locations[:10],
                "cnsa_status": result.status,
                "message": result.message,
                "remediation": result.remediation,
                "deadline": result.deadline,
            })

        status_order = {"non_compliant": 0, "transition": 1, "compliant": 2}
        findings.sort(key=lambda f: status_order.get(f["cnsa_status"], 3))

        non_compliant = [f for f in findings if f["cnsa_status"] == "non_compliant"]
        transition = [f for f in findings if f["cnsa_status"] == "transition"]

        return {
            "report_type": "CNSA 2.0 Code Scan",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "total_algorithms_detected": len(detected),
            "overall_status": "NON_COMPLIANT" if non_compliant else (
                "TRANSITION_REQUIRED" if transition else "COMPLIANT"
            ),
            "findings": findings,
        }

    def get_transition_timeline(self) -> dict:
        """
        Get the CNSA 2.0 transition timeline with urgency assessments.

        Returns:
            Timeline with deadlines and urgency levels.
        """
        timeline = []
        for entry in self.TRANSITION_TIMELINE:
            deadline_year = int(entry["deadline"][:4])
            if deadline_year < self._current_year:
                urgency = "OVERDUE"
            elif deadline_year == self._current_year:
                urgency = "DUE_NOW"
            elif deadline_year <= self._current_year + 1:
                urgency = "IMMEDIATE"
            elif deadline_year <= self._current_year + 3:
                urgency = "NEAR_TERM"
            else:
                urgency = "PLANNED"

            timeline.append({
                **entry,
                "urgency": urgency,
                "years_remaining": max(0, deadline_year - self._current_year),
            })

        return {
            "report_type": "CNSA 2.0 Transition Timeline",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "current_year": self._current_year,
            "timeline": timeline,
            "key_dates": {
                "software_signing": "2025",
                "web_tls": "2025",
                "cloud_services": "2025",
                "networking": "2026",
                "operating_systems": "2027",
                "niche_applications": "2030",
                "full_compliance": "2033",
            },
        }

    def get_cnsa_comparison(self) -> dict:
        """
        Get CNSA 1.0 vs 2.0 comparison showing what changed.

        Returns:
            Side-by-side comparison of CNSA versions.
        """
        return {
            "report_type": "CNSA 1.0 vs 2.0 Comparison",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "key_change": "CNSA 2.0 replaces classical public-key cryptography with "
                          "post-quantum algorithms based on lattice and hash problems. "
                          "Symmetric (AES-256) and hash (SHA-384) remain unchanged.",
            "comparison": self.CNSA_COMPARISON,
            "summary": {
                "unchanged": ["AES-256 (symmetric)", "SHA-384 (hash)"],
                "replaced": [
                    "ECDSA/RSA signatures -> ML-DSA-87 (lattice-based)",
                    "ECDH/DH key exchange -> ML-KEM-1024 (lattice-based KEM)",
                ],
                "new_in_2_0": [
                    "ML-KEM-1024 (FIPS 203) - Post-quantum key encapsulation",
                    "ML-DSA-87 (FIPS 204) - Post-quantum digital signatures",
                    "SLH-DSA-256 (FIPS 205) - Hash-based signature fallback",
                ],
                "removed_from_1_0": [
                    "ECDSA-P384 (transition use only)",
                    "ECDH-P384 (transition use only)",
                    "RSA-3072+ (transition use only)",
                    "DH-3072+ (transition use only)",
                ],
            },
        }

    def assess_crypto_agility(self, current_algorithms: list[str]) -> dict:
        """
        Assess how easily a system can transition to CNSA 2.0.

        Crypto agility measures the ability to swap cryptographic algorithms
        without major architectural changes.

        Args:
            current_algorithms: List of currently deployed algorithms.

        Returns:
            Crypto agility assessment with migration recommendations.
        """
        findings = [self.analyze_algorithm(a) for a in current_algorithms]

        # Categorize current state
        pqc_ready = [f for f in findings if f.status == "compliant" and f.cnsa_version == "2.0"]
        classical_cnsa = [f for f in findings if f.status == "transition"]
        non_compliant = [f for f in findings if f.status == "non_compliant"]
        symmetric_hash_ok = [
            f for f in findings
            if f.status == "compliant" and f.algorithm in ("AES-256", "SHA-384", "SHA-512")
        ]

        total = len(current_algorithms) if current_algorithms else 1

        # Calculate agility score (0-100)
        score = 0.0
        if symmetric_hash_ok:
            score += 25.0  # Symmetric/hash baseline is correct
        pqc_fraction = len(pqc_ready) / total
        score += pqc_fraction * 40.0  # PQC adoption
        classical_fraction = len(classical_cnsa) / total
        score += classical_fraction * 20.0  # At least CNSA 1.0 level
        if not non_compliant:
            score += 15.0  # No broken/weak algorithms

        score = min(100.0, round(score, 1))

        if score >= 80:
            agility_level = "HIGH"
            assessment = "System is well-positioned for CNSA 2.0 transition."
        elif score >= 50:
            agility_level = "MODERATE"
            assessment = "System has some CNSA-compliant algorithms but needs migration work."
        elif score >= 25:
            agility_level = "LOW"
            assessment = "Significant migration effort required for CNSA 2.0 compliance."
        else:
            agility_level = "CRITICAL"
            assessment = "System uses weak or broken algorithms. Immediate remediation required."

        # Build migration roadmap
        roadmap = []
        if non_compliant:
            roadmap.append({
                "priority": 1,
                "action": "Replace non-compliant algorithms",
                "algorithms": [f.algorithm for f in non_compliant],
                "urgency": "IMMEDIATE",
                "effort": "HIGH" if len(non_compliant) > 3 else "MEDIUM",
            })
        if classical_cnsa:
            roadmap.append({
                "priority": 2,
                "action": "Plan PQC migration for classical CNSA 1.0 algorithms",
                "algorithms": [f.algorithm for f in classical_cnsa],
                "urgency": "NEAR_TERM",
                "effort": "HIGH",
                "details": "Implement hybrid (classical + PQC) as intermediate step",
            })
        if not pqc_ready:
            roadmap.append({
                "priority": 3,
                "action": "Adopt post-quantum algorithms",
                "algorithms": ["ML-KEM-1024", "ML-DSA-87"],
                "urgency": "PLANNED",
                "effort": "HIGH",
                "details": "Requires PQC library support (liboqs, PQClean, or native)",
            })
        if not symmetric_hash_ok:
            roadmap.append({
                "priority": 1,
                "action": "Upgrade symmetric/hash to CNSA requirements",
                "algorithms": ["AES-256", "SHA-384"],
                "urgency": "IMMEDIATE",
                "effort": "LOW",
            })

        return {
            "report_type": "Crypto Agility Assessment",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "agility_score": score,
            "agility_level": agility_level,
            "assessment": assessment,
            "current_state": {
                "total_algorithms": len(current_algorithms),
                "pqc_ready": len(pqc_ready),
                "classical_cnsa_1": len(classical_cnsa),
                "non_compliant": len(non_compliant),
                "symmetric_hash_ok": len(symmetric_hash_ok),
            },
            "migration_roadmap": roadmap,
            "recommendations": [
                "Implement cryptographic abstraction layers for algorithm swappability",
                "Use hybrid key exchange (classical + PQC) during transition",
                "Dual-sign critical artifacts with both classical and PQC signatures",
                "Test PQC performance impact (larger keys, slower operations)",
                "Update certificate chains to support PQC algorithms",
                "Coordinate with PKI/CA infrastructure for PQC certificate issuance",
            ],
        }

    def generate_gap_analysis(self, algorithms: list[str]) -> dict:
        """
        Generate a comprehensive CNSA 2.0 gap analysis.

        Args:
            algorithms: Currently deployed algorithms.

        Returns:
            Full gap analysis with prioritized remediation plan.
        """
        analysis = self.analyze_multiple(algorithms)
        agility = self.assess_crypto_agility(algorithms)
        timeline = self.get_transition_timeline()
        comparison = self.get_cnsa_comparison()

        # Determine gaps per CNSA 2.0 category
        gaps = {
            "symmetric": {"required": "AES-256", "status": "gap", "current": []},
            "hash": {"required": "SHA-384", "status": "gap", "current": []},
            "signature": {"required": "ML-DSA-87 (or SLH-DSA-256)", "status": "gap", "current": []},
            "key_encapsulation": {"required": "ML-KEM-1024", "status": "gap", "current": []},
        }

        for algo_name in algorithms:
            normalized = self._normalize_name(algo_name)
            if normalized == "AES-256":
                gaps["symmetric"]["status"] = "met"
                gaps["symmetric"]["current"].append(normalized)
            elif normalized in ("AES-128", "AES-192"):
                gaps["symmetric"]["current"].append(normalized)
            elif normalized in ("SHA-384", "SHA-512"):
                gaps["hash"]["status"] = "met"
                gaps["hash"]["current"].append(normalized)
            elif normalized in ("SHA-256", "SHA-224", "SHA-1", "MD5"):
                gaps["hash"]["current"].append(normalized)
            elif normalized in ("ML-DSA-87", "SLH-DSA-256s", "SLH-DSA-256f"):
                gaps["signature"]["status"] = "met"
                gaps["signature"]["current"].append(normalized)
            elif normalized in ("ECDSA-P384", "RSA-3072", "RSA-4096"):
                if gaps["signature"]["status"] == "gap":
                    gaps["signature"]["status"] = "transition"
                gaps["signature"]["current"].append(normalized)
            elif normalized == "ML-KEM-1024":
                gaps["key_encapsulation"]["status"] = "met"
                gaps["key_encapsulation"]["current"].append(normalized)
            elif normalized in ("ECDH-P384", "DH-3072"):
                if gaps["key_encapsulation"]["status"] == "gap":
                    gaps["key_encapsulation"]["status"] = "transition"
                gaps["key_encapsulation"]["current"].append(normalized)

        open_gaps = {k: v for k, v in gaps.items() if v["status"] != "met"}

        return {
            "report_type": "CNSA 2.0 Gap Analysis",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "executive_summary": self._gap_summary(gaps, agility),
            "overall_compliance": analysis["overall_status"],
            "algorithm_analysis": analysis,
            "crypto_agility": agility,
            "gaps": gaps,
            "open_gap_count": len(open_gaps),
            "transition_timeline": timeline,
            "cnsa_version_comparison": comparison,
            "policy_reference": "CNSSP 15 (National Policy on AES)",
        }

    def _normalize_name(self, name: str) -> str:
        """Normalize algorithm name for lookup."""
        if name in self.CNSA_2_0_ALGORITHMS or name in self.NON_COMPLIANT_ALGORITHMS:
            return name

        name_upper = name.upper().replace(" ", "-").replace("_", "-")
        all_algos = {**{k.upper().replace("_", "-"): k for k in self.CNSA_2_0_ALGORITHMS},
                     **{k.upper().replace("_", "-"): k for k in self.NON_COMPLIANT_ALGORITHMS}}

        if name_upper in all_algos:
            return all_algos[name_upper]

        aliases = {
            "AES": "AES-256",
            "SHA256": "SHA-256",
            "SHA384": "SHA-384",
            "SHA512": "SHA-512",
            "SHA1": "SHA-1",
            "P256": "ECDSA-P256",
            "P384": "ECDSA-P384",
            "P521": "ECDSA-P521",
            "KYBER512": "ML-KEM-512",
            "KYBER768": "ML-KEM-768",
            "KYBER1024": "ML-KEM-1024",
            "KYBER": "ML-KEM-1024",
            "DILITHIUM2": "ML-DSA-44",
            "DILITHIUM3": "ML-DSA-65",
            "DILITHIUM5": "ML-DSA-87",
            "DILITHIUM": "ML-DSA-87",
            "CRYSTALS-KYBER": "ML-KEM-1024",
            "CRYSTALS-DILITHIUM": "ML-DSA-87",
            "SPHINCS+": "SLH-DSA-256s",
            "ED25519": "EdDSA-Ed25519",
            "TRIPLEDES": "3DES",
            "TRIPLE-DES": "3DES",
            "DESEDE": "3DES",
        }
        return aliases.get(name_upper, name)

    def _calculate_urgency(self, deadline: str) -> TransitionUrgency:
        """Calculate urgency based on deadline."""
        if not deadline:
            return TransitionUrgency.PLANNED
        deadline_year = int(deadline[:4])
        diff = deadline_year - self._current_year
        if diff < 0:
            return TransitionUrgency.OVERDUE
        elif diff == 0:
            return TransitionUrgency.IMMEDIATE
        elif diff <= 2:
            return TransitionUrgency.NEAR_TERM
        return TransitionUrgency.PLANNED

    def _gap_summary(self, gaps: dict, agility: dict) -> str:
        """Generate executive summary for gap analysis."""
        met = sum(1 for v in gaps.values() if v["status"] == "met")
        transition = sum(1 for v in gaps.values() if v["status"] == "transition")
        gap = sum(1 for v in gaps.values() if v["status"] == "gap")
        total = len(gaps)

        lines = [
            f"CNSA 2.0 Gap Analysis: {met}/{total} requirements met, "
            f"{transition} in transition, {gap} open gap(s).",
            f"Crypto Agility Score: {agility['agility_score']}/100 ({agility['agility_level']}).",
        ]

        if gap > 0:
            gap_names = [k for k, v in gaps.items() if v["status"] == "gap"]
            lines.append(
                f"CRITICAL GAPS in: {', '.join(gap_names)}. "
                "These categories have no CNSA-compliant algorithm deployed."
            )

        if transition > 0:
            lines.append(
                "Some categories use CNSA 1.0 algorithms acceptable for transition but "
                "must migrate to PQC algorithms per CNSA 2.0 timeline."
            )

        return " ".join(lines)
