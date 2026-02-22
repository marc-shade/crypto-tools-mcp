"""
Post-Quantum Cryptography Readiness Assessment

Evaluates cryptographic posture for quantum computing threats per
NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA).

References:
- FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)
- FIPS 204: Module-Lattice-Based Digital Signature Algorithm (ML-DSA)
- FIPS 205: Stateless Hash-Based Digital Signature Algorithm (SLH-DSA)
- OMB M-23-02: Migrating to Post-Quantum Cryptography
- NIST IR 8413: Status Report on the Third Round of the NIST PQC Process
"""

import time
from dataclasses import dataclass
from enum import Enum


class QuantumVulnerability(Enum):
    """Quantum vulnerability classification."""
    IMMUNE = "immune"
    REDUCED = "reduced"
    BROKEN = "broken"
    NOT_APPLICABLE = "not_applicable"


class PQCCategory(Enum):
    """Post-quantum algorithm category."""
    KEM = "key_encapsulation"
    SIGNATURE = "digital_signature"
    HASH_SIGNATURE = "hash_based_signature"


@dataclass
class PQCAlgorithm:
    """NIST post-quantum cryptography standard."""
    name: str
    category: PQCCategory
    fips_standard: str
    nist_level: int  # 1, 2, 3, 4, or 5
    security_bits_classical: int
    security_bits_quantum: int
    public_key_size: int  # bytes
    secret_key_size: int  # bytes
    ciphertext_or_signature_size: int  # bytes
    underlying_problem: str
    notes: str = ""


@dataclass
class QuantumRiskEntry:
    """Quantum risk assessment for a classical algorithm."""
    algorithm: str
    vulnerability: QuantumVulnerability
    attack: str
    quantum_security_bits: int
    classical_security_bits: int
    migration_target: str
    urgency: str


class PQCReadinessAssessor:
    """
    Post-Quantum Cryptography readiness assessment engine.

    Evaluates current cryptographic deployments for quantum vulnerability,
    calculates quantum risk scores, and generates migration roadmaps
    per NIST FIPS 203/204/205 and OMB M-23-02.
    """

    # NIST PQC Standards (FIPS 203, 204, 205)
    PQC_STANDARDS: dict[str, PQCAlgorithm] = {
        # FIPS 203: ML-KEM (Module-Lattice Key Encapsulation Mechanism)
        "ML-KEM-512": PQCAlgorithm(
            name="ML-KEM-512", category=PQCCategory.KEM,
            fips_standard="FIPS 203", nist_level=1,
            security_bits_classical=128, security_bits_quantum=128,
            public_key_size=800, secret_key_size=1632,
            ciphertext_or_signature_size=768,
            underlying_problem="Module Learning With Errors (MLWE)",
            notes="NIST Level 1. Suitable for general use. NOT CNSA 2.0 compliant.",
        ),
        "ML-KEM-768": PQCAlgorithm(
            name="ML-KEM-768", category=PQCCategory.KEM,
            fips_standard="FIPS 203", nist_level=3,
            security_bits_classical=192, security_bits_quantum=192,
            public_key_size=1184, secret_key_size=2400,
            ciphertext_or_signature_size=1088,
            underlying_problem="Module Learning With Errors (MLWE)",
            notes="NIST Level 3. Good balance of security and performance.",
        ),
        "ML-KEM-1024": PQCAlgorithm(
            name="ML-KEM-1024", category=PQCCategory.KEM,
            fips_standard="FIPS 203", nist_level=5,
            security_bits_classical=256, security_bits_quantum=256,
            public_key_size=1568, secret_key_size=3168,
            ciphertext_or_signature_size=1568,
            underlying_problem="Module Learning With Errors (MLWE)",
            notes="NIST Level 5. CNSA 2.0 REQUIRED for National Security Systems.",
        ),
        # FIPS 204: ML-DSA (Module-Lattice Digital Signature Algorithm)
        "ML-DSA-44": PQCAlgorithm(
            name="ML-DSA-44", category=PQCCategory.SIGNATURE,
            fips_standard="FIPS 204", nist_level=2,
            security_bits_classical=128, security_bits_quantum=128,
            public_key_size=1312, secret_key_size=2560,
            ciphertext_or_signature_size=2420,
            underlying_problem="Module Learning With Errors (MLWE) / Module Short Integer Solution (MSIS)",
            notes="NIST Level 2. Suitable for general use.",
        ),
        "ML-DSA-65": PQCAlgorithm(
            name="ML-DSA-65", category=PQCCategory.SIGNATURE,
            fips_standard="FIPS 204", nist_level=3,
            security_bits_classical=192, security_bits_quantum=192,
            public_key_size=1952, secret_key_size=4032,
            ciphertext_or_signature_size=3309,
            underlying_problem="Module Learning With Errors (MLWE) / Module Short Integer Solution (MSIS)",
            notes="NIST Level 3. Good balance of security and performance.",
        ),
        "ML-DSA-87": PQCAlgorithm(
            name="ML-DSA-87", category=PQCCategory.SIGNATURE,
            fips_standard="FIPS 204", nist_level=5,
            security_bits_classical=256, security_bits_quantum=256,
            public_key_size=2592, secret_key_size=4896,
            ciphertext_or_signature_size=4627,
            underlying_problem="Module Learning With Errors (MLWE) / Module Short Integer Solution (MSIS)",
            notes="NIST Level 5. CNSA 2.0 REQUIRED for National Security Systems.",
        ),
        # FIPS 205: SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
        "SLH-DSA-128s": PQCAlgorithm(
            name="SLH-DSA-128s", category=PQCCategory.HASH_SIGNATURE,
            fips_standard="FIPS 205", nist_level=1,
            security_bits_classical=128, security_bits_quantum=128,
            public_key_size=32, secret_key_size=64,
            ciphertext_or_signature_size=7856,
            underlying_problem="Hash function security (second preimage resistance)",
            notes="NIST Level 1. Small keys but large signatures. Conservative security assumption.",
        ),
        "SLH-DSA-128f": PQCAlgorithm(
            name="SLH-DSA-128f", category=PQCCategory.HASH_SIGNATURE,
            fips_standard="FIPS 205", nist_level=1,
            security_bits_classical=128, security_bits_quantum=128,
            public_key_size=32, secret_key_size=64,
            ciphertext_or_signature_size=17088,
            underlying_problem="Hash function security (second preimage resistance)",
            notes="NIST Level 1. Fast signing variant; larger signatures than 's' variant.",
        ),
        "SLH-DSA-192s": PQCAlgorithm(
            name="SLH-DSA-192s", category=PQCCategory.HASH_SIGNATURE,
            fips_standard="FIPS 205", nist_level=3,
            security_bits_classical=192, security_bits_quantum=192,
            public_key_size=48, secret_key_size=96,
            ciphertext_or_signature_size=16224,
            underlying_problem="Hash function security (second preimage resistance)",
            notes="NIST Level 3. Small keys; conservative assumption.",
        ),
        "SLH-DSA-192f": PQCAlgorithm(
            name="SLH-DSA-192f", category=PQCCategory.HASH_SIGNATURE,
            fips_standard="FIPS 205", nist_level=3,
            security_bits_classical=192, security_bits_quantum=192,
            public_key_size=48, secret_key_size=96,
            ciphertext_or_signature_size=35664,
            underlying_problem="Hash function security (second preimage resistance)",
            notes="NIST Level 3. Fast signing variant.",
        ),
        "SLH-DSA-256s": PQCAlgorithm(
            name="SLH-DSA-256s", category=PQCCategory.HASH_SIGNATURE,
            fips_standard="FIPS 205", nist_level=5,
            security_bits_classical=256, security_bits_quantum=256,
            public_key_size=64, secret_key_size=128,
            ciphertext_or_signature_size=29792,
            underlying_problem="Hash function security (second preimage resistance)",
            notes="NIST Level 5. CNSA 2.0 acceptable. Conservative security assumption.",
        ),
        "SLH-DSA-256f": PQCAlgorithm(
            name="SLH-DSA-256f", category=PQCCategory.HASH_SIGNATURE,
            fips_standard="FIPS 205", nist_level=5,
            security_bits_classical=256, security_bits_quantum=256,
            public_key_size=64, secret_key_size=128,
            ciphertext_or_signature_size=49856,
            underlying_problem="Hash function security (second preimage resistance)",
            notes="NIST Level 5. CNSA 2.0 acceptable. Fast signing variant.",
        ),
    }

    # Quantum vulnerability of classical algorithms
    QUANTUM_VULNERABILITY: dict[str, QuantumRiskEntry] = {
        "RSA-2048": QuantumRiskEntry(
            algorithm="RSA-2048", vulnerability=QuantumVulnerability.BROKEN,
            attack="Shor's algorithm (polynomial-time integer factoring)",
            quantum_security_bits=0, classical_security_bits=112,
            migration_target="ML-DSA-87 (signatures) or ML-KEM-1024 (key transport)",
            urgency="HIGH",
        ),
        "RSA-3072": QuantumRiskEntry(
            algorithm="RSA-3072", vulnerability=QuantumVulnerability.BROKEN,
            attack="Shor's algorithm",
            quantum_security_bits=0, classical_security_bits=128,
            migration_target="ML-DSA-87 or ML-KEM-1024",
            urgency="HIGH",
        ),
        "RSA-4096": QuantumRiskEntry(
            algorithm="RSA-4096", vulnerability=QuantumVulnerability.BROKEN,
            attack="Shor's algorithm",
            quantum_security_bits=0, classical_security_bits=152,
            migration_target="ML-DSA-87 or ML-KEM-1024",
            urgency="HIGH",
        ),
        "ECDSA-P256": QuantumRiskEntry(
            algorithm="ECDSA-P256", vulnerability=QuantumVulnerability.BROKEN,
            attack="Shor's algorithm (discrete log on elliptic curves)",
            quantum_security_bits=0, classical_security_bits=128,
            migration_target="ML-DSA-65 or ML-DSA-87",
            urgency="HIGH",
        ),
        "ECDSA-P384": QuantumRiskEntry(
            algorithm="ECDSA-P384", vulnerability=QuantumVulnerability.BROKEN,
            attack="Shor's algorithm",
            quantum_security_bits=0, classical_security_bits=192,
            migration_target="ML-DSA-87",
            urgency="HIGH",
        ),
        "ECDSA-P521": QuantumRiskEntry(
            algorithm="ECDSA-P521", vulnerability=QuantumVulnerability.BROKEN,
            attack="Shor's algorithm",
            quantum_security_bits=0, classical_security_bits=256,
            migration_target="ML-DSA-87",
            urgency="HIGH",
        ),
        "EdDSA-Ed25519": QuantumRiskEntry(
            algorithm="EdDSA-Ed25519", vulnerability=QuantumVulnerability.BROKEN,
            attack="Shor's algorithm",
            quantum_security_bits=0, classical_security_bits=128,
            migration_target="ML-DSA-65 or ML-DSA-87",
            urgency="HIGH",
        ),
        "EdDSA-Ed448": QuantumRiskEntry(
            algorithm="EdDSA-Ed448", vulnerability=QuantumVulnerability.BROKEN,
            attack="Shor's algorithm",
            quantum_security_bits=0, classical_security_bits=224,
            migration_target="ML-DSA-87",
            urgency="HIGH",
        ),
        "ECDH-P256": QuantumRiskEntry(
            algorithm="ECDH-P256", vulnerability=QuantumVulnerability.BROKEN,
            attack="Shor's algorithm",
            quantum_security_bits=0, classical_security_bits=128,
            migration_target="ML-KEM-768 or ML-KEM-1024",
            urgency="HIGH",
        ),
        "ECDH-P384": QuantumRiskEntry(
            algorithm="ECDH-P384", vulnerability=QuantumVulnerability.BROKEN,
            attack="Shor's algorithm",
            quantum_security_bits=0, classical_security_bits=192,
            migration_target="ML-KEM-1024",
            urgency="HIGH",
        ),
        "DH-2048": QuantumRiskEntry(
            algorithm="DH-2048", vulnerability=QuantumVulnerability.BROKEN,
            attack="Shor's algorithm (discrete log)",
            quantum_security_bits=0, classical_security_bits=112,
            migration_target="ML-KEM-1024",
            urgency="CRITICAL",
        ),
        "DH-3072": QuantumRiskEntry(
            algorithm="DH-3072", vulnerability=QuantumVulnerability.BROKEN,
            attack="Shor's algorithm",
            quantum_security_bits=0, classical_security_bits=128,
            migration_target="ML-KEM-1024",
            urgency="HIGH",
        ),
        "DSA-2048": QuantumRiskEntry(
            algorithm="DSA-2048", vulnerability=QuantumVulnerability.BROKEN,
            attack="Shor's algorithm",
            quantum_security_bits=0, classical_security_bits=112,
            migration_target="ML-DSA-87",
            urgency="CRITICAL",
        ),
        "AES-128": QuantumRiskEntry(
            algorithm="AES-128", vulnerability=QuantumVulnerability.REDUCED,
            attack="Grover's algorithm (quadratic speedup for brute force)",
            quantum_security_bits=64, classical_security_bits=128,
            migration_target="AES-256 (provides 128-bit quantum security)",
            urgency="MEDIUM",
        ),
        "AES-192": QuantumRiskEntry(
            algorithm="AES-192", vulnerability=QuantumVulnerability.REDUCED,
            attack="Grover's algorithm",
            quantum_security_bits=96, classical_security_bits=192,
            migration_target="AES-256",
            urgency="LOW",
        ),
        "AES-256": QuantumRiskEntry(
            algorithm="AES-256", vulnerability=QuantumVulnerability.REDUCED,
            attack="Grover's algorithm",
            quantum_security_bits=128, classical_security_bits=256,
            migration_target="No migration needed; 128-bit quantum security is sufficient",
            urgency="NONE",
        ),
        "SHA-256": QuantumRiskEntry(
            algorithm="SHA-256", vulnerability=QuantumVulnerability.REDUCED,
            attack="Grover's algorithm (collision: unchanged; preimage: halved)",
            quantum_security_bits=128, classical_security_bits=128,
            migration_target="SHA-384 or SHA-512 for extra margin",
            urgency="LOW",
        ),
        "SHA-384": QuantumRiskEntry(
            algorithm="SHA-384", vulnerability=QuantumVulnerability.REDUCED,
            attack="Grover's algorithm",
            quantum_security_bits=192, classical_security_bits=192,
            migration_target="No migration needed",
            urgency="NONE",
        ),
        "SHA-512": QuantumRiskEntry(
            algorithm="SHA-512", vulnerability=QuantumVulnerability.REDUCED,
            attack="Grover's algorithm",
            quantum_security_bits=256, classical_security_bits=256,
            migration_target="No migration needed",
            urgency="NONE",
        ),
        "HMAC-SHA-256": QuantumRiskEntry(
            algorithm="HMAC-SHA-256", vulnerability=QuantumVulnerability.REDUCED,
            attack="Grover's algorithm",
            quantum_security_bits=128, classical_security_bits=128,
            migration_target="HMAC-SHA-384 for extra margin",
            urgency="LOW",
        ),
    }

    # NIST PQC Round 4 candidates (under evaluation)
    ROUND_4_CANDIDATES: list[dict] = [
        {
            "name": "BIKE",
            "type": "KEM",
            "underlying_problem": "Quasi-Cyclic Moderate Density Parity-Check (QC-MDPC) codes",
            "status": "Under evaluation",
            "notes": "Code-based KEM. Competitive performance. Decapsulation failure rate is a concern.",
        },
        {
            "name": "Classic McEliece",
            "type": "KEM",
            "underlying_problem": "Binary Goppa codes",
            "status": "Under evaluation",
            "notes": "Very large public keys (~1MB) but minimal ciphertext. "
                     "Conservative choice; McEliece system unbroken for 40+ years.",
        },
        {
            "name": "HQC",
            "type": "KEM",
            "underlying_problem": "Quasi-Cyclic codes with Hamming metric",
            "status": "Under evaluation",
            "notes": "Code-based KEM. Simpler security proof than BIKE.",
        },
        {
            "name": "SIKE/SIDH",
            "type": "KEM",
            "underlying_problem": "Supersingular isogeny",
            "status": "BROKEN (August 2022)",
            "notes": "Devastating attack by Castryck-Decru reduced security to zero. "
                     "WITHDRAWN from consideration. Do NOT use.",
        },
    ]

    def __init__(self) -> None:
        self._current_year = int(time.strftime("%Y"))

    def assess_algorithm(self, algorithm_name: str) -> dict:
        """
        Assess quantum readiness of a single algorithm.

        Args:
            algorithm_name: Algorithm to assess.

        Returns:
            Quantum readiness assessment with risk level and migration target.
        """
        normalized = self._normalize_name(algorithm_name)

        # Check if it's a PQC standard
        if normalized in self.PQC_STANDARDS:
            pqc = self.PQC_STANDARDS[normalized]
            return {
                "algorithm": pqc.name,
                "is_post_quantum": True,
                "quantum_safe": True,
                "fips_standard": pqc.fips_standard,
                "nist_level": pqc.nist_level,
                "security_bits_classical": pqc.security_bits_classical,
                "security_bits_quantum": pqc.security_bits_quantum,
                "underlying_problem": pqc.underlying_problem,
                "key_sizes": {
                    "public_key_bytes": pqc.public_key_size,
                    "secret_key_bytes": pqc.secret_key_size,
                    "ciphertext_or_signature_bytes": pqc.ciphertext_or_signature_size,
                },
                "notes": pqc.notes,
                "quantum_risk_score": 0,
                "action": "No migration needed; this is a post-quantum algorithm.",
            }

        # Check quantum vulnerability
        if normalized in self.QUANTUM_VULNERABILITY:
            risk = self.QUANTUM_VULNERABILITY[normalized]
            risk_score = self._calculate_risk_score(risk)

            return {
                "algorithm": risk.algorithm,
                "is_post_quantum": False,
                "quantum_safe": risk.vulnerability == QuantumVulnerability.IMMUNE,
                "vulnerability": risk.vulnerability.value,
                "attack_vector": risk.attack,
                "security_bits_classical": risk.classical_security_bits,
                "security_bits_quantum": risk.quantum_security_bits,
                "quantum_risk_score": risk_score,
                "migration_target": risk.migration_target,
                "urgency": risk.urgency,
                "action": self._get_action(risk),
            }

        return {
            "algorithm": algorithm_name,
            "is_post_quantum": False,
            "quantum_safe": False,
            "vulnerability": "unknown",
            "message": f"Algorithm '{algorithm_name}' not found in quantum risk database.",
            "action": "Investigate quantum vulnerability of this algorithm.",
        }

    def assess_multiple(self, algorithms: list[str]) -> dict:
        """
        Assess quantum readiness of multiple algorithms.

        Args:
            algorithms: List of algorithm names.

        Returns:
            Comprehensive quantum readiness assessment.
        """
        assessments = []
        broken_count = 0
        reduced_count = 0
        safe_count = 0
        max_risk = 0

        for algo in algorithms:
            assessment = self.assess_algorithm(algo)
            assessments.append(assessment)
            vuln = assessment.get("vulnerability", "")
            if vuln == "broken":
                broken_count += 1
            elif vuln == "reduced":
                reduced_count += 1
            if assessment.get("quantum_safe", False):
                safe_count += 1
            risk = assessment.get("quantum_risk_score", 0)
            if risk > max_risk:
                max_risk = risk

        if max_risk >= 80:
            overall_risk = "CRITICAL"
        elif max_risk >= 60:
            overall_risk = "HIGH"
        elif max_risk >= 40:
            overall_risk = "MEDIUM"
        elif max_risk >= 20:
            overall_risk = "LOW"
        else:
            overall_risk = "MINIMAL"

        return {
            "report_type": "Post-Quantum Readiness Assessment",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "standards_reference": [
                "FIPS 203: ML-KEM (Module-Lattice Key Encapsulation)",
                "FIPS 204: ML-DSA (Module-Lattice Digital Signature)",
                "FIPS 205: SLH-DSA (Stateless Hash-Based Digital Signature)",
                "OMB M-23-02: Migrating to Post-Quantum Cryptography",
            ],
            "overall_quantum_risk": overall_risk,
            "max_risk_score": max_risk,
            "summary": {
                "total_algorithms": len(algorithms),
                "quantum_broken": broken_count,
                "quantum_reduced": reduced_count,
                "quantum_safe": safe_count,
            },
            "assessments": assessments,
        }

    def hndl_threat_assessment(
        self,
        algorithms: list[str],
        data_sensitivity: str = "high",
        data_shelf_life_years: int = 10,
    ) -> dict:
        """
        Harvest-Now-Decrypt-Later (HNDL) threat assessment.

        HNDL: Adversaries intercept encrypted data today with the intent
        to decrypt it once quantum computers become available.

        Args:
            algorithms: Currently used algorithms.
            data_sensitivity: "low", "medium", "high", or "critical".
            data_shelf_life_years: How many years the data must remain confidential.

        Returns:
            HNDL threat assessment with risk score and recommendations.
        """
        sensitivity_multiplier = {
            "low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0,
        }.get(data_sensitivity, 0.5)

        # Estimated timeline for cryptographically relevant quantum computer (CRQC)
        crqc_earliest = 2030
        crqc_likely = 2035
        crqc_latest = 2045

        data_expiry_year = self._current_year + data_shelf_life_years
        years_until_crqc_earliest = max(0, crqc_earliest - self._current_year)
        years_until_crqc_likely = max(0, crqc_likely - self._current_year)

        # Assess each algorithm
        vulnerable_algos = []
        for algo in algorithms:
            assessment = self.assess_algorithm(algo)
            if assessment.get("vulnerability") == "broken":
                vulnerable_algos.append(assessment)

        # Calculate HNDL risk
        # Risk = sensitivity * (data_shelf_life extends past CRQC availability) * (vulnerable algorithm count)
        if not vulnerable_algos:
            hndl_risk_score = 0
        else:
            time_risk = 0.0
            if data_expiry_year > crqc_earliest:
                time_risk = min(1.0, (data_expiry_year - crqc_earliest) / 15.0)
            algo_risk = min(1.0, len(vulnerable_algos) / max(len(algorithms), 1))
            hndl_risk_score = round(time_risk * sensitivity_multiplier * algo_risk * 100, 1)

        if hndl_risk_score >= 75:
            risk_level = "CRITICAL"
            recommendation = (
                "IMMEDIATE ACTION REQUIRED. Data encrypted with quantum-vulnerable algorithms "
                "will be exposed once CRQC becomes available. The data's required confidentiality "
                "period extends well beyond estimated CRQC availability. Begin PQC migration now."
            )
        elif hndl_risk_score >= 50:
            risk_level = "HIGH"
            recommendation = (
                "High HNDL risk. Data confidentiality period overlaps with CRQC timeline. "
                "Prioritize migration to post-quantum key exchange (ML-KEM-1024) for "
                "data-in-transit encryption. Implement hybrid modes as intermediate step."
            )
        elif hndl_risk_score >= 25:
            risk_level = "MODERATE"
            recommendation = (
                "Moderate HNDL risk. Begin planning PQC migration. Implement crypto agility "
                "to enable rapid algorithm replacement when needed."
            )
        else:
            risk_level = "LOW"
            recommendation = (
                "Low HNDL risk. Continue monitoring CRQC developments. Ensure systems "
                "support crypto agility for future migration."
            )

        return {
            "report_type": "HNDL Threat Assessment",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "threat_model": "Harvest-Now-Decrypt-Later (HNDL)",
            "hndl_risk_score": hndl_risk_score,
            "risk_level": risk_level,
            "parameters": {
                "data_sensitivity": data_sensitivity,
                "data_shelf_life_years": data_shelf_life_years,
                "data_expiry_year": data_expiry_year,
                "vulnerable_algorithm_count": len(vulnerable_algos),
            },
            "crqc_timeline_estimate": {
                "earliest": crqc_earliest,
                "likely": crqc_likely,
                "latest": crqc_latest,
                "years_until_earliest": years_until_crqc_earliest,
                "years_until_likely": years_until_crqc_likely,
            },
            "vulnerable_algorithms": [
                {
                    "algorithm": a["algorithm"],
                    "attack": a.get("attack_vector", ""),
                    "migration_target": a.get("migration_target", ""),
                }
                for a in vulnerable_algos
            ],
            "recommendation": recommendation,
            "mitigation_steps": [
                "Deploy ML-KEM-1024 for key encapsulation (replaces RSA/ECDH key exchange)",
                "Use hybrid key exchange (e.g., X25519+ML-KEM-768) during transition",
                "Re-encrypt stored sensitive data with quantum-safe algorithms",
                "Implement perfect forward secrecy (PFS) to limit exposure window",
                "Deploy ML-DSA-87 for digital signatures on new documents/code",
                "Audit and inventory all cryptographic key material",
            ],
        }

    def hybrid_mode_recommendations(self, algorithms: list[str]) -> dict:
        """
        Generate hybrid mode recommendations (classical + PQC) for transition.

        Args:
            algorithms: Currently deployed algorithms.

        Returns:
            Hybrid mode recommendations for each algorithm.
        """
        recommendations = []

        for algo in algorithms:
            normalized = self._normalize_name(algo)
            risk = self.QUANTUM_VULNERABILITY.get(normalized)

            if risk and risk.vulnerability == QuantumVulnerability.BROKEN:
                hybrid = self._get_hybrid_recommendation(normalized)
                recommendations.append(hybrid)
            elif risk and risk.vulnerability == QuantumVulnerability.REDUCED:
                recommendations.append({
                    "current_algorithm": normalized,
                    "quantum_impact": "Security reduced by Grover's algorithm",
                    "hybrid_needed": False,
                    "recommendation": f"Increase key size or use {risk.migration_target}",
                })
            else:
                recommendations.append({
                    "current_algorithm": algo,
                    "quantum_impact": "None or already post-quantum",
                    "hybrid_needed": False,
                    "recommendation": "No changes needed for quantum readiness",
                })

        return {
            "report_type": "Hybrid Mode Recommendations",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "purpose": "Hybrid modes combine classical and PQC algorithms for defense-in-depth "
                       "during the transition period. If either algorithm is broken, the other "
                       "still provides security.",
            "recommendations": recommendations,
            "general_guidance": [
                "TLS 1.3: Use hybrid key share (X25519+ML-KEM-768 or P384+ML-KEM-1024)",
                "SSH: Use hybrid key exchange (curve25519+sntrup761 already available in OpenSSH 9.0+)",
                "S/MIME/CMS: Dual-encrypt with RSA-OAEP + ML-KEM",
                "Code signing: Dual-sign with ECDSA-P384 + ML-DSA-87",
                "Certificates: Issue parallel certificate chains (classical + PQC)",
            ],
        }

    def generate_migration_roadmap(
        self,
        algorithms: list[str],
        system_type: str = "general",
    ) -> dict:
        """
        Generate a prioritized PQC migration roadmap.

        Args:
            algorithms: Currently deployed algorithms.
            system_type: Type of system ("nss" for National Security Systems,
                        "federal" for federal systems, "general" for commercial).

        Returns:
            Migration roadmap with prioritized actions.
        """
        assessments = self.assess_multiple(algorithms)
        hndl = self.hndl_threat_assessment(algorithms)

        phases = []

        # Phase 1: Inventory and Assessment (immediate)
        phases.append({
            "phase": 1,
            "name": "Cryptographic Inventory and Assessment",
            "timeline": "Immediate (0-3 months)",
            "actions": [
                "Complete cryptographic algorithm inventory across all systems",
                "Identify all quantum-vulnerable algorithms in production",
                "Assess data sensitivity and confidentiality requirements",
                "Evaluate HNDL exposure for long-lived secrets",
                "Map cryptographic dependencies in software supply chain",
            ],
            "deliverables": [
                "Cryptographic inventory report",
                "Quantum risk assessment per OMB M-23-02",
                "Prioritized migration list",
            ],
        })

        # Phase 2: Crypto Agility (short-term)
        phases.append({
            "phase": 2,
            "name": "Implement Crypto Agility",
            "timeline": "Short-term (3-6 months)",
            "actions": [
                "Abstract cryptographic operations behind swappable interfaces",
                "Implement algorithm negotiation in protocols",
                "Update build systems to support PQC libraries (liboqs, PQClean)",
                "Test PQC algorithm performance in representative workloads",
                "Establish algorithm governance and selection criteria",
            ],
            "deliverables": [
                "Crypto abstraction layer deployed",
                "PQC library integration complete",
                "Performance benchmark results",
            ],
        })

        # Phase 3: Hybrid Deployment
        broken_algos = [
            a for a in assessments["assessments"]
            if a.get("vulnerability") == "broken"
        ]
        if broken_algos:
            phases.append({
                "phase": 3,
                "name": "Deploy Hybrid Modes",
                "timeline": "Medium-term (6-12 months)",
                "actions": [
                    "Deploy hybrid key exchange (classical + PQC) in TLS/SSH",
                    "Implement dual-signing for software and firmware",
                    "Begin issuing hybrid/PQC certificates",
                    "Re-encrypt high-sensitivity stored data with PQC",
                    "Update VPN/IPsec configurations for hybrid mode",
                ],
                "algorithms_to_migrate": [a["algorithm"] for a in broken_algos],
                "target_configurations": [
                    "TLS: X25519+ML-KEM-768 (general) or P384+ML-KEM-1024 (NSS)",
                    "SSH: curve25519-sha256+sntrup761",
                    "Signing: ECDSA-P384 + ML-DSA-87",
                    "Encryption: AES-256-GCM (no change needed)",
                ],
                "deliverables": [
                    "Hybrid mode deployed in production",
                    "All high-sensitivity data re-encrypted",
                ],
            })

        # Phase 4: Full PQC Migration
        target_year = {"nss": 2033, "federal": 2035, "general": 2035}
        phases.append({
            "phase": 4 if broken_algos else 3,
            "name": "Complete PQC Migration",
            "timeline": f"Long-term (12-36 months, complete by {target_year.get(system_type, 2035)})",
            "actions": [
                "Replace all classical public-key algorithms with PQC equivalents",
                "Retire hybrid modes once PQC-only is validated",
                "Update certificate chains to PQC-only",
                "Verify interoperability with partners and supply chain",
                "Conduct post-migration security audit",
            ],
            "target_algorithms": {
                "key_encapsulation": "ML-KEM-1024 (FIPS 203)",
                "digital_signatures": "ML-DSA-87 (FIPS 204)",
                "hash_signatures": "SLH-DSA-256 (FIPS 205) for firmware/software",
                "symmetric": "AES-256 (unchanged)",
                "hash": "SHA-384 minimum (unchanged)",
            },
            "deliverables": [
                "Full PQC migration complete",
                "Compliance certification obtained",
                "Classical algorithms fully retired",
            ],
        })

        return {
            "report_type": "PQC Migration Roadmap",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "system_type": system_type,
            "compliance_target": {
                "nss": "CNSA 2.0 by 2033",
                "federal": "OMB M-23-02 compliance",
                "general": "Best practice PQC migration",
            }.get(system_type, "Best practice PQC migration"),
            "quantum_risk_summary": {
                "overall_risk": assessments["overall_quantum_risk"],
                "hndl_risk": hndl["risk_level"],
                "quantum_vulnerable_count": assessments["summary"]["quantum_broken"],
            },
            "migration_phases": phases,
            "round_4_candidates": self.ROUND_4_CANDIDATES,
            "key_considerations": [
                "PQC algorithms have larger keys/signatures than classical equivalents",
                "ML-KEM-1024 public key: 1568 bytes (vs ECDH-P384: 97 bytes)",
                "ML-DSA-87 signature: 4627 bytes (vs ECDSA-P384: 96 bytes)",
                "Performance testing is essential before production deployment",
                "Interoperability with external systems may require coordination",
                "Certificate chain size increases significantly with PQC",
            ],
            "omb_m_23_02_requirements": [
                "Submit cryptographic inventory to CISA/OMB",
                "Prioritize migration of most sensitive systems",
                "Implement hybrid modes during transition",
                "Report migration progress annually",
            ],
        }

    def get_pqc_algorithm_details(self) -> dict:
        """
        Get detailed specifications for all NIST PQC standards.

        Returns:
            Complete PQC algorithm catalog with specifications.
        """
        categories: dict[str, list[dict]] = {}
        for algo in self.PQC_STANDARDS.values():
            cat = algo.category.value
            if cat not in categories:
                categories[cat] = []
            categories[cat].append({
                "name": algo.name,
                "fips_standard": algo.fips_standard,
                "nist_level": algo.nist_level,
                "security_bits_classical": algo.security_bits_classical,
                "security_bits_quantum": algo.security_bits_quantum,
                "public_key_bytes": algo.public_key_size,
                "secret_key_bytes": algo.secret_key_size,
                "ciphertext_or_signature_bytes": algo.ciphertext_or_signature_size,
                "underlying_problem": algo.underlying_problem,
                "notes": algo.notes,
            })

        return {
            "report_type": "NIST PQC Algorithm Catalog",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "standards": {
                "FIPS 203": "ML-KEM (Module-Lattice Key Encapsulation Mechanism)",
                "FIPS 204": "ML-DSA (Module-Lattice Digital Signature Algorithm)",
                "FIPS 205": "SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)",
            },
            "categories": categories,
            "round_4_candidates": self.ROUND_4_CANDIDATES,
            "size_comparison": {
                "note": "PQC algorithms have significantly larger keys and signatures",
                "key_exchange_comparison": [
                    {"algorithm": "ECDH-P256", "public_key_bytes": 65, "shared_secret_bytes": 32},
                    {"algorithm": "ECDH-P384", "public_key_bytes": 97, "shared_secret_bytes": 48},
                    {"algorithm": "ML-KEM-512", "public_key_bytes": 800, "ciphertext_bytes": 768},
                    {"algorithm": "ML-KEM-768", "public_key_bytes": 1184, "ciphertext_bytes": 1088},
                    {"algorithm": "ML-KEM-1024", "public_key_bytes": 1568, "ciphertext_bytes": 1568},
                ],
                "signature_comparison": [
                    {"algorithm": "ECDSA-P256", "public_key_bytes": 65, "signature_bytes": 72},
                    {"algorithm": "ECDSA-P384", "public_key_bytes": 97, "signature_bytes": 104},
                    {"algorithm": "Ed25519", "public_key_bytes": 32, "signature_bytes": 64},
                    {"algorithm": "ML-DSA-44", "public_key_bytes": 1312, "signature_bytes": 2420},
                    {"algorithm": "ML-DSA-65", "public_key_bytes": 1952, "signature_bytes": 3309},
                    {"algorithm": "ML-DSA-87", "public_key_bytes": 2592, "signature_bytes": 4627},
                    {"algorithm": "SLH-DSA-128s", "public_key_bytes": 32, "signature_bytes": 7856},
                    {"algorithm": "SLH-DSA-256s", "public_key_bytes": 64, "signature_bytes": 29792},
                ],
            },
        }

    def _normalize_name(self, name: str) -> str:
        """Normalize algorithm name."""
        if name in self.PQC_STANDARDS or name in self.QUANTUM_VULNERABILITY:
            return name
        name_upper = name.upper().replace(" ", "-").replace("_", "-")
        all_names = {k.upper().replace("_", "-"): k for k in self.PQC_STANDARDS}
        all_names.update({k.upper().replace("_", "-"): k for k in self.QUANTUM_VULNERABILITY})
        if name_upper in all_names:
            return all_names[name_upper]
        aliases = {
            "KYBER512": "ML-KEM-512", "KYBER768": "ML-KEM-768", "KYBER1024": "ML-KEM-1024",
            "KYBER": "ML-KEM-1024",
            "DILITHIUM2": "ML-DSA-44", "DILITHIUM3": "ML-DSA-65", "DILITHIUM5": "ML-DSA-87",
            "DILITHIUM": "ML-DSA-87",
            "SPHINCS+": "SLH-DSA-256s", "SPHINCS+-256S": "SLH-DSA-256s",
            "CRYSTALS-KYBER": "ML-KEM-1024", "CRYSTALS-DILITHIUM": "ML-DSA-87",
            "P256": "ECDSA-P256", "P384": "ECDSA-P384", "P521": "ECDSA-P521",
            "P-256": "ECDSA-P256", "P-384": "ECDSA-P384", "P-521": "ECDSA-P521",
            "ED25519": "EdDSA-Ed25519", "ED448": "EdDSA-Ed448",
            "RSA2048": "RSA-2048", "RSA3072": "RSA-3072", "RSA4096": "RSA-4096",
            "SHA256": "SHA-256", "SHA384": "SHA-384", "SHA512": "SHA-512",
        }
        return aliases.get(name_upper, name)

    def _calculate_risk_score(self, risk: QuantumRiskEntry) -> int:
        """Calculate quantum risk score (0-100)."""
        base = 0
        if risk.vulnerability == QuantumVulnerability.BROKEN:
            base = 70
        elif risk.vulnerability == QuantumVulnerability.REDUCED:
            if risk.quantum_security_bits < 128:
                base = 40
            else:
                base = 10
        elif risk.vulnerability == QuantumVulnerability.IMMUNE:
            return 0

        urgency_bonus = {
            "CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5, "NONE": 0,
        }.get(risk.urgency, 0)

        return min(100, base + urgency_bonus)

    def _get_action(self, risk: QuantumRiskEntry) -> str:
        """Get recommended action for a quantum-vulnerable algorithm."""
        if risk.vulnerability == QuantumVulnerability.BROKEN:
            return (
                f"MIGRATE: {risk.algorithm} will be completely broken by quantum computers. "
                f"Replace with {risk.migration_target}. "
                "Consider hybrid mode (classical + PQC) as an intermediate step."
            )
        elif risk.vulnerability == QuantumVulnerability.REDUCED:
            if risk.quantum_security_bits >= 128:
                return f"MONITOR: {risk.algorithm} retains {risk.quantum_security_bits}-bit quantum security."
            return (
                f"UPGRADE: {risk.algorithm} is reduced to {risk.quantum_security_bits}-bit quantum security. "
                f"Upgrade to {risk.migration_target}."
            )
        return f"No action needed for {risk.algorithm}."

    def _get_hybrid_recommendation(self, algorithm: str) -> dict:
        """Get specific hybrid mode recommendation."""
        hybrids = {
            "RSA-2048": {
                "current_algorithm": "RSA-2048",
                "quantum_impact": "Completely broken by Shor's algorithm",
                "hybrid_needed": True,
                "hybrid_configuration": "RSA-3072 + ML-KEM-1024 (key exchange) or RSA-3072 + ML-DSA-87 (signing)",
                "recommendation": "Deploy hybrid mode immediately; plan full PQC migration",
            },
            "RSA-3072": {
                "current_algorithm": "RSA-3072",
                "quantum_impact": "Completely broken by Shor's algorithm",
                "hybrid_needed": True,
                "hybrid_configuration": "RSA-3072 + ML-KEM-1024 (key exchange) or RSA-3072 + ML-DSA-87 (signing)",
                "recommendation": "Deploy hybrid mode; plan full PQC migration",
            },
            "RSA-4096": {
                "current_algorithm": "RSA-4096",
                "quantum_impact": "Completely broken by Shor's algorithm",
                "hybrid_needed": True,
                "hybrid_configuration": "RSA-4096 + ML-KEM-1024 or ML-DSA-87",
                "recommendation": "Deploy hybrid mode; plan full PQC migration",
            },
            "ECDSA-P256": {
                "current_algorithm": "ECDSA-P256",
                "quantum_impact": "Completely broken by Shor's algorithm",
                "hybrid_needed": True,
                "hybrid_configuration": "ECDSA-P384 + ML-DSA-65 (general) or ML-DSA-87 (NSS)",
                "recommendation": "First upgrade to P-384, then add ML-DSA hybrid",
            },
            "ECDSA-P384": {
                "current_algorithm": "ECDSA-P384",
                "quantum_impact": "Completely broken by Shor's algorithm",
                "hybrid_needed": True,
                "hybrid_configuration": "ECDSA-P384 + ML-DSA-87",
                "recommendation": "Deploy dual-signing with ML-DSA-87",
            },
            "ECDH-P256": {
                "current_algorithm": "ECDH-P256",
                "quantum_impact": "Completely broken by Shor's algorithm",
                "hybrid_needed": True,
                "hybrid_configuration": "X25519 + ML-KEM-768 (general) or P384 + ML-KEM-1024 (NSS)",
                "recommendation": "Deploy hybrid key exchange in TLS 1.3",
            },
            "ECDH-P384": {
                "current_algorithm": "ECDH-P384",
                "quantum_impact": "Completely broken by Shor's algorithm",
                "hybrid_needed": True,
                "hybrid_configuration": "ECDH-P384 + ML-KEM-1024",
                "recommendation": "Deploy hybrid key exchange",
            },
            "EdDSA-Ed25519": {
                "current_algorithm": "EdDSA-Ed25519",
                "quantum_impact": "Completely broken by Shor's algorithm",
                "hybrid_needed": True,
                "hybrid_configuration": "Ed25519 + ML-DSA-65 (general) or ML-DSA-87 (NSS)",
                "recommendation": "Deploy dual-signing",
            },
            "DH-2048": {
                "current_algorithm": "DH-2048",
                "quantum_impact": "Completely broken by Shor's algorithm",
                "hybrid_needed": True,
                "hybrid_configuration": "DH-3072 + ML-KEM-1024",
                "recommendation": "Replace DH entirely with ECDH+ML-KEM hybrid",
            },
        }
        default = {
            "current_algorithm": algorithm,
            "quantum_impact": "Broken by quantum computer",
            "hybrid_needed": True,
            "hybrid_configuration": f"{algorithm} + ML-KEM-1024 or ML-DSA-87",
            "recommendation": "Deploy hybrid mode",
        }
        return hybrids.get(algorithm, default)
