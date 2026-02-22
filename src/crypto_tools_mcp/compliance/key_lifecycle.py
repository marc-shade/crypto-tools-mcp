"""
Key Lifecycle Management

Manages cryptographic key states, cryptoperiods, rotation schedules, and
compliance per NIST SP 800-57 Part 1 Rev 5.

References:
- NIST SP 800-57 Part 1 Rev 5: Recommendation for Key Management
- NIST SP 800-88 Rev 1: Guidelines for Media Sanitization
- NIST SP 800-53 Rev 5: SC-12, SC-17, SC-28
"""

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class KeyState(Enum):
    """Key lifecycle states per SP 800-57."""
    PRE_ACTIVATION = "pre-activation"
    ACTIVE = "active"
    DEACTIVATED = "deactivated"
    COMPROMISED = "compromised"
    DESTROYED = "destroyed"
    DESTROYED_COMPROMISED = "destroyed-compromised"
    SUSPENDED = "suspended"


class KeyType(Enum):
    """Key type classification per SP 800-57."""
    SYMMETRIC_ENCRYPTION = "symmetric_encryption"
    SYMMETRIC_AUTHENTICATION = "symmetric_authentication"
    SYMMETRIC_KEY_WRAPPING = "symmetric_key_wrapping"
    ASYMMETRIC_SIGNING_PRIVATE = "asymmetric_signing_private"
    ASYMMETRIC_SIGNING_PUBLIC = "asymmetric_signing_public"
    ASYMMETRIC_KEY_TRANSPORT_PRIVATE = "asymmetric_key_transport_private"
    ASYMMETRIC_KEY_TRANSPORT_PUBLIC = "asymmetric_key_transport_public"
    ASYMMETRIC_KEY_AGREEMENT_PRIVATE = "asymmetric_key_agreement_private"
    ASYMMETRIC_KEY_AGREEMENT_PUBLIC = "asymmetric_key_agreement_public"
    KEK = "key_encryption_key"
    DEK = "data_encryption_key"
    MASTER_KEY = "master_key"
    SESSION_KEY = "session_key"
    ROOT_CA_KEY = "root_ca_key"
    INTERMEDIATE_CA_KEY = "intermediate_ca_key"
    TLS_KEY = "tls_key"
    SSH_KEY = "ssh_key"
    PGP_KEY = "pgp_key"
    API_KEY = "api_key"


@dataclass
class CryptoperiodPolicy:
    """Maximum cryptoperiod per key type and usage (SP 800-57 Table 1)."""
    key_type: KeyType
    originator_usage_period: str  # How long the key can be used to protect data
    recipient_usage_period: str  # How long the key can be used to process data
    max_active_days: int  # Maximum days in active state
    rotation_warning_days: int  # Days before expiry to warn
    notes: str = ""


@dataclass
class KeyRecord:
    """Record of a cryptographic key in the lifecycle system."""
    key_id: str
    name: str
    key_type: KeyType
    algorithm: str
    key_length_bits: int
    state: KeyState
    created_at: str
    activated_at: Optional[str] = None
    deactivated_at: Optional[str] = None
    compromised_at: Optional[str] = None
    destroyed_at: Optional[str] = None
    expires_at: Optional[str] = None
    owner: str = ""
    location: str = ""
    purpose: str = ""
    rotation_schedule: str = ""
    metadata: dict = field(default_factory=dict)


class KeyLifecycleManager:
    """
    Key lifecycle management engine per NIST SP 800-57 Part 1 Rev 5.

    Tracks key states, enforces cryptoperiods, manages rotation schedules,
    and generates compliance reports for key management.
    """

    # Cryptoperiod policies per SP 800-57 Part 1 Rev 5, Table 1
    CRYPTOPERIOD_POLICIES: dict[str, CryptoperiodPolicy] = {
        "symmetric_encryption": CryptoperiodPolicy(
            key_type=KeyType.SYMMETRIC_ENCRYPTION,
            originator_usage_period="2 years",
            recipient_usage_period="Originator period + 3 years",
            max_active_days=730,
            rotation_warning_days=60,
            notes="AES keys for data encryption. Rotate every 2 years maximum.",
        ),
        "symmetric_authentication": CryptoperiodPolicy(
            key_type=KeyType.SYMMETRIC_AUTHENTICATION,
            originator_usage_period="2 years",
            recipient_usage_period="Originator period + 3 years",
            max_active_days=730,
            rotation_warning_days=60,
            notes="HMAC keys for message authentication.",
        ),
        "symmetric_key_wrapping": CryptoperiodPolicy(
            key_type=KeyType.SYMMETRIC_KEY_WRAPPING,
            originator_usage_period="2 years",
            recipient_usage_period="Originator period + 3 years",
            max_active_days=730,
            rotation_warning_days=60,
            notes="KEK for wrapping/unwrapping other keys.",
        ),
        "asymmetric_signing_private": CryptoperiodPolicy(
            key_type=KeyType.ASYMMETRIC_SIGNING_PRIVATE,
            originator_usage_period="1-3 years",
            recipient_usage_period="N/A (private key not shared)",
            max_active_days=1095,
            rotation_warning_days=90,
            notes="Private signing key. Certificate validity may differ.",
        ),
        "asymmetric_signing_public": CryptoperiodPolicy(
            key_type=KeyType.ASYMMETRIC_SIGNING_PUBLIC,
            originator_usage_period="N/A",
            recipient_usage_period="Years to decades (verification)",
            max_active_days=3650,
            rotation_warning_days=180,
            notes="Public verification key. Typically valid as long as signatures exist to verify.",
        ),
        "asymmetric_key_transport_private": CryptoperiodPolicy(
            key_type=KeyType.ASYMMETRIC_KEY_TRANSPORT_PRIVATE,
            originator_usage_period="2 years",
            recipient_usage_period="N/A",
            max_active_days=730,
            rotation_warning_days=60,
            notes="RSA private key used for key decryption/unwrapping.",
        ),
        "asymmetric_key_agreement_private": CryptoperiodPolicy(
            key_type=KeyType.ASYMMETRIC_KEY_AGREEMENT_PRIVATE,
            originator_usage_period="1-2 years",
            recipient_usage_period="N/A",
            max_active_days=730,
            rotation_warning_days=60,
            notes="ECDH/DH private key for key agreement.",
        ),
        "master_key": CryptoperiodPolicy(
            key_type=KeyType.MASTER_KEY,
            originator_usage_period="1 year",
            recipient_usage_period="N/A",
            max_active_days=365,
            rotation_warning_days=30,
            notes="Master key for deriving other keys. Strict rotation required.",
        ),
        "session_key": CryptoperiodPolicy(
            key_type=KeyType.SESSION_KEY,
            originator_usage_period="24 hours maximum",
            recipient_usage_period="24 hours",
            max_active_days=1,
            rotation_warning_days=0,
            notes="TLS session keys, ephemeral keys. Very short cryptoperiod.",
        ),
        "root_ca_key": CryptoperiodPolicy(
            key_type=KeyType.ROOT_CA_KEY,
            originator_usage_period="10-20 years",
            recipient_usage_period="10-20 years",
            max_active_days=7300,
            rotation_warning_days=365,
            notes="Root CA key. Long lifetime but highest security requirements.",
        ),
        "intermediate_ca_key": CryptoperiodPolicy(
            key_type=KeyType.INTERMEDIATE_CA_KEY,
            originator_usage_period="3-5 years",
            recipient_usage_period="5-10 years",
            max_active_days=1825,
            rotation_warning_days=180,
            notes="Intermediate CA signing key.",
        ),
        "tls_key": CryptoperiodPolicy(
            key_type=KeyType.TLS_KEY,
            originator_usage_period="1 year",
            recipient_usage_period="1 year",
            max_active_days=398,
            rotation_warning_days=30,
            notes="TLS certificate private key. CA/B Forum max 398 days.",
        ),
        "ssh_key": CryptoperiodPolicy(
            key_type=KeyType.SSH_KEY,
            originator_usage_period="1 year",
            recipient_usage_period="1 year",
            max_active_days=365,
            rotation_warning_days=30,
            notes="SSH host/user key. Annual rotation recommended.",
        ),
        "api_key": CryptoperiodPolicy(
            key_type=KeyType.API_KEY,
            originator_usage_period="90 days",
            recipient_usage_period="90 days",
            max_active_days=90,
            rotation_warning_days=14,
            notes="API keys and tokens. Rotate every 90 days.",
        ),
    }

    # Valid state transitions per SP 800-57
    VALID_TRANSITIONS: dict[KeyState, list[KeyState]] = {
        KeyState.PRE_ACTIVATION: [KeyState.ACTIVE, KeyState.DESTROYED, KeyState.COMPROMISED],
        KeyState.ACTIVE: [KeyState.DEACTIVATED, KeyState.COMPROMISED, KeyState.SUSPENDED],
        KeyState.DEACTIVATED: [KeyState.DESTROYED, KeyState.COMPROMISED],
        KeyState.SUSPENDED: [KeyState.ACTIVE, KeyState.DEACTIVATED, KeyState.COMPROMISED],
        KeyState.COMPROMISED: [KeyState.DESTROYED_COMPROMISED],
        KeyState.DESTROYED: [],
        KeyState.DESTROYED_COMPROMISED: [],
    }

    # NIST 800-88 media sanitization methods for key destruction
    SANITIZATION_METHODS: list[dict] = [
        {
            "method": "Clear",
            "description": "Logical overwrite with non-sensitive data",
            "use_case": "Standard data, non-sensitive keys",
            "nist_800_88_category": "Clear",
        },
        {
            "method": "Purge",
            "description": "Cryptographic erase, block erase, or overwrite that makes recovery infeasible",
            "use_case": "Sensitive keys, classified data",
            "nist_800_88_category": "Purge",
        },
        {
            "method": "Destroy",
            "description": "Physical destruction (shredding, disintegration, incineration)",
            "use_case": "HSM decommissioning, highest classification keys",
            "nist_800_88_category": "Destroy",
        },
        {
            "method": "Cryptographic Erase",
            "description": "Delete the encryption key rendering encrypted data unrecoverable",
            "use_case": "Self-encrypting drives, encrypted key storage",
            "nist_800_88_category": "Purge",
        },
    ]

    def __init__(self) -> None:
        self._keys: dict[str, KeyRecord] = {}

    def create_key(
        self,
        key_id: str,
        name: str,
        key_type: str,
        algorithm: str,
        key_length_bits: int,
        owner: str = "",
        location: str = "",
        purpose: str = "",
        expires_at: Optional[str] = None,
    ) -> dict:
        """
        Register a new key in the lifecycle management system.

        Args:
            key_id: Unique identifier for the key.
            name: Human-readable name.
            key_type: Key type (e.g., "symmetric_encryption", "tls_key").
            algorithm: Algorithm used (e.g., "AES-256", "RSA-4096").
            key_length_bits: Key length in bits.
            owner: Key owner/custodian.
            location: Storage location (e.g., "HSM", "AWS KMS", "filesystem").
            purpose: Description of key's purpose.
            expires_at: Optional expiration date (ISO 8601).

        Returns:
            Key record with lifecycle metadata.
        """
        if key_id in self._keys:
            return {
                "success": False,
                "error": f"Key '{key_id}' already exists in the system.",
            }

        resolved_type = self._resolve_key_type(key_type)
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ")

        policy = self.CRYPTOPERIOD_POLICIES.get(key_type)
        rotation_schedule = ""
        if policy:
            rotation_schedule = f"Rotate every {policy.max_active_days} days ({policy.originator_usage_period})"

        record = KeyRecord(
            key_id=key_id,
            name=name,
            key_type=resolved_type,
            algorithm=algorithm,
            key_length_bits=key_length_bits,
            state=KeyState.PRE_ACTIVATION,
            created_at=now,
            owner=owner,
            location=location,
            purpose=purpose,
            rotation_schedule=rotation_schedule,
            expires_at=expires_at,
        )

        self._keys[key_id] = record

        return {
            "success": True,
            "key_id": key_id,
            "state": record.state.value,
            "created_at": now,
            "key_type": resolved_type.value,
            "algorithm": algorithm,
            "key_length_bits": key_length_bits,
            "rotation_schedule": rotation_schedule,
            "message": f"Key '{name}' created in PRE-ACTIVATION state.",
            "next_actions": [
                "Activate key when ready for use: transition to ACTIVE state",
                "Verify key is stored in approved location (HSM recommended)",
                f"Cryptoperiod: {policy.originator_usage_period}" if policy else "Set rotation schedule",
            ],
        }

    def transition_key(self, key_id: str, new_state: str, reason: str = "") -> dict:
        """
        Transition a key to a new lifecycle state.

        Args:
            key_id: Key identifier.
            new_state: Target state ("active", "deactivated", "compromised", "destroyed", "suspended").
            reason: Reason for the transition.

        Returns:
            Transition result with validation.
        """
        if key_id not in self._keys:
            return {"success": False, "error": f"Key '{key_id}' not found."}

        record = self._keys[key_id]
        target = self._resolve_state(new_state)

        if target is None:
            return {"success": False, "error": f"Invalid state: '{new_state}'"}

        valid_targets = self.VALID_TRANSITIONS.get(record.state, [])
        if target not in valid_targets:
            return {
                "success": False,
                "error": f"Invalid transition: {record.state.value} -> {target.value}",
                "valid_transitions": [s.value for s in valid_targets],
            }

        now = time.strftime("%Y-%m-%dT%H:%M:%SZ")
        old_state = record.state
        record.state = target

        if target == KeyState.ACTIVE:
            record.activated_at = now
        elif target == KeyState.DEACTIVATED:
            record.deactivated_at = now
        elif target == KeyState.COMPROMISED:
            record.compromised_at = now
        elif target in (KeyState.DESTROYED, KeyState.DESTROYED_COMPROMISED):
            record.destroyed_at = now

        return {
            "success": True,
            "key_id": key_id,
            "previous_state": old_state.value,
            "new_state": target.value,
            "transitioned_at": now,
            "reason": reason,
            "message": f"Key '{record.name}' transitioned: {old_state.value} -> {target.value}",
            "next_actions": self._get_state_actions(target, record),
        }

    def check_key_compliance(self, key_id: str) -> dict:
        """
        Check a key's compliance with cryptoperiod and lifecycle policies.

        Args:
            key_id: Key identifier.

        Returns:
            Compliance status with any violations.
        """
        if key_id not in self._keys:
            return {"success": False, "error": f"Key '{key_id}' not found."}

        record = self._keys[key_id]
        violations = []
        warnings = []

        # Check cryptoperiod
        policy_key = record.key_type.value
        policy = self.CRYPTOPERIOD_POLICIES.get(policy_key)

        if policy and record.state == KeyState.ACTIVE and record.activated_at:
            activated = self._parse_timestamp(record.activated_at)
            now = time.time()
            days_active = (now - activated) / 86400

            if days_active > policy.max_active_days:
                violations.append({
                    "type": "cryptoperiod_exceeded",
                    "severity": "CRITICAL",
                    "message": f"Key has been active for {int(days_active)} days, "
                               f"exceeding maximum of {policy.max_active_days} days.",
                    "remediation": "Immediately rotate this key and deactivate the old one.",
                    "control": "SC-12",
                })
            elif days_active > (policy.max_active_days - policy.rotation_warning_days):
                warnings.append({
                    "type": "cryptoperiod_expiring",
                    "severity": "HIGH",
                    "message": f"Key will exceed cryptoperiod in "
                               f"{int(policy.max_active_days - days_active)} days.",
                    "remediation": "Plan key rotation within the warning period.",
                    "control": "SC-12",
                })

        # Check expiration
        if record.expires_at:
            expires = self._parse_timestamp(record.expires_at)
            now = time.time()
            if now > expires:
                violations.append({
                    "type": "key_expired",
                    "severity": "CRITICAL",
                    "message": f"Key expired at {record.expires_at}.",
                    "remediation": "Deactivate and rotate this key immediately.",
                    "control": "SC-12",
                })
            elif (expires - now) < 86400 * 30:
                days_left = int((expires - now) / 86400)
                warnings.append({
                    "type": "key_expiring_soon",
                    "severity": "HIGH",
                    "message": f"Key expires in {days_left} days.",
                    "remediation": "Prepare replacement key.",
                    "control": "SC-12",
                })

        # Check key state appropriateness
        if record.state == KeyState.COMPROMISED:
            violations.append({
                "type": "key_compromised",
                "severity": "CRITICAL",
                "message": "Key is in COMPROMISED state. Must be destroyed.",
                "remediation": "Destroy key per NIST 800-88 and issue replacement.",
                "control": "SC-12",
            })

        # Check key storage location
        insecure_locations = ["filesystem", "environment variable", "config file",
                              "source code", "database plaintext"]
        if record.location.lower() in insecure_locations:
            warnings.append({
                "type": "insecure_storage",
                "severity": "HIGH",
                "message": f"Key stored in potentially insecure location: {record.location}",
                "remediation": "Store keys in HSM, KMS, or hardware-backed secure storage.",
                "control": "SC-12",
            })

        compliance_status = "COMPLIANT"
        if violations:
            compliance_status = "NON_COMPLIANT"
        elif warnings:
            compliance_status = "COMPLIANT_WITH_WARNINGS"

        return {
            "success": True,
            "key_id": key_id,
            "key_name": record.name,
            "state": record.state.value,
            "compliance_status": compliance_status,
            "violations": violations,
            "warnings": warnings,
            "key_details": {
                "algorithm": record.algorithm,
                "key_length_bits": record.key_length_bits,
                "key_type": record.key_type.value,
                "created_at": record.created_at,
                "activated_at": record.activated_at,
                "location": record.location,
                "owner": record.owner,
            },
            "policy": {
                "originator_usage": policy.originator_usage_period if policy else "N/A",
                "max_active_days": policy.max_active_days if policy else "N/A",
                "rotation_warning_days": policy.rotation_warning_days if policy else "N/A",
            },
            "controls": ["SC-12", "SC-17", "SC-28"],
        }

    def get_key_inventory(self) -> dict:
        """
        Get complete key inventory with status summary.

        Returns:
            Full inventory of all managed keys.
        """
        inventory = []
        state_counts: dict[str, int] = {}

        for key_id, record in self._keys.items():
            state = record.state.value
            state_counts[state] = state_counts.get(state, 0) + 1

            inventory.append({
                "key_id": key_id,
                "name": record.name,
                "algorithm": record.algorithm,
                "key_length_bits": record.key_length_bits,
                "key_type": record.key_type.value,
                "state": state,
                "created_at": record.created_at,
                "activated_at": record.activated_at,
                "expires_at": record.expires_at,
                "owner": record.owner,
                "location": record.location,
            })

        return {
            "report_type": "Key Inventory",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "total_keys": len(self._keys),
            "state_summary": state_counts,
            "inventory": inventory,
            "controls": ["SC-12 (Key Management)", "SC-17 (PKI Certificates)"],
        }

    def check_rotation_schedule(self) -> dict:
        """
        Check rotation compliance for all active keys.

        Returns:
            Rotation status for all active keys with overdue/upcoming rotations.
        """
        overdue = []
        upcoming = []
        compliant = []

        now = time.time()

        for key_id, record in self._keys.items():
            if record.state != KeyState.ACTIVE:
                continue

            policy_key = record.key_type.value
            policy = self.CRYPTOPERIOD_POLICIES.get(policy_key)
            if not policy or not record.activated_at:
                continue

            activated = self._parse_timestamp(record.activated_at)
            days_active = (now - activated) / 86400
            days_remaining = policy.max_active_days - days_active

            entry = {
                "key_id": key_id,
                "name": record.name,
                "algorithm": record.algorithm,
                "days_active": int(days_active),
                "max_active_days": policy.max_active_days,
                "days_remaining": int(days_remaining),
            }

            if days_remaining < 0:
                entry["status"] = "OVERDUE"
                entry["overdue_days"] = abs(int(days_remaining))
                overdue.append(entry)
            elif days_remaining < policy.rotation_warning_days:
                entry["status"] = "ROTATION_DUE_SOON"
                upcoming.append(entry)
            else:
                entry["status"] = "COMPLIANT"
                compliant.append(entry)

        return {
            "report_type": "Key Rotation Schedule Check",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "summary": {
                "overdue": len(overdue),
                "upcoming": len(upcoming),
                "compliant": len(compliant),
            },
            "overall_status": "NON_COMPLIANT" if overdue else (
                "WARNING" if upcoming else "COMPLIANT"
            ),
            "overdue_keys": overdue,
            "upcoming_rotations": upcoming,
            "compliant_keys": compliant,
            "controls": ["SC-12"],
        }

    def get_cryptoperiod_policies(self) -> dict:
        """
        Get all cryptoperiod policies per SP 800-57.

        Returns:
            Complete cryptoperiod policy table.
        """
        policies = []
        for key, policy in self.CRYPTOPERIOD_POLICIES.items():
            policies.append({
                "key_type": key,
                "originator_usage_period": policy.originator_usage_period,
                "recipient_usage_period": policy.recipient_usage_period,
                "max_active_days": policy.max_active_days,
                "rotation_warning_days": policy.rotation_warning_days,
                "notes": policy.notes,
            })

        return {
            "report_type": "Cryptoperiod Policies (SP 800-57 Part 1 Rev 5)",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "policies": policies,
            "general_guidance": [
                "Shorter cryptoperiods reduce exposure from key compromise",
                "Session keys should have the shortest cryptoperiods (hours)",
                "Root CA keys have the longest cryptoperiods (decades)",
                "Key rotation must be planned before cryptoperiod expiry",
                "Compromised keys must be destroyed immediately",
            ],
        }

    def get_destruction_guidance(self, key_type: str = "symmetric_encryption") -> dict:
        """
        Get key destruction guidance per NIST 800-88.

        Args:
            key_type: Type of key to get destruction guidance for.

        Returns:
            Destruction methods and verification steps.
        """
        recommended_method = "Purge"
        if key_type in ("root_ca_key", "master_key"):
            recommended_method = "Destroy"
        elif key_type in ("session_key", "api_key"):
            recommended_method = "Clear"

        return {
            "report_type": "Key Destruction Guidance",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "key_type": key_type,
            "recommended_method": recommended_method,
            "available_methods": self.SANITIZATION_METHODS,
            "verification_steps": [
                "Confirm key material is overwritten/destroyed",
                "Verify no backup copies exist in other locations",
                "Update key inventory to reflect DESTROYED state",
                "Log destruction event with timestamp and method",
                "Have destruction witnessed by authorized personnel",
                "Retain destruction record for audit purposes",
            ],
            "common_pitfalls": [
                "Key material in swap space or memory dumps",
                "Backup copies in key escrow systems",
                "Cached copies in application memory",
                "Copies in log files or debug output",
                "Replicated copies in distributed systems",
                "HSM master key not properly zeroized",
            ],
            "reference": "NIST SP 800-88 Rev 1: Guidelines for Media Sanitization",
            "controls": ["SC-12"],
        }

    def generate_lifecycle_report(self) -> dict:
        """
        Generate comprehensive key lifecycle compliance report.

        Returns:
            Full lifecycle report with inventory, rotation, and compliance status.
        """
        inventory = self.get_key_inventory()
        rotation = self.check_rotation_schedule()
        policies = self.get_cryptoperiod_policies()

        # Check compliance for each key
        compliance_results = []
        for key_id in self._keys:
            result = self.check_key_compliance(key_id)
            compliance_results.append(result)

        total_violations = sum(
            len(r.get("violations", [])) for r in compliance_results
        )
        total_warnings = sum(
            len(r.get("warnings", [])) for r in compliance_results
        )

        overall = "COMPLIANT"
        if total_violations > 0:
            overall = "NON_COMPLIANT"
        elif total_warnings > 0:
            overall = "COMPLIANT_WITH_WARNINGS"

        return {
            "report_type": "Key Lifecycle Compliance Report",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "standard": "NIST SP 800-57 Part 1 Rev 5",
            "overall_compliance": overall,
            "summary": {
                "total_keys": inventory["total_keys"],
                "total_violations": total_violations,
                "total_warnings": total_warnings,
                "rotation_overdue": rotation["summary"]["overdue"],
                "rotation_upcoming": rotation["summary"]["upcoming"],
            },
            "key_inventory": inventory,
            "rotation_status": rotation,
            "compliance_checks": compliance_results,
            "cryptoperiod_policies": policies,
            "controls_mapped": {
                "SC-12": "Cryptographic Key Establishment and Management",
                "SC-17": "Public Key Infrastructure Certificates",
                "SC-28": "Protection of Information at Rest",
            },
        }

    def validate_key_management_practice(
        self,
        practice_description: str,
    ) -> dict:
        """
        Validate a described key management practice against SP 800-57.

        Analyzes text descriptions of key management practices and identifies
        compliance gaps.

        Args:
            practice_description: Description of current key management practices.

        Returns:
            Validation results with compliance gaps and recommendations.
        """
        text = practice_description.lower()
        findings = []

        # Check for key storage practices
        if any(term in text for term in ["plaintext", "plain text", "unencrypted", "config file"]):
            findings.append({
                "category": "Key Storage",
                "severity": "CRITICAL",
                "finding": "Keys stored in plaintext or configuration files",
                "requirement": "SP 800-57: Keys must be protected with encryption or hardware security",
                "remediation": "Store keys in HSM, KMS, or encrypted key store",
                "control": "SC-12",
            })

        if not any(term in text for term in ["hsm", "hardware security", "kms", "key management"]):
            findings.append({
                "category": "Key Storage",
                "severity": "HIGH",
                "finding": "No mention of HSM or KMS for key storage",
                "requirement": "SP 800-57: Use approved hardware for sensitive key storage",
                "remediation": "Deploy HSM or cloud KMS for key protection",
                "control": "SC-12",
            })

        # Check for rotation practices
        if not any(term in text for term in ["rotat", "renewal", "refresh", "replace"]):
            findings.append({
                "category": "Key Rotation",
                "severity": "HIGH",
                "finding": "No key rotation process described",
                "requirement": "SP 800-57: Keys must be rotated within cryptoperiod limits",
                "remediation": "Implement automated key rotation per SP 800-57 Table 1",
                "control": "SC-12",
            })

        # Check for destruction practices
        if not any(term in text for term in ["destroy", "destruct", "zeroiz", "wipe", "sanitiz"]):
            findings.append({
                "category": "Key Destruction",
                "severity": "MEDIUM",
                "finding": "No key destruction process described",
                "requirement": "SP 800-88: Keys must be sanitized when no longer needed",
                "remediation": "Implement key destruction with verification per NIST 800-88",
                "control": "SC-12",
            })

        # Check for access control
        if not any(term in text for term in ["access control", "authorization", "least privilege", "rbac"]):
            findings.append({
                "category": "Access Control",
                "severity": "HIGH",
                "finding": "No access control for key operations described",
                "requirement": "SP 800-57: Key access must be controlled and audited",
                "remediation": "Implement role-based access control for key operations",
                "control": "SC-12",
            })

        # Check for backup/escrow
        if not any(term in text for term in ["backup", "escrow", "recover"]):
            findings.append({
                "category": "Key Recovery",
                "severity": "MEDIUM",
                "finding": "No key backup or recovery process described",
                "requirement": "SP 800-57: Key recovery mechanisms should be in place",
                "remediation": "Implement secure key backup with split knowledge or escrow",
                "control": "SC-12",
            })

        # Check for audit
        if not any(term in text for term in ["audit", "log", "monitor", "track"]):
            findings.append({
                "category": "Audit",
                "severity": "MEDIUM",
                "finding": "No key operation auditing described",
                "requirement": "SP 800-57: All key operations must be logged and auditable",
                "remediation": "Implement comprehensive audit logging for key lifecycle events",
                "control": "SC-12",
            })

        compliance_score = max(0, 100 - (len(findings) * 15))

        return {
            "report_type": "Key Management Practice Validation",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "compliance_score": compliance_score,
            "overall_status": "COMPLIANT" if not findings else (
                "NON_COMPLIANT" if any(f["severity"] == "CRITICAL" for f in findings) else "NEEDS_IMPROVEMENT"
            ),
            "findings_count": len(findings),
            "findings": findings,
            "sp_800_57_requirements": [
                "Key generation using approved methods (DRBG)",
                "Key storage in approved containers (HSM, KMS)",
                "Key distribution using approved protocols",
                "Key rotation within cryptoperiod limits",
                "Key destruction with verification",
                "Key access control and authorization",
                "Key operation audit logging",
                "Key backup and recovery procedures",
                "Key compromise response procedures",
            ],
        }

    def _resolve_key_type(self, key_type_str: str) -> KeyType:
        """Resolve string to KeyType enum."""
        try:
            return KeyType(key_type_str)
        except ValueError:
            mapping = {
                "symmetric": KeyType.SYMMETRIC_ENCRYPTION,
                "aes": KeyType.SYMMETRIC_ENCRYPTION,
                "hmac": KeyType.SYMMETRIC_AUTHENTICATION,
                "signing": KeyType.ASYMMETRIC_SIGNING_PRIVATE,
                "signature": KeyType.ASYMMETRIC_SIGNING_PRIVATE,
                "rsa": KeyType.ASYMMETRIC_SIGNING_PRIVATE,
                "ecdsa": KeyType.ASYMMETRIC_SIGNING_PRIVATE,
                "kek": KeyType.KEK,
                "dek": KeyType.DEK,
                "master": KeyType.MASTER_KEY,
                "session": KeyType.SESSION_KEY,
                "tls": KeyType.TLS_KEY,
                "ssl": KeyType.TLS_KEY,
                "ssh": KeyType.SSH_KEY,
                "api": KeyType.API_KEY,
                "root_ca": KeyType.ROOT_CA_KEY,
                "ca": KeyType.INTERMEDIATE_CA_KEY,
                "pgp": KeyType.PGP_KEY,
                "gpg": KeyType.PGP_KEY,
            }
            return mapping.get(key_type_str.lower(), KeyType.SYMMETRIC_ENCRYPTION)

    def _resolve_state(self, state_str: str) -> Optional[KeyState]:
        """Resolve string to KeyState enum."""
        try:
            return KeyState(state_str)
        except ValueError:
            mapping = {
                "active": KeyState.ACTIVE,
                "activate": KeyState.ACTIVE,
                "deactivated": KeyState.DEACTIVATED,
                "deactivate": KeyState.DEACTIVATED,
                "compromised": KeyState.COMPROMISED,
                "compromise": KeyState.COMPROMISED,
                "destroyed": KeyState.DESTROYED,
                "destroy": KeyState.DESTROYED,
                "suspended": KeyState.SUSPENDED,
                "suspend": KeyState.SUSPENDED,
            }
            return mapping.get(state_str.lower())

    def _parse_timestamp(self, ts: str) -> float:
        """Parse ISO 8601 timestamp to epoch seconds."""
        try:
            return time.mktime(time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ"))
        except ValueError:
            try:
                return time.mktime(time.strptime(ts, "%Y-%m-%dT%H:%M:%S"))
            except ValueError:
                return time.time()

    def _get_state_actions(self, state: KeyState, record: KeyRecord) -> list[str]:
        """Get recommended actions for a key in a given state."""
        actions = {
            KeyState.ACTIVE: [
                f"Monitor cryptoperiod (rotation schedule: {record.rotation_schedule})",
                "Ensure key is stored in approved location",
                "Enable audit logging for all key operations",
            ],
            KeyState.DEACTIVATED: [
                "Key can still be used for decryption/verification but NOT for new operations",
                "Plan key destruction when no longer needed for decryption",
                "Issue replacement key if not already done",
            ],
            KeyState.COMPROMISED: [
                "IMMEDIATELY revoke all certificates using this key",
                "Notify all parties who received data encrypted with this key",
                "Issue replacement key on new key material",
                "Destroy compromised key per NIST 800-88",
                "Investigate and document the compromise",
            ],
            KeyState.DESTROYED: [
                "Verify destruction with audit log entry",
                "Confirm no backup copies remain",
                "Update key inventory",
            ],
            KeyState.DESTROYED_COMPROMISED: [
                "Verify destruction with audit log entry",
                "Complete compromise investigation",
                "Verify all data re-encrypted with new key",
            ],
            KeyState.SUSPENDED: [
                "Investigate reason for suspension",
                "Reactivate or deactivate based on investigation results",
            ],
        }
        return actions.get(state, ["Review key state and take appropriate action"])
