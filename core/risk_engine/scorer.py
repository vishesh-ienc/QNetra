"""
QNetra Risk Engine — Scorer Implementation
===========================================

Computes deterministic, explainable 0–100 risk scores for CryptoAsset instances.

Design Invariants:
  1. Strict Boundedness: 0 <= risk_score <= 100 at all times.
  2. Pure Determinism: Identical CryptoAsset input always yields the exact same score.
  3. Strict No-Fabrication: Missing parameters (key_length, curve) are never guessed;
     they receive 0 parameter modifiers and are noted in explainability factors.
  4. Double-Counting Prevention: Factor ownership is strictly segmented:
     - A classically broken primitive (MD5, DES) is handled by the classical factor (100)
       and does NOT receive a redundant quantum penalty.
     - A Shor-vulnerable primitive (RSA) is handled by the quantum factor (90) and key length
       modifier (+10 for <2048) and does NOT receive redundant classical penalties.
  5. Explainable Breakdown: Every non-zero contribution is linked to a named RiskFactor.
  6. Confidence Integrity: Discovery confidence is preserved as descriptive metadata;
     it does NOT artificially scale down mathematical risk scores.

Contract References:
  - docs/05_ALGORITHMS.md Alg-06 (Deterministic Quantum Risk Scoring)
  - docs/06_API_AND_DATA_CONTRACTS.md Section 2.3
  - docs/10_API_CONTRACT.md Section 9
"""

from __future__ import annotations

import logging
from typing import Optional

from core.classification.models import ClassicalSecurityStatus, QuantumSecurityStatus
from core.models import CryptoAsset, PrimitiveType
from core.risk_engine.knowledge import (
    BASE_CLASSICALLY_BROKEN,
    BASE_GROVER_DEGRADED_HASH,
    BASE_GROVER_DEGRADED_SYMMETRIC,
    BASE_NIST_APPROVED_PQC,
    BASE_NOT_APPLICABLE,
    BASE_QUANTUM_RESISTANT_CLASSICAL,
    BASE_SHOR_VULNERABLE,
    BASE_UNKNOWN_ALGORITHM,
    MOD_AES_128,
    MOD_AES_192,
    MOD_AES_256,
    MOD_CLASSICAL_WEAK,
    MOD_ECB_MODE,
    MOD_PARAM_UNKNOWN,
    MOD_RSA_BELOW_2048,
    MOD_RSA_GE_4096,
    MOD_WEAK_PADDING,
    RATIONALE_CLASSICALLY_BROKEN,
    RATIONALE_GROVER_DEGRADED,
    RATIONALE_NIST_PQC,
    RATIONALE_NOT_APPLICABLE,
    RATIONALE_QUANTUM_RESISTANT_HASH,
    RATIONALE_QUANTUM_RESISTANT_SYMMETRIC,
    RATIONALE_SHOR_VULNERABLE,
    RATIONALE_UNKNOWN_ALGORITHM,
)
from core.risk_engine.models import RiskAssessment, RiskFactor, RiskSeverity
from scanners.registry.crypto_algorithms import QuantumThreat

logger = logging.getLogger(__name__)

# Known finalized PQC prefixes (FIPS 203, 204, 205)
_PQC_ALGORITHMS = frozenset({"ML-KEM", "ML-DSA", "SLH-DSA"})

# Known classically broken algorithm identifiers
_CLASSICALLY_BROKEN_NAMES = frozenset({"MD5", "SHA-1", "SHA1", "DES", "RC4", "BLOWFISH"})


def _is_pqc(algorithm: str) -> bool:
    """Return True if algorithm matches a standardized NIST PQC standard."""
    upper = algorithm.upper()
    return any(upper.startswith(prefix) for prefix in _PQC_ALGORITHMS)


def _is_classically_broken(asset: CryptoAsset) -> bool:
    """
    Return True if the asset is classified as classically broken.
    Checks classical_security_status, quantum_threat_type, or canonical name.
    """
    if asset.classical_security_status == ClassicalSecurityStatus.BROKEN:
        return True
    if asset.quantum_threat_type == QuantumThreat.CLASSICALLY_BROKEN.value:
        return True
    upper = asset.algorithm.upper()
    return upper in _CLASSICALLY_BROKEN_NAMES


def _format_param_str(asset: CryptoAsset) -> str:
    """Build parameter display suffix for explainability rationales."""
    if asset.key_length_bits:
        return f"-{asset.key_length_bits}"
    if asset.curve:
        return f" ({asset.curve})"
    return ""


class RiskScorer:
    """
    Pure computational scorer implementing Alg-06 for CryptoAsset instances.
    Stateless and free of side-effects.
    """

    @classmethod
    def calculate_risk(cls, asset: CryptoAsset) -> RiskAssessment:
        """
        Calculate deterministic risk score and return structured RiskAssessment.

        Args:
            asset: Enriched canonical CryptoAsset instance.

        Returns:
            RiskAssessment with bounded 0–100 score, severity, and factor breakdown.
        """
        factors: list[RiskFactor] = []
        param_str = _format_param_str(asset)

        # ------------------------------------------------------------------
        # Branch 1: Non-Cryptographic / Non-Vulnerable Operational Artifacts
        # ------------------------------------------------------------------
        if asset.primitive_type in (PrimitiveType.LIBRARY, PrimitiveType.RANDOM):
            reason = RATIONALE_NOT_APPLICABLE.format(
                algorithm=asset.algorithm,
                primitive_type=asset.primitive_type.value,
            )
            factors.append(RiskFactor(
                name="operational_context",
                score=BASE_NOT_APPLICABLE,
                maximum=0.0,
                reason=reason,
                source_field="primitive_type",
            ))
            return RiskAssessment(
                asset_id=asset.asset_id,
                risk_score=0,
                severity=RiskSeverity.LOW,
                factors=factors,
                rationale=reason,
                confidence=asset.confidence_score,
            )

        # ------------------------------------------------------------------
        # Branch 2: Classically Broken Cryptographic Primitives (MD5, SHA-1, DES, RC4)
        # Immediate 100/100 risk. Prevents double-counting: classical factor owns
        # the entire risk; quantum vulnerability is zeroed out as superseded.
        # ------------------------------------------------------------------
        if _is_classically_broken(asset):
            notes = asset.classification_notes or "known practical collision/factoring attacks"
            reason = RATIONALE_CLASSICALLY_BROKEN.format(
                algorithm=asset.algorithm,
                notes=notes,
            )
            factors.append(RiskFactor(
                name="classical_vulnerability",
                score=BASE_CLASSICALLY_BROKEN,
                maximum=100.0,
                reason=reason,
                source_field="classical_security_status",
            ))
            # Explicitly record quantum factor as superseded (double-counting prevention)
            factors.append(RiskFactor(
                name="quantum_vulnerability",
                score=0.0,
                maximum=0.0,
                reason="Quantum threat analysis superseded by immediate classical cryptanalytic break.",
                source_field="quantum_threat_type",
            ))
            return RiskAssessment(
                asset_id=asset.asset_id,
                risk_score=100,
                severity=RiskSeverity.CRITICAL,
                factors=factors,
                rationale=reason,
                confidence=asset.confidence_score,
            )

        # ------------------------------------------------------------------
        # Branch 3: NIST-Standardized Post-Quantum Cryptography (ML-KEM, ML-DSA, SLH-DSA)
        # Zero baseline risk.
        # ------------------------------------------------------------------
        if _is_pqc(asset.algorithm) or (
            asset.quantum_threat_type == QuantumThreat.QUANTUM_RESISTANT.value
            and asset.quantum_security_status == QuantumSecurityStatus.SAFE
            and asset.primitive_type in (
                PrimitiveType.ASYMMETRIC_ENCRYPTION,
                PrimitiveType.DIGITAL_SIGNATURE,
                PrimitiveType.KEY_EXCHANGE,
            )
        ):
            reason = RATIONALE_NIST_PQC.format(algorithm=asset.algorithm)
            factors.append(RiskFactor(
                name="quantum_vulnerability",
                score=BASE_NIST_APPROVED_PQC,
                maximum=0.0,
                reason=reason,
                source_field="quantum_threat_type",
            ))
            return RiskAssessment(
                asset_id=asset.asset_id,
                risk_score=0,
                severity=RiskSeverity.LOW,
                factors=factors,
                rationale=reason,
                confidence=asset.confidence_score,
            )

        # ------------------------------------------------------------------
        # Branch 4: Shor-Vulnerable Public-Key Cryptography (RSA, ECC, DH, ECDSA)
        # Base score 90. Key length modifiers: <2048 -> +10; >=4096 -> -5.
        # ------------------------------------------------------------------
        is_shor = (
            asset.quantum_threat_type == QuantumThreat.SHOR_POLYNOMIAL_BREAK.value
            or asset.quantum_security_status == QuantumSecurityStatus.CRITICAL
        )
        if is_shor:
            reason = RATIONALE_SHOR_VULNERABLE.format(
                algorithm=asset.algorithm,
                param_str=param_str,
            )
            factors.append(RiskFactor(
                name="quantum_vulnerability",
                score=BASE_SHOR_VULNERABLE,
                maximum=90.0,
                reason=reason,
                source_field="quantum_threat_type",
            ))

            # Key / Curve Parameter Modifier (NO FABRICATION: only if parameters are known)
            if "RSA" in asset.algorithm.upper():
                if asset.key_length_bits is not None:
                    if asset.key_length_bits < 2048:
                        factors.append(RiskFactor(
                            name="parameter_key_length",
                            score=MOD_RSA_BELOW_2048,
                            maximum=10.0,
                            reason=f"RSA modulus ({asset.key_length_bits} bits) is below NIST SP 800-131A minimum 2048 bits.",
                            source_field="key_length_bits",
                        ))
                    elif asset.key_length_bits >= 4096:
                        factors.append(RiskFactor(
                            name="parameter_key_length",
                            score=MOD_RSA_GE_4096,
                            maximum=0.0,
                            reason=f"RSA modulus ({asset.key_length_bits} bits) provides maximum classical security margin.",
                            source_field="key_length_bits",
                        ))
                else:
                    # Key size unknown: record zero modifier with explanation
                    factors.append(RiskFactor(
                        name="parameter_key_length",
                        score=MOD_PARAM_UNKNOWN,
                        maximum=0.0,
                        reason=f"Key length for {asset.algorithm} is unverified in source inspection (no fabrication).",
                        source_field="key_length_bits",
                    ))
            elif any(term in (asset.algorithm_family or "").upper() or term in asset.algorithm.upper() for term in ("ECC", "ECDSA", "ECDH")):
                if asset.curve is None:
                    factors.append(RiskFactor(
                        name="parameter_curve",
                        score=MOD_PARAM_UNKNOWN,
                        maximum=0.0,
                        reason=f"Elliptic curve for {asset.algorithm} is unverified in source inspection (no fabrication).",
                        source_field="curve",
                    ))

            # Padding modifier if applicable
            if asset.padding and "PKCS1" in asset.padding.upper():
                factors.append(RiskFactor(
                    name="parameter_padding",
                    score=MOD_WEAK_PADDING,
                    maximum=5.0,
                    reason="PKCS#1 v1.5 padding susceptible to Bleichenbacher-style adaptive chosen-ciphertext attacks.",
                    source_field="padding",
                ))

            score = int(round(max(0.0, min(100.0, sum(f.score for f in factors)))))
            severity = RiskSeverity.from_score(score)
            return RiskAssessment(
                asset_id=asset.asset_id,
                risk_score=score,
                severity=severity,
                factors=factors,
                rationale=reason,
                confidence=asset.confidence_score,
            )

        # ------------------------------------------------------------------
        # Branch 5: Symmetric Ciphers (AES, ChaCha20, 3DES)
        # ------------------------------------------------------------------
        if asset.primitive_type == PrimitiveType.SYMMETRIC_CIPHER:
            # 3DES check
            if "3DES" in asset.algorithm.upper() or "DES3" in asset.algorithm.upper() or "TRIPLEDES" in asset.algorithm.upper():
                factors.append(RiskFactor(
                    name="quantum_vulnerability",
                    score=BASE_GROVER_DEGRADED_SYMMETRIC,
                    maximum=60.0,
                    reason="Grover's algorithm halves 3DES key search to < 64 bits.",
                    source_field="quantum_threat_type",
                ))
                factors.append(RiskFactor(
                    name="classical_vulnerability",
                    score=MOD_CLASSICAL_WEAK + 5.0,
                    maximum=15.0,
                    reason="3DES is deprecated by NIST SP 800-131A (Sweet32 64-bit block collision vulnerability).",
                    source_field="classical_security_status",
                ))
                score = int(round(max(0.0, min(100.0, sum(f.score for f in factors)))))
                return RiskAssessment(
                    asset_id=asset.asset_id,
                    risk_score=score,
                    severity=RiskSeverity.from_score(score),
                    factors=factors,
                    rationale=f"3DES is deprecated classically and vulnerable to Grover key halving.",
                    confidence=asset.confidence_score,
                )

            # AES / ChaCha20 with 256-bit key (Quantum-Resistant Classical)
            if asset.key_length_bits == 256 or (
                asset.quantum_security_status == QuantumSecurityStatus.SAFE
                and (asset.algorithm_family == "CHACHA" or "CHACHA" in asset.algorithm.upper())
            ):
                qbits = asset.effective_quantum_security_bits or 128
                reason = RATIONALE_QUANTUM_RESISTANT_SYMMETRIC.format(
                    algorithm=asset.algorithm,
                    param_str=param_str,
                    qbits=qbits,
                )
                factors.append(RiskFactor(
                    name="quantum_vulnerability",
                    score=BASE_QUANTUM_RESISTANT_CLASSICAL,
                    maximum=20.0,
                    reason=reason,
                    source_field="quantum_security_status",
                ))
                factors.append(RiskFactor(
                    name="parameter_key_length",
                    score=MOD_AES_256,
                    maximum=0.0,
                    reason="256-bit key length guarantees >= 128-bit post-Grover security.",
                    source_field="key_length_bits",
                ))
                if asset.mode and asset.mode.upper() == "ECB":
                    factors.append(RiskFactor(
                        name="parameter_cipher_mode",
                        score=MOD_ECB_MODE,
                        maximum=15.0,
                        reason="Electronic Codebook (ECB) mode leaks plaintext pattern structure.",
                        source_field="mode",
                    ))
                score = int(round(max(0.0, min(100.0, sum(f.score for f in factors)))))
                return RiskAssessment(
                    asset_id=asset.asset_id,
                    risk_score=score,
                    severity=RiskSeverity.from_score(score),
                    factors=factors,
                    rationale=reason,
                    confidence=asset.confidence_score,
                )

            # AES with 128-bit key (Grover-Impacted)
            if asset.key_length_bits == 128:
                qbits = asset.effective_quantum_security_bits or 64
                reason = RATIONALE_GROVER_DEGRADED.format(
                    algorithm=asset.algorithm,
                    param_str=param_str,
                    qbits=qbits,
                )
                factors.append(RiskFactor(
                    name="quantum_vulnerability",
                    score=BASE_GROVER_DEGRADED_SYMMETRIC,
                    maximum=60.0,
                    reason=reason,
                    source_field="quantum_threat_type",
                ))
                factors.append(RiskFactor(
                    name="parameter_key_length",
                    score=MOD_AES_128,
                    maximum=10.0,
                    reason="128-bit key security reduced to ~64 bits post-Grover (below NIST 128-bit threshold).",
                    source_field="key_length_bits",
                ))
                if asset.mode and asset.mode.upper() == "ECB":
                    factors.append(RiskFactor(
                        name="parameter_cipher_mode",
                        score=MOD_ECB_MODE,
                        maximum=15.0,
                        reason="Electronic Codebook (ECB) mode leaks plaintext pattern structure.",
                        source_field="mode",
                    ))
                score = int(round(max(0.0, min(100.0, sum(f.score for f in factors)))))
                return RiskAssessment(
                    asset_id=asset.asset_id,
                    risk_score=score,
                    severity=RiskSeverity.from_score(score),
                    factors=factors,
                    rationale=reason,
                    confidence=asset.confidence_score,
                )

            # AES with 192-bit key
            if asset.key_length_bits == 192:
                qbits = asset.effective_quantum_security_bits or 96
                reason = RATIONALE_GROVER_DEGRADED.format(
                    algorithm=asset.algorithm,
                    param_str=param_str,
                    qbits=qbits,
                )
                factors.append(RiskFactor(
                    name="quantum_vulnerability",
                    score=BASE_GROVER_DEGRADED_SYMMETRIC,
                    maximum=60.0,
                    reason=reason,
                    source_field="quantum_threat_type",
                ))
                factors.append(RiskFactor(
                    name="parameter_key_length",
                    score=MOD_AES_192,
                    maximum=0.0,
                    reason="192-bit key length provides 96-bit post-Grover security.",
                    source_field="key_length_bits",
                ))
                score = int(round(max(0.0, min(100.0, sum(f.score for f in factors)))))
                return RiskAssessment(
                    asset_id=asset.asset_id,
                    risk_score=score,
                    severity=RiskSeverity.from_score(score),
                    factors=factors,
                    rationale=reason,
                    confidence=asset.confidence_score,
                )

            # Symmetric cipher with UNKNOWN key size (NO FABRICATION)
            # Evaluated as moderate quantum uncertainty (base 45 + 5 uncertainty = 50 MEDIUM)
            reason = (
                f"{asset.algorithm} symmetric key size could not be extracted from source code. "
                "Post-quantum security status is unverified pending parameter identification."
            )
            factors.append(RiskFactor(
                name="quantum_vulnerability",
                score=45.0,
                maximum=60.0,
                reason=reason,
                source_field="quantum_threat_type",
            ))
            factors.append(RiskFactor(
                name="parameter_uncertainty",
                score=5.0,
                maximum=10.0,
                reason="Key length parameter is unverified in source inspection (no fabrication).",
                source_field="key_length_bits",
            ))
            if asset.mode and asset.mode.upper() == "ECB":
                factors.append(RiskFactor(
                    name="parameter_cipher_mode",
                    score=MOD_ECB_MODE,
                    maximum=15.0,
                    reason="Electronic Codebook (ECB) mode leaks plaintext pattern structure.",
                    source_field="mode",
                ))
            score = int(round(max(0.0, min(100.0, sum(f.score for f in factors)))))
            return RiskAssessment(
                asset_id=asset.asset_id,
                risk_score=score,
                severity=RiskSeverity.from_score(score),
                factors=factors,
                rationale=reason,
                confidence=asset.confidence_score,
            )

        # ------------------------------------------------------------------
        # Branch 6: Hash Functions (SHA-256, SHA-384, SHA-512, SHA-224)
        # ------------------------------------------------------------------
        if asset.primitive_type == PrimitiveType.HASH_FUNCTION:
            upper = asset.algorithm.upper()
            # SHA-384, SHA-512, SHA-3 (Quantum-Resistant Hash)
            if any(h in upper for h in ("384", "512", "SHA3", "SHA-3")):
                reason = RATIONALE_QUANTUM_RESISTANT_HASH.format(algorithm=asset.algorithm)
                factors.append(RiskFactor(
                    name="quantum_vulnerability",
                    score=15.0,
                    maximum=20.0,
                    reason=reason,
                    source_field="quantum_security_status",
                ))
                return RiskAssessment(
                    asset_id=asset.asset_id,
                    risk_score=15,
                    severity=RiskSeverity.LOW,
                    factors=factors,
                    rationale=reason,
                    confidence=asset.confidence_score,
                )

            # SHA-256 (Grover/BHT Degraded in collision contexts)
            if "256" in upper:
                reason = (
                    f"{asset.algorithm} post-quantum collision resistance is reduced to ~85 bits "
                    "under the BHT quantum collision algorithm (< 128-bit NIST threshold)."
                )
                factors.append(RiskFactor(
                    name="quantum_vulnerability",
                    score=BASE_GROVER_DEGRADED_HASH,
                    maximum=40.0,
                    reason=reason,
                    source_field="quantum_security_status",
                ))
                return RiskAssessment(
                    asset_id=asset.asset_id,
                    risk_score=40,
                    severity=RiskSeverity.MEDIUM,
                    factors=factors,
                    rationale=reason,
                    confidence=asset.confidence_score,
                )

            # SHA-224 (Legacy/High Risk)
            if "224" in upper:
                reason = f"{asset.algorithm} provides reduced collision resistance (< 80 bits post-quantum)."
                factors.append(RiskFactor(
                    name="quantum_vulnerability",
                    score=55.0,
                    maximum=60.0,
                    reason=reason,
                    source_field="quantum_security_status",
                ))
                factors.append(RiskFactor(
                    name="classical_vulnerability",
                    score=10.0,
                    maximum=10.0,
                    reason="SHA-224 is a legacy digest length not recommended for new deployments.",
                    source_field="classical_security_status",
                ))
                score = int(round(max(0.0, min(100.0, sum(f.score for f in factors)))))
                return RiskAssessment(
                    asset_id=asset.asset_id,
                    risk_score=score,
                    severity=RiskSeverity.from_score(score),
                    factors=factors,
                    rationale=reason,
                    confidence=asset.confidence_score,
                )

        # ------------------------------------------------------------------
        # Branch 7: Key Derivation Functions & Message Authentication Codes
        # (PBKDF2, HKDF, HMAC)
        # ------------------------------------------------------------------
        if asset.primitive_type in (PrimitiveType.KDF, PrimitiveType.MAC):
            upper = asset.algorithm.upper()
            if "MD5" in upper or "SHA1" in upper or "SHA-1" in upper:
                # Classically broken underlying hash
                reason = f"{asset.algorithm} uses a classically broken hash function (collision attacks feasible)."
                factors.append(RiskFactor(
                    name="classical_vulnerability",
                    score=BASE_CLASSICALLY_BROKEN,
                    maximum=100.0,
                    reason=reason,
                    source_field="classical_security_status",
                ))
                return RiskAssessment(
                    asset_id=asset.asset_id,
                    risk_score=100,
                    severity=RiskSeverity.CRITICAL,
                    factors=factors,
                    rationale=reason,
                    confidence=asset.confidence_score,
                )

            # Standard approved KDF / HMAC (e.g. HMAC-SHA256, PBKDF2)
            reason = f"{asset.algorithm} provides adequate classical and quantum longevity in authentication contexts."
            factors.append(RiskFactor(
                name="quantum_vulnerability",
                score=30.0,
                maximum=40.0,
                reason=reason,
                source_field="quantum_security_status",
            ))
            score = 30
            return RiskAssessment(
                asset_id=asset.asset_id,
                risk_score=score,
                severity=RiskSeverity.MEDIUM,
                factors=factors,
                rationale=reason,
                confidence=asset.confidence_score,
            )

        # ------------------------------------------------------------------
        # Branch 8: Protocols (TLS, SSH, SSL)
        # ------------------------------------------------------------------
        if asset.primitive_type == PrimitiveType.PROTOCOL:
            if asset.classical_security_status == ClassicalSecurityStatus.BROKEN:
                reason = f"Protocol {asset.algorithm} is deprecated and broken (e.g. SSLv3, TLS 1.0/1.1)."
                factors.append(RiskFactor(
                    name="classical_vulnerability",
                    score=BASE_CLASSICALLY_BROKEN,
                    maximum=100.0,
                    reason=reason,
                    source_field="classical_security_status",
                ))
                return RiskAssessment(
                    asset_id=asset.asset_id,
                    risk_score=100,
                    severity=RiskSeverity.CRITICAL,
                    factors=factors,
                    rationale=reason,
                    confidence=asset.confidence_score,
                )
            if asset.classical_security_status == ClassicalSecurityStatus.WEAK:
                reason = f"Protocol {asset.algorithm} has deprecated configuration or weak cipher suite compatibility."
                factors.append(RiskFactor(
                    name="classical_vulnerability",
                    score=40.0,
                    maximum=40.0,
                    reason=reason,
                    source_field="classical_security_status",
                ))
                factors.append(RiskFactor(
                    name="quantum_vulnerability",
                    score=30.0,
                    maximum=40.0,
                    reason="Protocol handshake relies on classical key exchange without post-quantum hybrid support.",
                    source_field="quantum_threat_type",
                ))
                score = 70
                return RiskAssessment(
                    asset_id=asset.asset_id,
                    risk_score=score,
                    severity=RiskSeverity.HIGH,
                    factors=factors,
                    rationale=reason,
                    confidence=asset.confidence_score,
                )
            # Modern protocol (e.g. TLS 1.3)
            reason = f"Protocol {asset.algorithm} is modern; quantum exposure depends on negotiated cipher suites."
            factors.append(RiskFactor(
                name="quantum_vulnerability",
                score=25.0,
                maximum=30.0,
                reason=reason,
                source_field="quantum_security_status",
            ))
            return RiskAssessment(
                asset_id=asset.asset_id,
                risk_score=25,
                severity=RiskSeverity.LOW,
                factors=factors,
                rationale=reason,
                confidence=asset.confidence_score,
            )

        # ------------------------------------------------------------------
        # Branch 9: Default / Unknown / Unverified Primitive
        # ------------------------------------------------------------------
        reason = RATIONALE_UNKNOWN_ALGORITHM.format(algorithm=asset.algorithm)
        factors.append(RiskFactor(
            name="uncertainty_baseline",
            score=BASE_UNKNOWN_ALGORITHM,
            maximum=50.0,
            reason=reason,
            source_field="algorithm",
        ))
        return RiskAssessment(
            asset_id=asset.asset_id,
            risk_score=int(BASE_UNKNOWN_ALGORITHM),
            severity=RiskSeverity.MEDIUM,
            factors=factors,
            rationale=reason,
            confidence=asset.confidence_score,
        )
