"""
QNetra Recommendation Engine — Algorithm Mapper
================================================

Pure stateless mapping functions that translate a classified CryptoAsset
into a deterministic PQCRecommendation.

Design Principles:
  - Purely functional: map_asset_to_recommendation() takes a CryptoAsset and returns
    a PQCRecommendation. No side effects. No CryptoAsset mutation.
  - Deterministic: Given identical inputs, always returns identical outputs.
  - No fabrication: Unknown algorithms return UNKNOWN recommendations.
    No parameter set is fabricated from an unrelated classical parameter.
  - No risk/Mosca coupling: Recommendation logic is independent of risk_score
    and Mosca urgency. These fields are intentionally ignored.
  - Explicit algorithm routing: Uses algorithm family matching and primitive type
    routing, not generic string pattern matching.
  - Only finalized NIST PQC standards are used as primary recommendations.

Contract References:
  - docs/05_ALGORITHMS.md (Alg-08: PQC Recommendation Engine)
  - docs/06_API_AND_DATA_CONTRACTS.md (Section 2.5)
"""

from __future__ import annotations

from core.models import CryptoAsset, PrimitiveType
from core.recommendation_engine.knowledge import (
    ASSUMPTION_HYBRID_TRANSITION,
    ASSUMPTION_ML_DSA_65_DEFAULT,
    ASSUMPTION_ML_DSA_87_HIGH_SECURITY,
    ASSUMPTION_ML_KEM_1024_HIGH_SECURITY,
    ASSUMPTION_ML_KEM_768_DEFAULT,
    ASSUMPTION_NO_KEY_SIZE,
    CLASSICALLY_BROKEN_ALGORITHMS,
    DSA_HIGH_SECURITY_KEY_THRESHOLD,
    ECC_HIGH_SECURITY_BITS_THRESHOLD,
    FIPS_203,
    FIPS_204,
    FIPS_205,
    GUIDANCE_ALREADY_PQC,
    GUIDANCE_CERTIFICATE_PQC,
    GUIDANCE_HASH_UPGRADE,
    GUIDANCE_ML_DSA_DIRECT,
    GUIDANCE_ML_DSA_HYBRID,
    GUIDANCE_ML_KEM_DIRECT,
    GUIDANCE_ML_KEM_HYBRID,
    GUIDANCE_NO_MIGRATION,
    GUIDANCE_SLH_DSA_FALLBACK,
    GUIDANCE_SYMMETRIC_UPGRADE,
    HASH_UPGRADE_MAP,
    HYBRID_ED25519_ML_DSA_65,
    HYBRID_X25519_ML_KEM_768,
    LIMITATION_CLASSICALLY_BROKEN_PRIORITY,
    LIMITATION_CURVE_UNKNOWN,
    LIMITATION_HYBRID_NOT_STANDARDIZED,
    LIMITATION_KEY_SIZE_UNKNOWN,
    LIMITATION_PQC_LIBRARY_AVAILABILITY,
    ML_DSA_65,
    ML_DSA_87,
    ML_KEM_1024,
    ML_KEM_768,
    NOT_APPLICABLE_PRIMITIVE_TYPES,
    PQC_ALGORITHM_PREFIXES,
    RATIONALE_ALREADY_PQC,
    RATIONALE_CERTIFICATE_PQC,
    RATIONALE_CLASSICALLY_BROKEN,
    RATIONALE_HASH_GROVER,
    RATIONALE_HYBRID_KEM,
    RATIONALE_ML_DSA_SELECTED,
    RATIONALE_ML_KEM_SELECTED,
    RATIONALE_NOT_APPLICABLE,
    RATIONALE_SHOR_VULNERABLE_KEM,
    RATIONALE_SHOR_VULNERABLE_SIG,
    RATIONALE_SYMMETRIC_GROVER,
    RATIONALE_UNKNOWN_ALGORITHM,
    RSA_HIGH_SECURITY_KEY_THRESHOLD,
    SLH_DSA_SHA2_128S,
    SHOR_VULNERABLE_ASYMMETRIC_ENCRYPTION_FAMILIES,
    SHOR_VULNERABLE_KEY_EXCHANGE_FAMILIES,
    SHOR_VULNERABLE_SIGNATURE_FAMILIES,
    SYMMETRIC_UPGRADE_MAP,
)
from core.recommendation_engine.models import (
    MigrationComplexity,
    PQCRecommendation,
    PQCRecommendationType,
)


def _is_pqc_algorithm(algorithm: str) -> bool:
    """Return True if algorithm is a standardized NIST PQC algorithm (FIPS 203/204/205)."""
    upper = algorithm.upper()
    return any(upper.startswith(prefix) for prefix in PQC_ALGORITHM_PREFIXES)


def _is_classically_broken(algorithm: str) -> bool:
    """Return True if algorithm is classically broken (MD5, SHA-1, DES, RC4, etc.)."""
    # Normalize: strip key length suffixes for lookup
    upper = algorithm.upper().strip()
    return upper in CLASSICALLY_BROKEN_ALGORITHMS


def _normalize_family(algorithm: str) -> str:
    """
    Extract a normalized algorithm family key for routing.
    Strips parameter suffixes like key sizes, modes, or curve names.
    Returns upper-cased family string.
    """
    upper = algorithm.upper().strip()
    # For algorithms like "AES-128-GCM", "SHA-256", "ECDSA", strip common suffixes
    for sep in ["-", "_", "/"]:
        if sep in upper:
            return upper.split(sep)[0]
    return upper


def _select_ml_kem_param_set(key_length_bits: int | None, curve: str | None) -> tuple[str, str, list[str]]:
    """
    Select ML-KEM parameter set based on available key parameters.

    Returns:
        Tuple of (param_set, security_category, assumptions).
    """
    assumptions: list[str] = []

    # ECC-based: check curve bit length
    if curve is not None:
        curve_upper = curve.upper()
        # ECC P-384, brainpoolP384, etc. -> high security
        if "384" in curve_upper or "521" in curve_upper or "448" in curve_upper:
            assumptions.append(ASSUMPTION_ML_KEM_1024_HIGH_SECURITY)
            return ML_KEM_1024, "5", assumptions

    # RSA-based: check key length
    if key_length_bits is not None:
        if key_length_bits >= RSA_HIGH_SECURITY_KEY_THRESHOLD:
            assumptions.append(ASSUMPTION_ML_KEM_1024_HIGH_SECURITY)
            return ML_KEM_1024, "5", assumptions

    # Default: ML-KEM-768 (Category 3)
    if key_length_bits is None and curve is None:
        assumptions.append(ASSUMPTION_NO_KEY_SIZE)
    assumptions.append(ASSUMPTION_ML_KEM_768_DEFAULT)
    return ML_KEM_768, "3", assumptions


def _select_ml_dsa_param_set(key_length_bits: int | None, curve: str | None) -> tuple[str, str, list[str]]:
    """
    Select ML-DSA parameter set based on available key parameters.

    Returns:
        Tuple of (param_set, security_category, assumptions).
    """
    assumptions: list[str] = []

    if curve is not None:
        curve_upper = curve.upper()
        if "384" in curve_upper or "521" in curve_upper or "448" in curve_upper:
            assumptions.append(ASSUMPTION_ML_DSA_87_HIGH_SECURITY)
            return ML_DSA_87, "5", assumptions

    if key_length_bits is not None and key_length_bits >= DSA_HIGH_SECURITY_KEY_THRESHOLD:
        assumptions.append(ASSUMPTION_ML_DSA_87_HIGH_SECURITY)
        return ML_DSA_87, "5", assumptions

    if key_length_bits is None and curve is None:
        assumptions.append(ASSUMPTION_NO_KEY_SIZE)
    assumptions.append(ASSUMPTION_ML_DSA_65_DEFAULT)
    return ML_DSA_65, "3", assumptions


def _map_shor_vulnerable_kem(asset: CryptoAsset) -> PQCRecommendation:
    """
    Map a Shor-vulnerable key exchange / KEM asset to a PQC recommendation.
    Handles: DH, ECDH, X25519, X448, RSA (when used for key transport).
    """
    alg_upper = asset.algorithm.upper()
    param_set, category, kem_assumptions = _select_ml_kem_param_set(
        asset.key_length_bits, asset.curve
    )

    rationale = [
        RATIONALE_SHOR_VULNERABLE_KEM.format(algorithm=asset.algorithm),
        RATIONALE_ML_KEM_SELECTED.format(param_set=param_set, category=category),
        RATIONALE_HYBRID_KEM.format(hybrid=HYBRID_X25519_ML_KEM_768),
    ]

    assumptions = list(kem_assumptions) + [ASSUMPTION_HYBRID_TRANSITION]

    limitations = [
        LIMITATION_PQC_LIBRARY_AVAILABILITY,
        LIMITATION_HYBRID_NOT_STANDARDIZED,
    ]
    if asset.key_length_bits is None and asset.curve is None:
        limitations.append(LIMITATION_KEY_SIZE_UNKNOWN)
    if asset.curve is None and "EC" in alg_upper:
        limitations.append(LIMITATION_CURVE_UNKNOWN)

    return PQCRecommendation(
        asset_id=asset.asset_id,
        current_algorithm=asset.algorithm,
        current_primitive=asset.primitive_type.value,
        recommendation_type=PQCRecommendationType.HYBRID,
        recommended_algorithm=param_set,
        pqc_standard=FIPS_203,
        hybrid_recommendation=HYBRID_X25519_ML_KEM_768,
        rationale=rationale,
        assumptions=assumptions,
        limitations=limitations,
        confidence="HIGH",
        migration_complexity=MigrationComplexity.HIGH,
        guidance_steps=list(GUIDANCE_ML_KEM_HYBRID),
    )


def _map_rsa_asymmetric_encryption(asset: CryptoAsset) -> PQCRecommendation:
    """
    Map RSA used for asymmetric encryption/key transport to ML-KEM recommendation.
    RSA OAEP/PKCS1 encryption -> ML-KEM hybrid.
    """
    param_set, category, kem_assumptions = _select_ml_kem_param_set(
        asset.key_length_bits, None
    )

    rationale = [
        f"{asset.algorithm} is used for asymmetric key transport/encryption. "
        f"RSA is vulnerable to Shor's algorithm — a CRQC can recover the RSA private key "
        f"and decrypt all previously encrypted messages.",
        RATIONALE_ML_KEM_SELECTED.format(param_set=param_set, category=category),
        RATIONALE_HYBRID_KEM.format(hybrid=HYBRID_X25519_ML_KEM_768),
    ]

    assumptions = list(kem_assumptions) + [ASSUMPTION_HYBRID_TRANSITION]
    limitations = [
        LIMITATION_PQC_LIBRARY_AVAILABILITY,
        LIMITATION_HYBRID_NOT_STANDARDIZED,
    ]
    if asset.key_length_bits is None:
        limitations.append(LIMITATION_KEY_SIZE_UNKNOWN)

    return PQCRecommendation(
        asset_id=asset.asset_id,
        current_algorithm=asset.algorithm,
        current_primitive=asset.primitive_type.value,
        recommendation_type=PQCRecommendationType.HYBRID,
        recommended_algorithm=param_set,
        pqc_standard=FIPS_203,
        hybrid_recommendation=HYBRID_X25519_ML_KEM_768,
        rationale=rationale,
        assumptions=assumptions,
        limitations=limitations,
        confidence="HIGH",
        migration_complexity=MigrationComplexity.HIGH,
        guidance_steps=list(GUIDANCE_ML_KEM_HYBRID),
    )


def _map_shor_vulnerable_signature(asset: CryptoAsset) -> PQCRecommendation:
    """
    Map a Shor-vulnerable digital signature asset to ML-DSA recommendation.
    Handles: RSA (signatures), ECDSA, DSA, Ed25519.
    """
    alg_upper = asset.algorithm.upper()
    param_set, category, dsa_assumptions = _select_ml_dsa_param_set(
        asset.key_length_bits, asset.curve
    )

    # Ed25519 and ECDSA can use hybrid Ed25519+ML-DSA-65 construction
    use_hybrid = "ECDSA" in alg_upper or "ED25519" in alg_upper or "ED448" in alg_upper

    rationale = [
        RATIONALE_SHOR_VULNERABLE_SIG.format(algorithm=asset.algorithm),
        RATIONALE_ML_DSA_SELECTED.format(param_set=param_set, category=category),
    ]

    if use_hybrid:
        rationale.append(
            f"A hybrid {HYBRID_ED25519_ML_DSA_65} construction is recommended for a "
            f"staged migration. This preserves backward compatibility with classical "
            f"verifiers while introducing post-quantum security."
        )

    assumptions = list(dsa_assumptions)
    if use_hybrid:
        assumptions.append(ASSUMPTION_HYBRID_TRANSITION)

    limitations = [
        LIMITATION_PQC_LIBRARY_AVAILABILITY,
    ]
    if asset.key_length_bits is None and asset.curve is None:
        limitations.append(LIMITATION_KEY_SIZE_UNKNOWN)
    if use_hybrid:
        limitations.append(LIMITATION_HYBRID_NOT_STANDARDIZED)

    rec_type = PQCRecommendationType.HYBRID if use_hybrid else PQCRecommendationType.DIRECT_PQC
    hybrid_rec = HYBRID_ED25519_ML_DSA_65 if use_hybrid else None
    guidance = GUIDANCE_ML_DSA_HYBRID if use_hybrid else GUIDANCE_ML_DSA_DIRECT

    return PQCRecommendation(
        asset_id=asset.asset_id,
        current_algorithm=asset.algorithm,
        current_primitive=asset.primitive_type.value,
        recommendation_type=rec_type,
        recommended_algorithm=param_set,
        pqc_standard=FIPS_204,
        hybrid_recommendation=hybrid_rec,
        rationale=rationale,
        assumptions=assumptions,
        limitations=limitations,
        confidence="HIGH",
        migration_complexity=MigrationComplexity.HIGH,
        guidance_steps=list(guidance),
    )


def _map_rsa_flexible(asset: CryptoAsset) -> PQCRecommendation:
    """
    Map RSA to either KEM (ASYMMETRIC_ENCRYPTION) or DSA (DIGITAL_SIGNATURE) recommendation
    based on the primitive type.
    """
    if asset.primitive_type in (PrimitiveType.DIGITAL_SIGNATURE,):
        return _map_shor_vulnerable_signature(asset)
    # Default RSA -> treat as key transport/KEM
    return _map_rsa_asymmetric_encryption(asset)


def _map_hash_function(asset: CryptoAsset) -> PQCRecommendation:
    """
    Map a hash function to an appropriate upgrade recommendation.

    Hash functions are NOT replaced by ML-KEM/ML-DSA. They are upgraded
    within the same hash family (e.g. SHA-256 -> SHA-384) or to SHA-256
    if classically broken (MD5, SHA-1 -> SHA-256).

    These are CLASSICAL_UPGRADE recommendations, NOT direct PQC algorithms.
    """
    alg_upper = asset.algorithm.upper()

    if _is_classically_broken(asset.algorithm):
        recommended = HASH_UPGRADE_MAP.get(alg_upper, "SHA-256")
        rationale = [
            RATIONALE_CLASSICALLY_BROKEN.format(algorithm=asset.algorithm),
            f"Upgrade to {recommended} as an immediate priority before quantum timeline considerations.",
            "SHA-256 or stronger is required as the minimum secure hash function.",
        ]
        return PQCRecommendation(
            asset_id=asset.asset_id,
            current_algorithm=asset.algorithm,
            current_primitive=asset.primitive_type.value,
            recommendation_type=PQCRecommendationType.CLASSICAL_UPGRADE,
            recommended_algorithm=recommended,
            pqc_standard=None,
            hybrid_recommendation=None,
            rationale=rationale,
            assumptions=[],
            limitations=[LIMITATION_CLASSICALLY_BROKEN_PRIORITY],
            confidence="HIGH",
            migration_complexity=MigrationComplexity.MEDIUM,
            guidance_steps=list(GUIDANCE_HASH_UPGRADE),
        )

    # Grover-impacted hash: SHA-256 family
    recommended = HASH_UPGRADE_MAP.get(alg_upper)
    if recommended is None:
        # Already strong enough (SHA-384, SHA-512, SHA3-256+, etc.) -> no migration
        return PQCRecommendation(
            asset_id=asset.asset_id,
            current_algorithm=asset.algorithm,
            current_primitive=asset.primitive_type.value,
            recommendation_type=PQCRecommendationType.NO_MIGRATION_REQUIRED,
            recommended_algorithm=None,
            pqc_standard=None,
            hybrid_recommendation=None,
            rationale=[
                f"{asset.algorithm} provides adequate post-quantum hash security. "
                f"SHA-384 and SHA-512 retain sufficient collision resistance under BHT quantum search. "
                f"No hash upgrade is required."
            ],
            assumptions=[],
            limitations=[],
            confidence="HIGH",
            migration_complexity=MigrationComplexity.LOW,
            guidance_steps=list(GUIDANCE_ALREADY_PQC),
        )

    rationale = [
        RATIONALE_HASH_GROVER.format(algorithm=asset.algorithm),
        f"Recommended upgrade: {recommended} (stronger hash within the SHA-2 family). "
        f"This is a classical hash length upgrade, not an algorithm replacement. "
        f"No PQC KEM or DSA algorithm is required for hash function migration.",
    ]

    return PQCRecommendation(
        asset_id=asset.asset_id,
        current_algorithm=asset.algorithm,
        current_primitive=asset.primitive_type.value,
        recommendation_type=PQCRecommendationType.CLASSICAL_UPGRADE,
        recommended_algorithm=recommended,
        pqc_standard=None,
        hybrid_recommendation=None,
        rationale=rationale,
        assumptions=[],
        limitations=[],
        confidence="HIGH",
        migration_complexity=MigrationComplexity.MEDIUM,
        guidance_steps=list(GUIDANCE_HASH_UPGRADE),
    )


def _map_symmetric_cipher(asset: CryptoAsset) -> PQCRecommendation:
    """
    Map a symmetric cipher to a key-length upgrade recommendation.

    Symmetric ciphers are NOT replaced by ML-KEM/ML-DSA. They are upgraded
    to 256-bit keys (AES-128 -> AES-256) to maintain post-Grover security,
    or from broken ciphers (DES, 3DES) to AES-256-GCM.

    These are CLASSICAL_UPGRADE recommendations, NOT direct PQC algorithms.
    """
    alg_upper = asset.algorithm.upper()

    # Check for classically-broken symmetric ciphers (DES, 3DES, RC4, etc.)
    if _is_classically_broken(asset.algorithm):
        rationale = [
            RATIONALE_CLASSICALLY_BROKEN.format(algorithm=asset.algorithm),
            "Replace with AES-256-GCM as an immediate priority.",
        ]
        return PQCRecommendation(
            asset_id=asset.asset_id,
            current_algorithm=asset.algorithm,
            current_primitive=asset.primitive_type.value,
            recommendation_type=PQCRecommendationType.CLASSICAL_UPGRADE,
            recommended_algorithm="AES-256-GCM",
            pqc_standard=None,
            hybrid_recommendation=None,
            rationale=rationale,
            assumptions=[],
            limitations=[LIMITATION_CLASSICALLY_BROKEN_PRIORITY],
            confidence="HIGH",
            migration_complexity=MigrationComplexity.MEDIUM,
            guidance_steps=list(GUIDANCE_SYMMETRIC_UPGRADE),
        )

    # Check if key length is already sufficient
    key_len = asset.key_length_bits
    if key_len is not None and key_len >= 256:
        return PQCRecommendation(
            asset_id=asset.asset_id,
            current_algorithm=asset.algorithm,
            current_primitive=asset.primitive_type.value,
            recommendation_type=PQCRecommendationType.NO_MIGRATION_REQUIRED,
            recommended_algorithm=None,
            pqc_standard=None,
            hybrid_recommendation=None,
            rationale=[
                f"{asset.algorithm} with {key_len}-bit key retains ~{key_len // 2} bits "
                f"of effective post-quantum security under Grover's search, meeting the "
                f"NIST 128-bit post-quantum security baseline. No key-length upgrade is required."
            ],
            assumptions=[],
            limitations=[],
            confidence="HIGH",
            migration_complexity=MigrationComplexity.LOW,
            guidance_steps=list(GUIDANCE_ALREADY_PQC),
        )

    # AES-128 or similar: needs upgrade to AES-256
    recommended = SYMMETRIC_UPGRADE_MAP.get(alg_upper)
    if recommended is None:
        # Unknown key length or unknown algorithm -- check if contains "128" in name
        if "128" in alg_upper:
            recommended = "AES-256-GCM"
        elif key_len is not None and key_len < 256:
            recommended = "AES-256-GCM"
        else:
            # Cannot determine if upgrade is needed
            return PQCRecommendation(
                asset_id=asset.asset_id,
                current_algorithm=asset.algorithm,
                current_primitive=asset.primitive_type.value,
                recommendation_type=PQCRecommendationType.UNKNOWN,
                recommended_algorithm=None,
                pqc_standard=None,
                hybrid_recommendation=None,
                rationale=[
                    f"{asset.algorithm}: key length unknown. Cannot determine if upgrade is required. "
                    f"Manual review needed to confirm key length meets post-quantum requirements."
                ],
                assumptions=[ASSUMPTION_NO_KEY_SIZE],
                limitations=[LIMITATION_KEY_SIZE_UNKNOWN],
                confidence="INSUFFICIENT_DATA",
                migration_complexity=MigrationComplexity.LOW,
                guidance_steps=list(GUIDANCE_SYMMETRIC_UPGRADE),
            )

    rationale = [
        RATIONALE_SYMMETRIC_GROVER.format(algorithm=asset.algorithm),
        f"Recommended upgrade: {recommended} (256-bit symmetric key). "
        f"This is a classical key-length upgrade, not an algorithm change. "
        f"No PQC KEM or DSA replacement is required for symmetric cipher migration.",
    ]

    return PQCRecommendation(
        asset_id=asset.asset_id,
        current_algorithm=asset.algorithm,
        current_primitive=asset.primitive_type.value,
        recommendation_type=PQCRecommendationType.CLASSICAL_UPGRADE,
        recommended_algorithm=recommended,
        pqc_standard=None,
        hybrid_recommendation=None,
        rationale=rationale,
        assumptions=[],
        limitations=[],
        confidence="HIGH",
        migration_complexity=MigrationComplexity.LOW,
        guidance_steps=list(GUIDANCE_SYMMETRIC_UPGRADE),
    )


def _map_certificate(asset: CryptoAsset) -> PQCRecommendation:
    """
    Map a CERTIFICATE primitive to ML-DSA hybrid recommendation.

    Certificates typically use RSA or ECDSA for signing. Migration requires
    PQC-capable certificate authorities and hybrid certificate deployment.
    """
    alg_upper = asset.algorithm.upper()

    # Already PQC certificate
    if _is_pqc_algorithm(asset.algorithm):
        return _already_pqc(asset)

    param_set, category, dsa_assumptions = _select_ml_dsa_param_set(
        asset.key_length_bits, asset.curve
    )

    rationale = [
        RATIONALE_CERTIFICATE_PQC.format(algorithm=asset.algorithm),
        RATIONALE_ML_DSA_SELECTED.format(param_set=param_set, category=category),
    ]

    return PQCRecommendation(
        asset_id=asset.asset_id,
        current_algorithm=asset.algorithm,
        current_primitive=asset.primitive_type.value,
        recommendation_type=PQCRecommendationType.HYBRID,
        recommended_algorithm=param_set,
        pqc_standard=FIPS_204,
        hybrid_recommendation=HYBRID_ED25519_ML_DSA_65,
        rationale=rationale,
        assumptions=list(dsa_assumptions) + [ASSUMPTION_HYBRID_TRANSITION],
        limitations=[
            LIMITATION_PQC_LIBRARY_AVAILABILITY,
            LIMITATION_HYBRID_NOT_STANDARDIZED,
            "Certificate authority (CA) PQC support must be verified before migration.",
        ],
        confidence="HIGH",
        migration_complexity=MigrationComplexity.HIGH,
        guidance_steps=list(GUIDANCE_CERTIFICATE_PQC),
    )


def _map_key_material(asset: CryptoAsset) -> PQCRecommendation:
    """
    Map KEY_MATERIAL assets (private/public keys, hardcoded keys) to recommendations.
    Route based on algorithm family — same logic as the primary primitive type.
    """
    alg_upper = asset.algorithm.upper()
    family = _normalize_family(asset.algorithm)

    if _is_pqc_algorithm(asset.algorithm):
        return _already_pqc(asset)

    if family in SHOR_VULNERABLE_ASYMMETRIC_ENCRYPTION_FAMILIES or "RSA" in alg_upper:
        return _map_rsa_asymmetric_encryption(asset)

    if (family in SHOR_VULNERABLE_KEY_EXCHANGE_FAMILIES or
            "ECDH" in alg_upper or "DH" in alg_upper):
        return _map_shor_vulnerable_kem(asset)

    if (family in SHOR_VULNERABLE_SIGNATURE_FAMILIES or
            "ECDSA" in alg_upper or "DSA" in alg_upper or "ED25519" in alg_upper):
        return _map_shor_vulnerable_signature(asset)

    # Generic key material without clear algorithm family
    return _unknown_recommendation(asset)


def _already_pqc(asset: CryptoAsset) -> PQCRecommendation:
    """Return ALREADY_PQC recommendation for NIST-approved PQC algorithms."""
    # Determine standard
    alg_upper = asset.algorithm.upper()
    if alg_upper.startswith("ML-KEM"):
        standard = FIPS_203
    elif alg_upper.startswith("ML-DSA"):
        standard = FIPS_204
    elif alg_upper.startswith("SLH-DSA"):
        standard = FIPS_205
    else:
        standard = None

    return PQCRecommendation(
        asset_id=asset.asset_id,
        current_algorithm=asset.algorithm,
        current_primitive=asset.primitive_type.value,
        recommendation_type=PQCRecommendationType.ALREADY_PQC,
        recommended_algorithm=None,
        pqc_standard=standard,
        hybrid_recommendation=None,
        rationale=[RATIONALE_ALREADY_PQC.format(algorithm=asset.algorithm)],
        assumptions=[],
        limitations=[],
        confidence="HIGH",
        migration_complexity=MigrationComplexity.LOW,
        guidance_steps=list(GUIDANCE_ALREADY_PQC),
    )


def _no_migration_required(asset: CryptoAsset) -> PQCRecommendation:
    """Return NO_MIGRATION_REQUIRED recommendation for non-applicable asset types."""
    return PQCRecommendation(
        asset_id=asset.asset_id,
        current_algorithm=asset.algorithm,
        current_primitive=asset.primitive_type.value,
        recommendation_type=PQCRecommendationType.NO_MIGRATION_REQUIRED,
        recommended_algorithm=None,
        pqc_standard=None,
        hybrid_recommendation=None,
        rationale=[RATIONALE_NOT_APPLICABLE.format(
            algorithm=asset.algorithm, primitive=asset.primitive_type.value
        )],
        assumptions=[],
        limitations=[],
        confidence="HIGH",
        migration_complexity=MigrationComplexity.LOW,
        guidance_steps=list(GUIDANCE_NO_MIGRATION),
    )


def _unknown_recommendation(asset: CryptoAsset) -> PQCRecommendation:
    """Return UNKNOWN recommendation when algorithm cannot be reliably mapped."""
    return PQCRecommendation(
        asset_id=asset.asset_id,
        current_algorithm=asset.algorithm,
        current_primitive=asset.primitive_type.value,
        recommendation_type=PQCRecommendationType.UNKNOWN,
        recommended_algorithm=None,
        pqc_standard=None,
        hybrid_recommendation=None,
        rationale=[RATIONALE_UNKNOWN_ALGORITHM.format(algorithm=asset.algorithm)],
        assumptions=[],
        limitations=[
            "Manual cryptographic audit required to determine migration path.",
        ],
        confidence="INSUFFICIENT_DATA",
        migration_complexity=MigrationComplexity.MEDIUM,
        guidance_steps=[
            "Perform manual cryptographic audit to identify the algorithm family.",
            "Consult NIST guidance to determine the appropriate PQC migration path.",
        ],
    )


def map_asset_to_recommendation(asset: CryptoAsset) -> PQCRecommendation:
    """
    Map a classified CryptoAsset to a deterministic PQCRecommendation.

    This is the central routing function of the Recommendation Engine.
    It NEVER mutates the input CryptoAsset.

    Routing Priority:
      1. Already PQC (ML-KEM, ML-DSA, SLH-DSA) -> ALREADY_PQC
      2. NOT_APPLICABLE primitives (LIBRARY, RANDOM) -> NO_MIGRATION_REQUIRED
      3. Classically-broken algorithms -> CLASSICAL_UPGRADE (upgrade to classical-secure first)
      4. Shor-vulnerable by primitive type:
         - KEY_EXCHANGE -> ML-KEM HYBRID
         - ASYMMETRIC_ENCRYPTION (RSA) -> ML-KEM HYBRID
         - DIGITAL_SIGNATURE -> ML-DSA HYBRID (or DIRECT_PQC for DSA/RSA-sign)
         - CERTIFICATE -> ML-DSA HYBRID
         - KEY_MATERIAL -> route by algorithm family
      5. Grover-impacted:
         - HASH_FUNCTION -> hash family upgrade (CLASSICAL_UPGRADE or NO_MIGRATION_REQUIRED)
         - SYMMETRIC_CIPHER -> key-length upgrade (CLASSICAL_UPGRADE or NO_MIGRATION_REQUIRED)
         - MAC/KDF -> NO_MIGRATION_REQUIRED (key-length upgrade, not PQC replacement)
      6. Not classifiable -> UNKNOWN

    Args:
        asset: A classified CryptoAsset. Must not be mutated.

    Returns:
        PQCRecommendation — deterministic, fully explainable, never fabricated.
    """
    algorithm = asset.algorithm
    primitive = asset.primitive_type
    alg_upper = algorithm.upper()
    family = _normalize_family(algorithm)

    # --- Step 1: Already PQC ---
    if _is_pqc_algorithm(algorithm):
        return _already_pqc(asset)

    # --- Step 2: NOT_APPLICABLE primitives ---
    if primitive in NOT_APPLICABLE_PRIMITIVE_TYPES:
        return _no_migration_required(asset)

    # --- Step 3: Protocol (TLS, SSH, etc.) ---
    # Protocols wrap other crypto; not a direct algorithm replacement target
    if primitive == PrimitiveType.PROTOCOL:
        return _no_migration_required(asset)

    # --- Step 4: Hash functions ---
    if primitive == PrimitiveType.HASH_FUNCTION:
        return _map_hash_function(asset)

    # --- Step 5: Symmetric ciphers ---
    if primitive == PrimitiveType.SYMMETRIC_CIPHER:
        return _map_symmetric_cipher(asset)

    # --- Step 6: MAC / KDF — key-length upgrade, not algorithm replacement ---
    if primitive in (PrimitiveType.MAC, PrimitiveType.KDF):
        # Classically broken MACs/KDFs based on MD5/SHA-1 -> flag them
        if _is_classically_broken(algorithm):
            rationale = [
                RATIONALE_CLASSICALLY_BROKEN.format(algorithm=algorithm),
                "Replace with HMAC-SHA-256 or stronger as immediate priority.",
            ]
            return PQCRecommendation(
                asset_id=asset.asset_id,
                current_algorithm=algorithm,
                current_primitive=primitive.value,
                recommendation_type=PQCRecommendationType.CLASSICAL_UPGRADE,
                recommended_algorithm="HMAC-SHA-256",
                pqc_standard=None,
                hybrid_recommendation=None,
                rationale=rationale,
                assumptions=[],
                limitations=[LIMITATION_CLASSICALLY_BROKEN_PRIORITY],
                confidence="HIGH",
                migration_complexity=MigrationComplexity.MEDIUM,
                guidance_steps=list(GUIDANCE_HASH_UPGRADE),
            )
        # Modern MACs/KDFs (HMAC-SHA-256+, HKDF, PBKDF2-SHA256+) -> no migration needed
        return _no_migration_required(asset)

    # --- Step 7: Certificate ---
    if primitive == PrimitiveType.CERTIFICATE:
        return _map_certificate(asset)

    # --- Step 8: Key Material ---
    if primitive == PrimitiveType.KEY_MATERIAL:
        return _map_key_material(asset)

    # --- Step 9: Digital Signatures ---
    if primitive == PrimitiveType.DIGITAL_SIGNATURE:
        # RSA used for signatures
        if family in SHOR_VULNERABLE_ASYMMETRIC_ENCRYPTION_FAMILIES or "RSA" in alg_upper:
            return _map_shor_vulnerable_signature(asset)
        # ECDSA, DSA, Ed25519
        if (family in SHOR_VULNERABLE_SIGNATURE_FAMILIES or
                "ECDSA" in alg_upper or "DSA" in alg_upper or "ED" in alg_upper):
            return _map_shor_vulnerable_signature(asset)
        # Check quantum_threat_type from classification layer
        if asset.quantum_threat_type == "SHOR_POLYNOMIAL_BREAK":
            return _map_shor_vulnerable_signature(asset)
        return _unknown_recommendation(asset)

    # --- Step 10: Key Exchange ---
    if primitive == PrimitiveType.KEY_EXCHANGE:
        if family in SHOR_VULNERABLE_ASYMMETRIC_ENCRYPTION_FAMILIES or "RSA" in alg_upper:
            return _map_rsa_asymmetric_encryption(asset)
        if (family in SHOR_VULNERABLE_KEY_EXCHANGE_FAMILIES or
                "ECDH" in alg_upper or "DH" in alg_upper):
            return _map_shor_vulnerable_kem(asset)
        if asset.quantum_threat_type == "SHOR_POLYNOMIAL_BREAK":
            return _map_shor_vulnerable_kem(asset)
        return _unknown_recommendation(asset)

    # --- Step 11: Asymmetric Encryption ---
    if primitive == PrimitiveType.ASYMMETRIC_ENCRYPTION:
        if family in SHOR_VULNERABLE_ASYMMETRIC_ENCRYPTION_FAMILIES or "RSA" in alg_upper:
            return _map_rsa_asymmetric_encryption(asset)
        if (family in SHOR_VULNERABLE_KEY_EXCHANGE_FAMILIES or
                "ECDH" in alg_upper):
            return _map_shor_vulnerable_kem(asset)
        if asset.quantum_threat_type == "SHOR_POLYNOMIAL_BREAK":
            return _map_rsa_asymmetric_encryption(asset)
        return _unknown_recommendation(asset)

    # --- Step 12: UNKNOWN primitive ---
    # Cannot reliably recommend without knowing what the primitive does
    return _unknown_recommendation(asset)
