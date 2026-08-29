"""
QNetra Repository Scanner — Multi-Signal Confidence Model

Implements the deterministic confidence scoring logic for cryptographic findings
discovered by the Repository Scanner.

Design principles (per docs/05_ALGORITHMS.md):
  - Confidence represents HOW CERTAIN QNetra is that a crypto artifact is present.
  - Confidence is NOT quantum risk, NOT security severity, NOT migration urgency.
  - Confidence is additive across corroborating signals with diminishing returns.
  - All scores are deterministic and explainable (no ML models per RULE-002).

Signal weights (per implementation plan):
  | Signal Type                              | Score Range |
  | Confirmed AST crypto API call            | 0.90 – 0.98 |
  | Known library import + matching API call | 0.85 – 0.95 |
  | Known binary symbol import               | 0.90 – 0.95 |
  | Library import only (no call)            | 0.55 – 0.70 |
  | Strong regex in executable code          | 0.60 – 0.75 |
  | Package metadata / manifest              | 0.70 – 0.80 |
  | String indicator in binary               | 0.30 – 0.50 |
  | Regex match in comment                   | 0.15 – 0.30 |
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class SignalType(str, Enum):
    """Discrete evidence signals that contribute to a confidence calculation."""
    AST_API_CALL = "ast_api_call"                       # AST-confirmed API call
    KNOWN_IMPORT = "known_import"                       # Library import detected
    REGEX_EXECUTABLE = "regex_executable"               # Regex match in code (not comment)
    REGEX_COMMENT = "regex_comment"                     # Regex match in a comment
    API_CALL_WITH_IMPORT = "api_call_with_import"       # API call when import also found
    ARGUMENT_EXTRACTED = "argument_extracted"           # Config argument successfully extracted
    KNOWN_API_MAPPING = "known_api_mapping"             # Matched in API registry


# Base scores for each signal type
_SIGNAL_BASE_SCORES: dict[SignalType, float] = {
    SignalType.AST_API_CALL: 0.90,
    SignalType.KNOWN_IMPORT: 0.60,
    SignalType.REGEX_EXECUTABLE: 0.62,
    SignalType.REGEX_COMMENT: 0.18,
    SignalType.API_CALL_WITH_IMPORT: 0.05,   # Bonus applied ON TOP of base API call
    SignalType.ARGUMENT_EXTRACTED: 0.03,     # Bonus for extracting concrete config
    SignalType.KNOWN_API_MAPPING: 0.02,      # Bonus for matching known API registry
}

# Maximum final score for each primary signal type
_SIGNAL_MAX_SCORES: dict[SignalType, float] = {
    SignalType.AST_API_CALL: 0.98,
    SignalType.KNOWN_IMPORT: 0.70,
    SignalType.REGEX_EXECUTABLE: 0.75,
    SignalType.REGEX_COMMENT: 0.30,
}


@dataclass
class ConfidenceCalculation:
    """Result of a confidence computation with full rationale."""
    score: float
    rationale: str
    signals: list[SignalType] = field(default_factory=list)


def calculate_confidence(
    primary_signal: SignalType,
    has_import_corroboration: bool = False,
    has_argument_extracted: bool = False,
    has_api_mapping: bool = False,
    base_override: float | None = None,
) -> ConfidenceCalculation:
    """
    Compute a deterministic confidence score from a primary signal and bonuses.

    Args:
        primary_signal: The main detection signal type.
        has_import_corroboration: True if a library import was also detected.
        has_argument_extracted: True if a concrete algorithm argument was extracted.
        has_api_mapping: True if the call matched the known API registry.
        base_override: Override the base score (used when registry provides its own).

    Returns:
        ConfidenceCalculation with score and human-readable rationale.
    """
    signals_used = [primary_signal]
    base = base_override if base_override is not None else _SIGNAL_BASE_SCORES[primary_signal]
    score = base
    rationale_parts = [_describe_signal(primary_signal, base)]

    # Apply corroborating signal bonuses (additive, with caps)
    if has_import_corroboration and primary_signal == SignalType.AST_API_CALL:
        bonus = _SIGNAL_BASE_SCORES[SignalType.API_CALL_WITH_IMPORT]
        score += bonus
        signals_used.append(SignalType.API_CALL_WITH_IMPORT)
        rationale_parts.append(f"Corroborating import detected (+{bonus:.2f})")

    if has_argument_extracted:
        bonus = _SIGNAL_BASE_SCORES[SignalType.ARGUMENT_EXTRACTED]
        score += bonus
        signals_used.append(SignalType.ARGUMENT_EXTRACTED)
        rationale_parts.append(f"Concrete argument extracted (+{bonus:.2f})")

    if has_api_mapping:
        bonus = _SIGNAL_BASE_SCORES[SignalType.KNOWN_API_MAPPING]
        score += bonus
        signals_used.append(SignalType.KNOWN_API_MAPPING)
        rationale_parts.append(f"Matched known crypto API registry (+{bonus:.2f})")

    # Apply ceiling for the primary signal type
    max_score = _SIGNAL_MAX_SCORES.get(primary_signal, 1.0)
    score = min(score, max_score)
    score = max(0.0, score)  # Never below 0

    rationale = " | ".join(rationale_parts) + f" → Final: {score:.2f}"
    return ConfidenceCalculation(score=round(score, 4), rationale=rationale, signals=signals_used)


def _describe_signal(signal: SignalType, score: float) -> str:
    descriptions = {
        SignalType.AST_API_CALL: f"AST-confirmed cryptographic API call ({score:.2f})",
        SignalType.KNOWN_IMPORT: f"Known cryptographic library import ({score:.2f})",
        SignalType.REGEX_EXECUTABLE: f"Regex pattern match in executable code ({score:.2f})",
        SignalType.REGEX_COMMENT: f"Regex pattern match in source comment ({score:.2f})",
        SignalType.API_CALL_WITH_IMPORT: f"API call with import corroboration ({score:.2f})",
        SignalType.ARGUMENT_EXTRACTED: f"Concrete argument extracted ({score:.2f})",
        SignalType.KNOWN_API_MAPPING: f"Known API registry match ({score:.2f})",
    }
    return descriptions.get(signal, f"{signal.value} ({score:.2f})")
