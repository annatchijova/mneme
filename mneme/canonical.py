"""
MNEME — Canonicalization discipline.

Lifted from STIGMERGY's canonical.py (same author, same rules) because
the requirement is identical: everything that participates in a hash
goes through this module first, and two writers hashing "the same"
payload MUST produce the same bytes or chain-of-custody is fiction.

  - Keys sorted ascending, no insignificant whitespace, UTF-8 unescaped.
  - floats are REJECTED, not serialized carefully. Exact values travel
    as Decimal quantized to CANONICAL_SCALE and serialized as fixed-point
    strings.
  - Decimal must arrive already quantized. This module verifies; it does
    not silently re-quantize.

THIS MODULE IS PART OF THE PROTOCOL. Any writer in any language must
reproduce these exact bytes or its custody hashes will not verify.
"""

from __future__ import annotations

import json
from datetime import date, datetime
from decimal import Decimal, ROUND_HALF_EVEN
from fractions import Fraction
from typing import Any

# Matches DECIMAL(11,10) in schema.sql — single source of truth for scale.
CANONICAL_SCALE = 10
_QUANTUM = Decimal(1).scaleb(-CANONICAL_SCALE)  # Decimal('1E-10')

# One rounding mode, named once, used everywhere.
CANONICAL_ROUNDING = ROUND_HALF_EVEN


def quantize(value: Fraction | Decimal | int, field: str = "value") -> Decimal:
    """
    Convert an exact value to the canonical Decimal scale, deterministically.

    The ONLY place in the codebase where Fraction becomes Decimal. The
    application computes in Fraction (exact), quantizes here (explicit,
    documented rounding), and only then does the value touch SQL or a hash.
    """
    if isinstance(value, bool):  # bool is an int subclass; reject explicitly
        raise TypeError(f"{field}: bool is not a quantizable numeric value.")
    if isinstance(value, Fraction):
        d = Decimal(value.numerator) / Decimal(value.denominator)
    elif isinstance(value, (Decimal, int)):
        d = Decimal(value)
    else:
        raise TypeError(
            f"{field}: cannot quantize {type(value).__name__}. "
            "Floats are forbidden by design — compute in Fraction."
        )
    return d.quantize(_QUANTUM, rounding=CANONICAL_ROUNDING)


def _canonicalize(obj: Any, path: str) -> Any:
    """Recursively validate and normalize a payload for canonical JSON."""
    if obj is None or isinstance(obj, (str, int)) and not isinstance(obj, bool):
        return obj
    if isinstance(obj, bool):
        # Deliberate asymmetry with quantize(), which REJECTS bool:
        # quantize answers "is this a quantizable NUMBER?"; this function
        # answers "does this have exactly one canonical JSON form?" —
        # and true/false does. A flag like {"quarantined": true} is
        # legitimate payload content.
        return obj
    if isinstance(obj, float):
        raise TypeError(
            f"{path}: float is forbidden in custody payloads. Quantize to "
            f"Decimal (scale {CANONICAL_SCALE}) and it will serialize as a "
            "string, exactly."
        )
    if isinstance(obj, Decimal):
        # Scale is checked via the EXPONENT, not numeric equality —
        # Decimal("0.5") == Decimal("0.5000000000") is True numerically,
        # but they are two representations, and two representations of
        # one value is exactly what canonical form exists to prevent.
        if obj.as_tuple().exponent != -CANONICAL_SCALE:
            raise ValueError(
                f"{path}: Decimal {obj} is not at canonical scale "
                f"{CANONICAL_SCALE}. Quantize explicitly with quantize() — "
                "this module verifies, it never silently re-rounds."
            )
        if not obj.is_finite():
            raise ValueError(f"{path}: non-finite Decimal in custody payload.")
        # format(d, 'f') — NEVER str(d): str emits scientific notation for
        # small magnitudes ('2E-10'), which is a second representation of
        # the same value. Fixed-point, always, exactly scale digits.
        return format(obj, "f")
    if isinstance(obj, dict):
        out = {}
        for key in obj:
            if not isinstance(key, str):
                raise TypeError(
                    f"{path}: JSON object keys must be str, got {type(key).__name__}."
                )
            out[key] = _canonicalize(obj[key], f"{path}.{key}")
        return out
    if isinstance(obj, (list, tuple)):
        return [_canonicalize(v, f"{path}[{i}]") for i, v in enumerate(obj)]
    if isinstance(obj, (datetime, date)):
        raise TypeError(
            f"{path}: {type(obj).__name__} is not serializable in a custody "
            "payload. Format it explicitly — for event timestamps use "
            "custody.format_ts (UTC, microseconds, ISO 8601) so there is "
            "exactly one representation."
        )
    raise TypeError(f"{path}: {type(obj).__name__} is not serializable in a custody payload.")


def canonical_json(payload: dict[str, Any]) -> str:
    """
    Serialize a payload to canonical JSON: keys sorted ascending,
    separators without whitespace, non-ASCII preserved as UTF-8.

    The returned string is what gets hashed AND what gets stored in
    payload_json, so the stored bytes and the hashed bytes cannot drift.
    """
    if not isinstance(payload, dict):
        raise TypeError("Custody payload must be a dict at the top level.")
    normalized = _canonicalize(payload, "payload")
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
