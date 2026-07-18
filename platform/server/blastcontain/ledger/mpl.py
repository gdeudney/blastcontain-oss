"""
Maximum Probable Loss (MPL) — the priced-risk engine (roadmap P2 ★).

MPL = (Base Value × Volume Factor) × Regulatory Multiplier
       × Trust-Aware Blast Radius × Business Context × TrustTier Weight
       × Human-Oversight Factor

Presented as a **calibrated exposure index, not a loss prediction**: the base
values are indicative magnitudes in the range of public breach-cost studies
(IBM Cost-of-a-Data-Breach class), and every deployment is expected to
**calibrate per org** (`MPLCalibration`, stored via `/v1/ledger/calibration`).
The banded index (`LOW … SEVERE`) is the primary read; dollars are the input
to calibration conversations, not a promise.

The **human-oversight factor** is the interactive-scope insight (roadmap):
an action that passed a real human gate carries less residual risk than the
same action unattended — and a rubber-stamped gate is worth less than a real
one. The factor is derived from the HITL quality metrics when available.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Base values by Cisco data classification label (USD) — indicative magnitudes,
# expected to be overridden by per-org calibration.
BASE_VALUES: dict[str, float] = {
    "PUBLIC":        10.0,
    "INTERNAL":     100.0,
    "CONFIDENTIAL": 500.0,
    "RESTRICTED":  2000.0,
    "PII":         1000.0,
    "PHI":         5000.0,
}

REGULATORY_MULTIPLIERS: dict[str, float] = {
    "EU_AI_ACT_HIGH_RISK": 2.5,
    "CANADA_AIDA":         2.0,
    "STANDARD":            1.0,
}

BUSINESS_CONTEXT_MULTIPLIERS: dict[str, float] = {
    "CRITICAL":  1.5,   # Earnings, launch, fiscal close
    "ELEVATED":  1.2,
    "STANDARD":  1.0,
}

TIER_BLAST_WEIGHTS: dict[int, float] = {0: 1.0, 1: 1.5, 2: 2.5, 3: 4.0}
TIER_TIER_WEIGHTS: dict[int, float]  = {0: 1.0, 1: 2.5, 2: 5.0, 3: 10.0}

# Human-oversight factor (roadmap P2 ★): a real approval gate lowers residual
# risk; a rubber-stamped gate barely does; no gate changes nothing.
OVERSIGHT_FACTORS: dict[str, float] = {
    "none":              1.0,   # autonomous / no HITL evidence
    "gated":             0.6,   # interactive with a healthy approval gate
    "gated_low_quality": 0.9,   # gate present but rubber-stamp signals
}

# Exposure-index bands — the primary presentation (not false-precision dollars).
EXPOSURE_BANDS: tuple[tuple[float, str], ...] = (
    (10_000.0,    "LOW"),
    (100_000.0,   "MODERATE"),
    (1_000_000.0, "HIGH"),
)

METHODOLOGY = (
    "MPL is a calibrated exposure index, not a loss prediction. Base values are "
    "indicative magnitudes in the range of public breach-cost studies; calibrate "
    "them per org (POST /v1/ledger/calibration). Volume scales sublinearly "
    "(sqrt). The human-oversight factor discounts risk behind a healthy human "
    "approval gate (interactive scope) and withdraws most of that discount when "
    "rubber-stamping is detected. Read the band; treat the dollars as an input "
    "to calibration, not an output of prophecy."
)


@dataclass
class MPLInput:
    classification_label: str = "INTERNAL"
    volume_records: int = 1
    regulatory_regime: str = "STANDARD"
    hops: int = 1
    max_tier_in_chain: int = 0
    business_context: str = "STANDARD"
    agent_trust_tier: int = 0
    oversight: str = "none"     # none | gated | gated_low_quality


@dataclass
class MPLCalibration:
    """Per-org overrides (stored as the `mpl_calibration` setting)."""

    base_values: dict[str, float] = field(default_factory=dict)
    regulatory_multipliers: dict[str, float] = field(default_factory=dict)
    global_scale: float = 1.0
    currency: str = "USD"
    note: str = ""

    @classmethod
    def from_dict(cls, raw: dict | None) -> MPLCalibration:
        raw = raw or {}
        return cls(
            base_values={str(k).upper(): float(v)
                         for k, v in (raw.get("base_values") or {}).items()},
            regulatory_multipliers={str(k).upper(): float(v)
                                    for k, v in (raw.get("regulatory_multipliers") or {}).items()},
            global_scale=float(raw.get("global_scale", 1.0)),
            currency=str(raw.get("currency", "USD")),
            note=str(raw.get("note", "")),
        )

    def to_dict(self) -> dict:
        return {
            "base_values": dict(self.base_values),
            "regulatory_multipliers": dict(self.regulatory_multipliers),
            "global_scale": self.global_scale,
            "currency": self.currency,
            "note": self.note,
        }


def oversight_level(autonomy_mode: str, hitl_metrics: dict | None) -> str:
    """Pick the oversight factor from autonomy + observed HITL quality."""
    if autonomy_mode != "interactive":
        return "none"
    if not hitl_metrics or not hitl_metrics.get("asks_total"):
        return "none"           # interactive on paper; no gate evidence yet
    if hitl_metrics.get("rubber_stamp_risk"):
        return "gated_low_quality"
    return "gated"


def exposure_band(mpl_usd: float) -> str:
    for threshold, band in EXPOSURE_BANDS:
        if mpl_usd < threshold:
            return band
    return "SEVERE"


def calculate_mpl(inp: MPLInput, calibration: MPLCalibration | None = None) -> float:
    """Return the MPL exposure value (calibration currency, default USD)."""
    cal = calibration or MPLCalibration()
    base_values = {**BASE_VALUES, **cal.base_values}
    regulatory_multipliers = {**REGULATORY_MULTIPLIERS, **cal.regulatory_multipliers}

    base = base_values.get(inp.classification_label.upper(), base_values["INTERNAL"])
    volume_factor = max(1, inp.volume_records) ** 0.5   # Sublinear scaling
    regulatory = regulatory_multipliers.get(inp.regulatory_regime.upper(), 1.0)
    blast_radius = (1.0 + 0.1 * max(0, inp.hops - 1)) * TIER_BLAST_WEIGHTS.get(
        inp.max_tier_in_chain, 1.0
    )
    business = BUSINESS_CONTEXT_MULTIPLIERS.get(inp.business_context.upper(), 1.0)
    tier_weight = TIER_TIER_WEIGHTS.get(inp.agent_trust_tier, 1.0)
    oversight = OVERSIGHT_FACTORS.get(inp.oversight, 1.0)

    return ((base * volume_factor) * regulatory * blast_radius * business
            * tier_weight * oversight * cal.global_scale)


def mpl_report(inp: MPLInput, calibration: MPLCalibration | None = None) -> dict:
    """The full exposure-index report the API serves."""
    cal = calibration or MPLCalibration()
    value = calculate_mpl(inp, cal)
    return {
        "exposure": round(value, 2),
        "currency": cal.currency,
        "band": exposure_band(value),
        "oversight_factor": OVERSIGHT_FACTORS.get(inp.oversight, 1.0),
        "calibrated": bool(cal.base_values or cal.regulatory_multipliers
                           or cal.global_scale != 1.0),
        "methodology": METHODOLOGY,
    }
