"""
Supply chain checks: SUP-01.

SUP-01  Model weights present without attestation files.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from ..models import InfraFinding, Severity
from ..constants import MIT_RISK_MAP, MODEL_EXTENSIONS, ATTESTATION_EXTENSIONS, ATTESTATION_FILENAMES
from ..augmentation import AGT_AVAILABLE


def _finding(check_id: str, finding_type: str, severity: Severity,
             title: str, detail: str, remediation: str,
             references: Optional[list[str]] = None,
             evidence: Optional[str] = None) -> InfraFinding:
    mit = MIT_RISK_MAP.get(finding_type, (None, None, None))
    return InfraFinding(
        check_id=check_id, finding_type=finding_type, severity=severity,
        title=title, detail=detail, remediation=remediation,
        references=references or [], evidence=evidence,
        mit_domain=mit[0], mit_causal_id=mit[1], mit_causal_label=mit[2],
    )


def _has_attestation(model_path: str) -> bool:
    """Check if a model weight file has an attestation file alongside it."""
    model_p = Path(model_path)
    parent = model_p.parent

    # Accept both common attestation naming conventions:
    #   <model_name>.<ext>   e.g. weights.safetensors.sha256
    #   <model_stem>.<ext>   e.g. weights.sha256
    for ext in ATTESTATION_EXTENSIONS:
        if (parent / (model_p.name + ext)).exists():
            return True
        if (parent / (model_p.stem + ext)).exists():
            return True

    # Check for manifest / checksums in same directory
    for fname in ATTESTATION_FILENAMES:
        if (parent / fname).exists():
            return True

    return False


def check_sup01_model_weight_attestation(model_dir: str) -> tuple[list[InfraFinding], str]:
    """SUP-01: Model weights without attestation."""
    if not model_dir or not os.path.isdir(model_dir):
        return [], "SKIP"

    unattested: list[str] = []
    for root, dirs, files in os.walk(model_dir, followlinks=False):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for filename in files:
            if Path(filename).suffix.lower() in MODEL_EXTENSIONS:
                filepath = os.path.join(root, filename)
                if not _has_attestation(filepath):
                    rel = os.path.relpath(filepath, model_dir)
                    unattested.append(rel)

    if not unattested:
        return [], "PASS"

    scanner_note = " (AGT SupplyChainGuard not installed)" if not AGT_AVAILABLE else ""

    return [_finding(
        check_id="SUP-01",
        finding_type="blastcontain.supply_chain.unsigned_weights",
        severity=Severity.HIGH,
        title="Model Weights Without Attestation",
        detail=(
            f"Found {len(unattested)} model weight file(s) in `{model_dir}` without "
            f"an accompanying attestation file (`.sha256`, `.sig`, `.asc`, or "
            f"`manifest.json`){scanner_note}. "
            "Unattested model weights could have been tampered with in the supply chain "
            "— the agent has no way to verify it is running the model it was certified on."
        ),
        remediation=(
            "For each model file:\n"
            "1. Generate a SHA-256 checksum: `sha256sum model.bin > model.bin.sha256`\n"
            "2. Verify at container startup: `sha256sum -c model.bin.sha256`\n"
            "3. Sign with a GPG key or Sigstore for stronger attestation.\n"
            "4. Prefer models distributed via Hugging Face with verified commit hashes."
        ),
        references=[
            "https://www.sigstore.dev/",
            "https://huggingface.co/docs/hub/security-pickle",
        ],
        evidence=f"Unattested: {', '.join(unattested[:5])}{'...' if len(unattested) > 5 else ''}",
    )], "FAIL"


def run(model_dir: str = "/models", **_) -> tuple[list[InfraFinding], list[str], list[dict]]:
    findings: list[InfraFinding] = []
    passed: list[str] = []
    skipped: list[dict] = []

    result_findings, status = check_sup01_model_weight_attestation(model_dir)
    if status == "PASS":
        passed.append("SUP-01")
    elif status == "SKIP":
        skipped.append({"check_id": "SUP-01", "reason": f"Model directory {model_dir!r} not found"})
    else:
        findings.extend(result_findings)

    return findings, passed, skipped
