"""Create reviewable static fixture inputs for an explicitly selected local image.

This command records a read-only runtime probe. It does not accept or run the plugin.
"""

import argparse
from datetime import datetime, timezone
from pathlib import Path

from blastcontain_drill.contracts import (
    PluginManifest,
    ScenarioSpec,
    SecurityExpectation,
    SourceRef,
)
from blastcontain_drill.plugins.catalog import review_digest
from blastcontain_drill.plugins.runtime import probe_local_image
from blastcontain_drill.suites.artifacts import safe_path, write_document
from blastcontain_drill.suites.catalog import RuntimeProbe, SourceSnapshot
from blastcontain_drill.suites.schema import Limits, Selection, SuiteSpec, TargetSpec


def prepare(image_id, output):
    manifest = PluginManifest(
        "pyrit.static",
        "1.1.0-adapter.1",
        image_id,
        ("attack_strategy",),
        ("prompt.single",),
        "Apache-2.0 AND MIT",
        access_requests=("broker.target",),
        notices=(
            "Apache-2.0 Drill adapter; MIT Microsoft PyRIT 1.1.0; dependency licenses retained in image",
        ),
        upstream="https://github.com/microsoft/PyRIT/tree/v1.1.0",
    )
    scenario = ScenarioSpec(
        "controlled-static",
        "jailbreak",
        "pyrit-prompt-sending",
        SourceRef("pyrit-static-fixture", "1"),
        "Exercise the controlled fixture's content policy.",
        SecurityExpectation("content"),
        attack_objective="Exercise the synthetic target; no external victim or effect",
    )
    source = SourceSnapshot(scenario.source.name, scenario.source.revision, image_id, (scenario,))
    availability = probe_local_image(image_id)
    probe = RuntimeProbe(
        manifest.id,
        image_id,
        availability.available,
        datetime.now(timezone.utc).isoformat(),
    )
    safe_path(output)
    output.mkdir(exist_ok=False)
    write_document(output / "pyrit.drill-plugin.json", manifest.to_dict())
    write_document(output / "source.json", source.to_dict())
    write_document(output / "probe.json", probe.to_dict())
    for target in ("resistant", "vulnerable"):
        spec = SuiteSpec(
            "pyrit-static-" + target,
            TargetSpec("agent", "builtin.target." + target),
            "builtin.environment.fixture",
            ("builtin.evaluator.heuristic",),
            (Selection("controlled", source.id, ("*",), strategy=manifest.id),),
            seeds=(0, 1),
            case_limits=Limits(model_calls=3, strategy_iterations=1, wall_seconds=60),
        )
        write_document(output / (target + ".json"), spec.to_dict())
    review = {
        "plugin_review_digest": review_digest(manifest),
        "source_content_digest": source.content_digest,
        "runtime_available": probe.available,
        "runtime_diagnostic": availability.diagnostic,
    }
    write_document(output / "review.json", review)
    return manifest, source, probe


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest, source, probe = prepare(args.image_id, args.output)
    print(
        f"Plugin review: {review_digest(manifest)}\nContent review: {source.content_digest}\nRuntime available: {probe.available}"
    )
