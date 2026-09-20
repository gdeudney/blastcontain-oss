"""Run an explicitly selected reference image with temporary fixture acceptance."""

import argparse
import asyncio
from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path

from blastcontain_drill.contracts import (
    AcceptanceRecord,
    PluginManifest,
    ScenarioSpec,
    SecurityExpectation,
    SourceRef,
)
from blastcontain_drill.plugins.catalog import review_digest
from blastcontain_drill.plugins.runtime import PodmanWorker, WorkerLimits


async def run(image_id, output):
    output.mkdir(parents=True, exist_ok=False)
    manifest = PluginManifest(
        "reference-strategy",
        "1.0",
        image_id,
        ("attack_strategy",),
        ("prompt.single",),
        "Apache-2.0",
        access_requests=("broker.target",),
    )
    # This is explicitly a fixture acceptance, not a human identity assertion or
    # production registry mutation. Nothing is added to global configuration.
    record = AcceptanceRecord(
        manifest.id,
        "plugin",
        review_digest(manifest),
        "reference-demo",
        "accepted",
        datetime.now(timezone.utc).isoformat(),
        "Temporary acceptance for the operator-selected reference demo image",
        manifest.access_requests,
    )
    (output / "reference.drill-plugin.json").write_text(json.dumps(manifest.to_dict(), indent=2))
    (output / "acceptances.json").write_text(
        json.dumps({"schema_version": 1, "records": [record.to_dict()]}, indent=2)
    )
    scenario = ScenarioSpec(
        "reference-case",
        "controlled-demo",
        "sequential-refinement",
        SourceRef("reference-fixture", "v1"),
        "Run a controlled fixture request.",
        SecurityExpectation("content"),
        attack_objective="Exercise bounded broker calls",
    )

    async def target(injection, context):
        return {
            "response_text": "Controlled resistant fixture response",
            "scenario_id": context.scenario_id,
        }

    worker = PodmanWorker(
        manifest, [record], bindings={"target": target}, limits=WorkerLimits(max_calls=2)
    )
    async with worker:
        await worker.prepare()
        await worker.reset(scenario)
        result = await worker.execute()
        await worker.finish()
    evidence = {
        "fixture_only": True,
        "container": worker.name,
        "image_id": image_id,
        "review_digest": review_digest(manifest),
        "worker_claims": result.claims,
        "host_observed_calls": [asdict(call) for call in result.calls],
        "cleanup_completed": True,
    }
    (output / "result.json").write_text(json.dumps(evidence, indent=2))
    print(
        f"Reference worker completed {len(result.calls)} brokered calls; container removed. Evidence: {output}"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--image-id", required=True, help="Local sha256 image ID built from this reference plugin"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="New directory for fixture metadata and result",
    )
    args = parser.parse_args()
    asyncio.run(run(args.image_id, args.output_dir))
