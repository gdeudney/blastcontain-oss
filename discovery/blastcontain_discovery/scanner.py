"""blastcontain_discovery — scan orchestrator."""
from __future__ import annotations

import datetime

from . import __version__
from .models import AssetClassification, DiscoveredAsset, DiscoveryReport
from .scanners import bootstrap, copilot, process, registry, repo


def _now() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_discovery(
    environment: str,
    search_path: str = ".",
    process_scan: bool = True,
    copilot_scan: bool = True,
    blastcontain_url: str = "",
    token: str | None = None,
    bootstrap_charter: bool = False,
    charter_output_dir: str = "./charters",
    *,
    now: str | None = None,
) -> DiscoveryReport:
    """Run the enabled scanners, classify against the registry, optionally
    bootstrap draft Charters for shadow finds, and return a DiscoveryReport."""
    assets: list[DiscoveredAsset] = []

    if process_scan:
        assets.extend(process.scan())
    if search_path:
        assets.extend(repo.scan(search_path=search_path))
    if copilot_scan:
        assets.extend(copilot.scan(search_path=search_path or None))

    if blastcontain_url:
        assets = registry.classify_against_registry(
            assets, blastcontain_url, environment, token=token
        )

    if bootstrap_charter:
        for asset in assets:
            if asset.classification != AssetClassification.UNKNOWN_SHADOW_AI:
                continue
            if blastcontain_url:
                ref = bootstrap.bootstrap_platform(
                    asset, blastcontain_url, environment=environment, token=token
                )
                asset.draft_charter_ref = ref or bootstrap.bootstrap_local(
                    asset, output_dir=charter_output_dir, environment=environment
                )
            else:
                asset.draft_charter_ref = bootstrap.bootstrap_local(
                    asset, output_dir=charter_output_dir, environment=environment
                )

    return DiscoveryReport(
        environment=environment,
        scanned_at=now or _now(),
        assets=assets,
        generator_version=__version__,
    )
