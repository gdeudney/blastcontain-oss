"""Read-only plugin diagnostics. No build, pull, import, acceptance or execution."""

from dataclasses import asdict
import json
from pathlib import Path

import click

from ..contracts import ContractError
from .catalog import discover, read_acceptances
from .runtime import local_image_available


@click.command()
@click.option(
    "--directory",
    multiple=True,
    required=True,
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Explicit directory containing *.drill-plugin.json metadata; repeatable.",
)
@click.option("--acceptances", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--probe-runtime", is_flag=True, help="Check local Podman image presence without starting it."
)
def main(directory, acceptances, probe_runtime):
    """List registered plugins and separate acceptance, compatibility and availability."""
    try:
        statuses = discover(
            directory,
            read_acceptances(acceptances),
            local_image_available if probe_runtime else None,
        )
    except (ContractError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc
    output = []
    for status in statuses:
        row = asdict(status)
        row.pop("manifest")
        output.append(row)
    click.echo(json.dumps({"schema_version": 1, "plugins": output}, indent=2))


if __name__ == "__main__":
    main()
