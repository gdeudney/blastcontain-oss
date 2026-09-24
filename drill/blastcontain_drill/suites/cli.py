"""Plan offline; explicitly execute, stop and verify accepted fixture suites."""

from pathlib import Path

import click

from ..contracts import ContractError, PluginManifest
from ..plugins.catalog import read_acceptances, read_metadata
from .artifacts import canonical, read_document, safe_path, write_document
from .catalog import RuntimeProbe, SourceSnapshot, builtin_catalog
from .lock import SuiteLock, create_lock, validate_lock
from .planner import plan_suite
from .schema import SuiteSpec

INPUT = click.Path(exists=True, dir_okay=False, path_type=Path)
OUTPUT = click.Path(dir_okay=False, path_type=Path)


def inputs(command):
    for name, help_text in (
        ("--source", "Materialized external SourceSnapshot JSON; repeatable."),
        ("--plugin", "Explicit PluginManifest JSON; repeatable. Never imported."),
        ("--probe", "Previously recorded RuntimeProbe JSON; repeatable. No live probing."),
    ):
        command = click.option(name, multiple=True, type=INPUT, help=help_text)(command)
    return click.option("--acceptances", type=INPUT, help="Current local decision history.")(
        command
    )


def load_inputs(source, plugin, probe, acceptances):
    for path in (*source, *plugin, *probe, *((acceptances,) if acceptances else ())):
        safe_path(path)
    catalog = builtin_catalog(
        external_sources=tuple(SourceSnapshot.from_dict(read_document(p)) for p in source),
        plugins=tuple(PluginManifest.from_dict(read_metadata(p)) for p in plugin),
    )
    return (
        catalog,
        read_acceptances(acceptances),
        tuple(RuntimeProbe.from_dict(read_document(p)) for p in probe),
    )


@click.group()
def main():
    """Review, run and verify accepted Agent/MCP fixture suites."""


@main.command("plan")
@click.argument("suite", type=INPUT)
@inputs
@click.option("--output", type=OUTPUT, help="Write plan JSON to a new file (default: stdout).")
@click.option(
    "--lock",
    "lock_path",
    type=OUTPUT,
    help="Also write a lock; requires current acceptance of the resolved content digest.",
)
def plan_command(suite, source, plugin, probe, acceptances, output, lock_path):
    """Resolve selected cases without executing them. Blocked plans exit nonzero."""
    try:
        catalog, records, probes = load_inputs(source, plugin, probe, acceptances)
        plan = plan_suite(
            SuiteSpec.from_dict(read_document(suite)), catalog, records=records, probes=probes
        )
        data = {
            "schema_version": 1,
            "content_digest": plan.content_digest,
            "ready": plan.ready,
            "plan": plan.to_dict(),
        }
        if output is None:
            click.echo(canonical(data).decode("utf-8"))
        else:
            write_document(output, data)
        click.echo(
            f"Plan {plan.content_digest}: {len(plan.cases)} cases; "
            f"{sum(c.disposition == 'ready' for c in plan.cases)} ready, "
            f"{sum(c.disposition == 'blocked' for c in plan.cases)} blocked, "
            f"{sum(c.disposition == 'excluded' for c in plan.cases)} excluded.",
            err=True,
        )
        if not plan.ready:
            raise ContractError("Plan is blocked or has no ready cases; inspect case diagnostics")
        if lock_path is not None:
            lock = create_lock(plan, catalog, records=records, probes=probes)
            write_document(lock_path, lock.to_dict())
            click.echo(f"Lock {lock.lock_digest} written to {lock_path}", err=True)
    except (ContractError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc


@main.command("check-lock")
@click.argument("lock_path", type=INPUT)
@inputs
def check_lock_command(lock_path, source, plugin, probe, acceptances):
    """Revalidate against current data and decisions; this is not runtime attestation."""
    try:
        catalog, records, probes = load_inputs(source, plugin, probe, acceptances)
        lock = SuiteLock.from_dict(read_document(lock_path))
        validate_lock(lock, catalog, records=records, probes=probes)
        click.echo(f"Lock {lock.lock_digest} matches current planning inputs and acceptance.")
    except (ContractError, OSError) as exc:
        raise click.ClickException(str(exc)) from exc


from .commands import register  # noqa: E402

register(main, inputs, load_inputs)


if __name__ == "__main__":
    main()
