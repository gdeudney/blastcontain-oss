"""Launch the local acceptance and run workbench."""

from pathlib import Path
import signal

import click

from ..suites.commands import credential_resolver, safe_errors
from ..suites.privacy import read_private
from ..suites.signatures import Signer
from .research import Research
from .server import WorkbenchServer
from .service import Runs, Workspace


@click.command()
@click.option(
    "--workspace",
    type=click.Path(path_type=Path),
    required=True,
    help="New or owner-only workbench directory; separate from your source checkout.",
)
@click.option(
    "--port",
    type=click.IntRange(0, 65535),
    default=0,
    show_default=True,
    help="Loopback port; zero chooses an available port.",
)
@click.option(
    "--signing-key",
    type=click.Path(exists=True, path_type=Path),
    help="Explicit private Ed25519 PEM; otherwise results are advisory.",
)
@click.option(
    "--credential", multiple=True, help="Host-only REF=ENVIRONMENT_VARIABLE credential mapping."
)
@click.option(
    "--scout-database",
    type=click.Path(path_type=Path),
    help="Explicit writable Scout database; initializes/upgrades it for review.",
)
@click.option(
    "--repository",
    type=click.Path(exists=True, path_type=Path),
    help="Local Git repository for read-only research provenance.",
)
@safe_errors
def main(workspace, port, signing_key, credential, scout_database, repository):
    """Review scope, compose accepted suites and inspect bounded Agent/MCP fixture runs."""
    state = runs = server = None
    old_term = signal.getsignal(signal.SIGTERM)

    def stop(*args):
        raise KeyboardInterrupt

    try:
        signal.signal(signal.SIGTERM, stop)
        state = Workspace(workspace)
        signer = Signer.from_pem(read_private(signing_key, 16384)) if signing_key else None
        runs = Runs(state, signer=signer, credentials=credential_resolver(credential))
        server = WorkbenchServer(state, runs, Research(scout_database, repository), port=port)
        click.echo("Drill local workbench: " + server.launch_url)
        click.echo(
            "Open this one-use link within five minutes. Ctrl+C stops the UI and cancels active work."
        )
        try:
            server.serve_forever(poll_interval=0.2)
        except KeyboardInterrupt:
            pass
    finally:
        signal.signal(signal.SIGTERM, old_term)
        if server:
            server.server_close()
        try:
            if runs:
                runs.close()
        finally:
            if state:
                state.close()


if __name__ == "__main__":
    main()
