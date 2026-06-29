"""One agent. The SAME code for every mode — only the config file differs.

    python examples/agent.py examples/mode-guard-only.yaml
    python examples/agent.py examples/mode-guard-agt.yaml     # start demo_agt_server.py first
    python examples/agent.py examples/mode-agt-only.yaml      # start demo_agt_server.py first

Nothing below changes between guard-only, guard+AGT, and AGT-only. The mode lives
entirely in the config you point it at (`Guard.from_config`).
"""
import sys

from blastcontain_guard import AskChoice, Guard, GuardDenied

try:  # Windows consoles default to cp1252; the real CLI does this for you.
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

# ── the ONLY thing that varies between modes: which config we load ──
config_path = sys.argv[1] if len(sys.argv) > 1 else "examples/mode-guard-only.yaml"
guard = Guard.from_config(config_path, on_ask=lambda req: AskChoice.ALLOW_ONCE)
print(f"# {guard.describe_mode()}   (config: {config_path})")


# ── the agent and its tools — identical in every mode ──
@guard.tool
def query_invoice(invoice_id):
    return f"invoice {invoice_id}: $420"


@guard.tool(action_type="delete")
def delete_invoice(invoice_id):
    return f"deleted {invoice_id}"


@guard.tool(action_type="send")
def send_invoice(to, body):
    return f"sent to {to}"


def run_agent():
    calls = [
        ("query_invoice", lambda: query_invoice("INV-1")),
        ("delete_invoice", lambda: delete_invoice("INV-1")),
        ("send_invoice", lambda: send_invoice("ext@vendor.com", "ledger.csv")),
    ]
    for label, call in calls:
        try:
            print(f"  ALLOW  {label:<15} -> {call()}")
        except GuardDenied as exc:
            print(f"  DENY   {label:<15} -> {exc.result.decision.reason}")


run_agent()
guard.close()
