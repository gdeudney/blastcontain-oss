"""Run from guard/: python examples/quickstart.py. Tools return mock data only."""
from blastcontain_guard import AskChoice, Guard, GuardDenied
from blastcontain_guard.telemetry import JsonlSink


def prompt(request):
    answer = input(f"Allow {request.tool_name} once? [y/N] ").strip().lower()
    return AskChoice.ALLOW_ONCE if answer == "y" else AskChoice.DENY


guard = Guard.from_yaml(
    "examples/policy.yaml",
    on_ask=prompt,
    extra_sinks=[JsonlSink("decisions.jsonl")],
)


@guard.tool(action_type="read")
def query_invoice(invoice_id):
    return f"mock invoice {invoice_id}: $420"


@guard.tool(action_type="delete")
def delete_invoice(invoice_id):
    return f"mock deletion of {invoice_id} (no data changed)"


@guard.tool(action_type="send")
def send_invoice(invoice_id):
    return f"mock send of {invoice_id} (nothing sent)"


try:
    for tool in (query_invoice, delete_invoice, send_invoice):
        try:
            print(f"ALLOW {tool.__name__}: {tool('INV-1')}")
        except GuardDenied as exc:
            print(f"DENY {tool.__name__}: {exc.result.decision.reason}")
    guard.write_decision_log("decisions.json")
finally:
    guard.close()
