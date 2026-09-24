"""
Multi-agent delegation scenario for integration testing.

Simulates a TIER_0 orchestrator delegating to a TIER_2 sub-agent.
Used to test blast radius amplification and delegation chain detection.
"""
import os
import sys
import httpx

BLASTCONTAIN_URL = os.environ.get("BLASTCONTAIN_URL", "http://localhost:8080")
AGENT_URL = os.environ.get("AGENT_URL", "http://agent:8081")


def run_scenario():
    print("Multi-agent delegation scenario starting...")

    # Simulate TIER_0 orchestrator calling TIER_2 sub-agent
    delegation_chain = [
        {"agent_id": "orchestrator", "tier": 0},
        {"agent_id": "specialist-agent", "tier": 2},  # Trust boundary hop
    ]

    max_tier = max(a["tier"] for a in delegation_chain)
    print(f"Delegation chain max tier: {max_tier}")

    # Post delegation event to Ledger
    try:
        resp = httpx.post(
            f"{BLASTCONTAIN_URL}/v1/agents/orchestrator/findings",
            json={
                "agent_id": "orchestrator",
                "environment": "test",
                "scan_id": "integration-test-001",
                "status": "APPROVED",
                "findings": [],
                "delegation_chain": delegation_chain,
                "blast_radius_factor": 2.5,  # TIER_2 = 2.5x
            },
            timeout=10,
        )
        print(f"Ledger POST: {resp.status_code}")
    except Exception as e:
        print(f"Ledger not reachable: {e}")

    print("Scenario complete.")
    return 0


if __name__ == "__main__":
    sys.exit(run_scenario())
