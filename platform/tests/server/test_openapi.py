"""The curated OpenAPI document stays pinned to the registered routes."""
from __future__ import annotations

from pathlib import Path

import yaml

SPEC_PATH = Path(__file__).resolve().parents[2] / "server" / "docs" / "openapi.yaml"

# FastAPI internals that are not part of the public contract.
_INTERNAL_PATHS = {"/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"}


def _spec() -> dict:
    return yaml.safe_load(SPEC_PATH.read_text(encoding="utf-8"))


def _spec_operations(spec: dict) -> set[tuple[str, str]]:
    operations = set()
    for path, item in spec["paths"].items():
        for method in ("get", "post", "put", "patch", "delete"):
            if method in item:
                operations.add((method.upper(), path))
    return operations


def _app_operations(app) -> set[tuple[str, str]]:
    operations = set()
    for route in app.routes:
        if not hasattr(route, "methods") or route.path in _INTERNAL_PATHS:
            continue
        for method in route.methods - {"HEAD", "OPTIONS"}:
            operations.add((method, route.path))
    return operations


def test_spec_matches_registered_routes(app):
    spec_ops = _spec_operations(_spec())
    app_ops = _app_operations(app)
    missing_from_spec = app_ops - spec_ops
    stale_in_spec = spec_ops - app_ops
    assert not missing_from_spec, (
        f"routes not documented in server/docs/openapi.yaml: {sorted(missing_from_spec)}"
    )
    assert not stale_in_spec, (
        f"documented routes that no longer exist: {sorted(stale_in_spec)}"
    )


def test_every_operation_has_summary_id_and_responses():
    spec = _spec()
    for path, item in spec["paths"].items():
        for method in ("get", "post", "put", "patch", "delete"):
            operation = item.get(method)
            if operation is None:
                continue
            where = f"{method.upper()} {path}"
            assert operation.get("summary"), f"{where}: missing summary"
            assert operation.get("operationId"), f"{where}: missing operationId"
            assert operation.get("responses"), f"{where}: missing responses"


def test_operation_ids_are_unique():
    spec = _spec()
    seen: dict[str, str] = {}
    for path, item in spec["paths"].items():
        for method in ("get", "post", "put", "patch", "delete"):
            operation = item.get(method)
            if operation is None:
                continue
            op_id = operation["operationId"]
            assert op_id not in seen, (
                f"duplicate operationId {op_id!r}: {seen[op_id]} and {method.upper()} {path}"
            )
            seen[op_id] = f"{method.upper()} {path}"


def test_app_serves_the_curated_spec(client):
    served = client.get("/openapi.json").json()
    curated = _spec()
    assert served["info"]["title"] == curated["info"]["title"]
    assert set(served["paths"]) == set(curated["paths"])
    # The curated spec carries real body schemas, not bare dicts.
    sign_op = served["paths"]["/v1/charters/{agent_id}/sign"]["post"]
    schema = sign_op["requestBody"]["content"]["application/json"]["schema"]
    assert "actor" in schema["properties"]


def test_swagger_ui_loads(client):
    assert client.get("/docs").status_code == 200


def test_spec_component_refs_resolve():
    spec = _spec()
    components = spec.get("components", {})

    def walk(node):
        if isinstance(node, dict):
            ref = node.get("$ref")
            if isinstance(ref, str) and ref.startswith("#/components/"):
                _, _, kind, name = ref.split("/")
                assert name in components.get(kind, {}), f"dangling $ref: {ref}"
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(spec)
