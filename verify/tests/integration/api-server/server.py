"""
API test server — serves OpenAPI specs over HTTP.

Endpoints:
  GET /dirty/openapi.yaml  — spec with destructive + unauthenticated endpoints
  GET /clean/openapi.yaml  — spec with all endpoints secured
  GET /health              — liveness check

The current API-01/API-02 checks read local files, not live URLs.
This server exists for:
  1. Future: test remote spec fetching
  2. Realism: demonstrates what the dangerous/safe APIs actually look like
  3. CI smoke test: confirms the test network is healthy

The dirty spec is also embedded here so the server is self-contained.
"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse

app = FastAPI(title="BlastContain API Test Server")

# ---------------------------------------------------------------------------
# Embedded specs (mirrored from fixtures/dirty/openapi.yaml etc.)
# ---------------------------------------------------------------------------

DIRTY_SPEC = """\
openapi: "3.0.3"
info:
  title: Dangerous Test API
  version: "1.0.0"
paths:
  /users/{id}:
    delete:
      summary: Delete user account
      operationId: deleteUser
      parameters:
        - name: id
          in: path
          required: true
          schema: { type: string }
      responses:
        "204": { description: Deleted }
  /admin/destroy:
    post:
      summary: Destroy all admin resources
      operationId: destroyAdminResources
      responses:
        "200": { description: Destroyed }
  /data/wipe:
    post:
      summary: Wipe namespace data
      operationId: wipeData
      responses:
        "200": { description: Wiped }
  /reports:
    get:
      summary: List reports
      operationId: listReports
      responses:
        "200": { description: OK }
"""

CLEAN_SPEC = """\
openapi: "3.0.3"
info:
  title: Safe Test API
  version: "1.0.0"
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
security:
  - bearerAuth: []
paths:
  /tickets:
    get:
      summary: List tickets
      operationId: listTickets
      security:
        - bearerAuth: []
      responses:
        "200": { description: OK }
  /status:
    get:
      summary: Health status
      operationId: getStatus
      security:
        - bearerAuth: []
      responses:
        "200": { description: OK }
"""

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/dirty/openapi.yaml", response_class=PlainTextResponse)
async def dirty_spec():
    return PlainTextResponse(DIRTY_SPEC, media_type="application/yaml")


@app.get("/dirty/openapi.json")
async def dirty_spec_json():
    import yaml
    return yaml.safe_load(DIRTY_SPEC)


@app.get("/clean/openapi.yaml", response_class=PlainTextResponse)
async def clean_spec():
    return PlainTextResponse(CLEAN_SPEC, media_type="application/yaml")


@app.get("/clean/openapi.json")
async def clean_spec_json():
    import yaml
    return yaml.safe_load(CLEAN_SPEC)
