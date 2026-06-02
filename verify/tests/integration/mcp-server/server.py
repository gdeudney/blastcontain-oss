"""
MCP test server — implements JSON-RPC 2.0 MCP protocol over HTTP.

/dirty  — returns a dangerous tool set (Read+Send+Credential+Execute+Write)
/clean  — returns a safe read-only tool set
/health — liveness check

The cisco-ai-mcp-scanner calls scan_remote_server_tools(url=...) which
performs: initialize → tools/list over HTTP POST (Streamable HTTP transport).
"""
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="BlastContain MCP Test Server")

# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

DIRTY_TOOLS = [
    {
        "name": "read_file",
        "description": "Read file contents from the local filesystem",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "http_post",
        "description": "POST data to any external HTTP endpoint — supports arbitrary URLs",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url":     {"type": "string"},
                "payload": {"type": "object"},
            },
            "required": ["url", "payload"],
        },
    },
    {
        "name": "get_secret",
        "description": "Retrieve secrets and API credentials from the vault",
        "inputSchema": {
            "type": "object",
            "properties": {"secret_name": {"type": "string"}},
            "required": ["secret_name"],
        },
    },
    {
        "name": "exec",
        "description": "Execute arbitrary shell commands on the host",
        "inputSchema": {
            "type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"],
        },
    },
    {
        "name": "write_file",
        "description": "Write arbitrary content to any path on the filesystem",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path":    {"type": "string"},
                "content": {"type": "string"},
            },
            "required": ["path", "content"],
        },
    },
]

CLEAN_TOOLS = [
    {
        "name": "search_knowledge_base",
        "description": "Search the internal knowledge base for relevant documents",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "top_k": {"type": "integer", "default": 5},
            },
            "required": ["query"],
        },
    },
    {
        "name": "get_ticket_status",
        "description": "Get the status of a support ticket by its ID",
        "inputSchema": {
            "type": "object",
            "properties": {"ticket_id": {"type": "string"}},
            "required": ["ticket_id"],
        },
    },
    {
        "name": "get_weather",
        "description": "Retrieve current weather for a city from the internal weather API",
        "inputSchema": {
            "type": "object",
            "properties": {
                "city":    {"type": "string"},
                "country": {"type": "string"},
            },
            "required": ["city"],
        },
    },
]

# ---------------------------------------------------------------------------
# MCP JSON-RPC handler
# ---------------------------------------------------------------------------

def _handle(body: dict, tools: list[dict]) -> dict:
    method = body.get("method", "")
    req_id = body.get("id", 1)

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {
                    "name": "blastcontain-test-server",
                    "version": "1.0.0",
                },
            },
        }

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"tools": tools},
        }

    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}

    # Unknown method — return empty result (not an error, for forward compat)
    return {"jsonrpc": "2.0", "id": req_id, "result": {}}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/dirty")
@app.post("/dirty/")
async def dirty_mcp(request: Request):
    body = await request.json()
    if isinstance(body, list):
        return JSONResponse([_handle(b, DIRTY_TOOLS) for b in body])
    return JSONResponse(_handle(body, DIRTY_TOOLS))


@app.post("/clean")
@app.post("/clean/")
async def clean_mcp(request: Request):
    body = await request.json()
    if isinstance(body, list):
        return JSONResponse([_handle(b, CLEAN_TOOLS) for b in body])
    return JSONResponse(_handle(body, CLEAN_TOOLS))


# Root endpoint — acts as both dirty and clean based on Accept header or param
@app.post("/")
async def root_mcp(request: Request, profile: str = "dirty"):
    body = await request.json()
    tools = DIRTY_TOOLS if profile == "dirty" else CLEAN_TOOLS
    if isinstance(body, list):
        return JSONResponse([_handle(b, tools) for b in body])
    return JSONResponse(_handle(body, tools))
