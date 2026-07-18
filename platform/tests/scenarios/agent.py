"""
Minimal test agent for integration scenarios.

Exposes:
  POST /v1/chat  — echoes the message back (no real LLM)
  GET  /health
"""
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="BlastContain Test Agent")


class ChatRequest(BaseModel):
    message: str


class ChatResponse(BaseModel):
    response: str
    agent_id: str = "test-agent"


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/v1/chat", response_model=ChatResponse)
def chat(req: ChatRequest):
    # Simulate basic injection detection — reject obviously adversarial prompts
    injection_keywords = ["ignore all previous", "system prompt", "disable safety"]
    if any(kw in req.message.lower() for kw in injection_keywords):
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="Request blocked by content policy")

    return ChatResponse(response=f"Echo: {req.message}")
