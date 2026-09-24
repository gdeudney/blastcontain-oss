/**
 * Typed API client for the BlastContain platform.
 *
 * Types come from src/lib/api/schema.d.ts, generated from
 * server/docs/openapi.yaml (regenerate: pwsh gui/dev.ps1 gen-api).
 *
 * Two modes (NEXT_PUBLIC_API_MODE):
 *   - "mock" (default): spec-shaped fixtures from ./mock — the clickable
 *     prototype needs no backend.
 *   - "real": same-origin /api/* calls, rewritten by next.config.ts to the
 *     platform server — the browser never needs CORS.
 */
import type { components, paths } from "./schema";
import * as mock from "./mock";

export type Schemas = components["schemas"];
export type CharterDocument = Schemas["CharterDocument"];
export type CompiledPolicy = Schemas["CompiledPolicy"];
export type CompileConflict = Schemas["CompileConflict"];
export type SignedCharterBundle = Schemas["SignedCharterBundle"];
export type LifecycleState = Schemas["LifecycleState"];

export type FleetResponse =
  paths["/fleet"]["get"]["responses"]["200"]["content"]["application/json"];
export type ViolationsResponse =
  paths["/violations"]["get"]["responses"]["200"]["content"]["application/json"];
export type DeriveResponse =
  paths["/v1/charters/{agent_id}/derive"]["post"]["responses"]["201"]["content"]["application/json"];
export type SignResponse =
  paths["/v1/charters/{agent_id}/sign"]["post"]["responses"]["200"]["content"]["application/json"];
export type CreateDraftResponse =
  paths["/v1/charters"]["post"]["responses"]["201"]["content"]["application/json"];

export const API_MODE: "mock" | "real" =
  process.env.NEXT_PUBLIC_API_MODE === "real" ? "real" : "mock";

export class ApiError extends Error {
  status: number;
  detail: unknown;
  constructor(status: number, detail: unknown) {
    super(typeof detail === "string" ? detail : `HTTP ${status}`);
    this.status = status;
    this.detail = detail;
  }
}

function token(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem("bc_token");
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init?.headers as Record<string, string>),
  };
  const t = token();
  if (t) headers["Authorization"] = `Bearer ${t}`;
  const res = await fetch(`/api${path}`, { ...init, headers });
  const body = await res.json().catch(() => null);
  if (!res.ok) throw new ApiError(res.status, body?.detail ?? body);
  return body as T;
}

// ── The calls the console uses ────────────────────────────────────────────────

export function getFleet(): Promise<FleetResponse> {
  if (API_MODE === "mock") return mock.getFleet();
  return call("/fleet");
}

export function listViolations(): Promise<ViolationsResponse> {
  if (API_MODE === "mock") return mock.listViolations();
  return call("/violations");
}

export function deriveCharter(
  agentId: string,
  env: string,
  body: {
    autonomy_mode?: string;
    base_strictness?: string;
    owner?: string;
    observed?: { tools?: string[]; trust_tier?: number };
  },
): Promise<DeriveResponse> {
  if (API_MODE === "mock") return mock.deriveCharter(agentId, env, body);
  return call(`/v1/charters/${encodeURIComponent(agentId)}/derive?env=${encodeURIComponent(env)}`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export function createDraft(doc: CharterDocument): Promise<CreateDraftResponse> {
  if (API_MODE === "mock") return mock.createDraft(doc);
  return call("/v1/charters", { method: "POST", body: JSON.stringify(doc) });
}

export function getDraftPolicy(agentId: string, env: string): Promise<CompiledPolicy> {
  if (API_MODE === "mock") return mock.getDraftPolicy(agentId, env);
  return call(
    `/v1/charters/${encodeURIComponent(agentId)}/policy?env=${encodeURIComponent(env)}&draft=true`,
  );
}

export function signCharter(agentId: string, env: string, actor: string): Promise<SignResponse> {
  if (API_MODE === "mock") return mock.signCharter(agentId, env, actor);
  return call(`/v1/charters/${encodeURIComponent(agentId)}/sign?env=${encodeURIComponent(env)}`, {
    method: "POST",
    body: JSON.stringify({ actor }),
  });
}
