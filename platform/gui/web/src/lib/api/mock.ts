/**
 * Spec-shaped fixtures + a tiny stateful charter store, so the authoring
 * wizard is fully clickable with no backend (NEXT_PUBLIC_API_MODE=mock).
 *
 * The compile preview and conflict logic MIRROR server/blastcontain/charter/
 * compiler.py (verified against the live platform 2026-06-12):
 *   - mandatory never degrades to a prompt: require_approval hardens to deny
 *     (§3.7 honesty line); deny carries approvers [central], asks [self];
 *   - an egress-blocked deployment gets an env-egress-blocked hard deny when
 *     no objective already denies sends;
 *   - the allowlist is STRUCTURAL (always emitted when tools exist), named
 *     allow-permitted-tools, tools sorted;
 *   - rules order most-restrictive first, then dedupe by condition keep-first;
 *   - conflicts arise from constraint mismatches (blocking iff mandatory) and
 *     the unset transparency_label note — never from tool names.
 */
import { byId, defaultsFor, type Autonomy, type Strictness } from "../catalog";
import { ApiError } from "./client";
import type {
  CharterDocument,
  CompileConflict,
  CompiledPolicy,
  CreateDraftResponse,
  DeriveResponse,
  FleetResponse,
  SignResponse,
  ViolationsResponse,
} from "./client";

const now = () => new Date().toISOString();
const minutesAgo = (m: number) => new Date(Date.now() - m * 60_000).toISOString();

/** The org Standard fixture (what /v1/standards would serve). Keep in sync
 *  with STANDARD_MANDATORY in app/charters/new/wizard.ts. */
const MOCK_STANDARD_MANDATORY = ["no-prod-data-mutation", "block-exfiltration"];

// ── Fleet / violations (Screen 5 fixtures, real platform vocabulary) ─────────

export async function getFleet(): Promise<FleetResponse> {
  return {
    agents: [
      { agent_id: "invoice-bot", status: "PASSED", last_scan: minutesAgo(2), critical: 0, charters: { prod: "active" } },
      { agent_id: "data-syncer", status: "REJECTED", last_scan: minutesAgo(60), critical: 2, charters: { prod: "quarantined", staging: "active" } },
      { agent_id: "support-copilot", status: "PASSED", last_scan: minutesAgo(5), critical: 0, charters: { prod: "active" } },
      { agent_id: "shadow-x:8080", status: "UNKNOWN", last_scan: null, critical: 0, charters: { "": "discovered" } },
    ],
    total: 4,
  };
}

export async function listViolations(): Promise<ViolationsResponse> {
  return {
    violations: [
      {
        agent_id: "data-syncer",
        check_id: "ENV-03",
        finding_type: "blastcontain.env.model_weights_writable",
        severity: "CRITICAL",
        title: "Model Weight Directory Is Writable",
        detail: "Model weights are writable by the agent process while the Charter requires attestation.",
      },
      {
        agent_id: "data-syncer",
        check_id: "CRED-01",
        finding_type: "blastcontain.cred.readable_secret",
        severity: "CRITICAL",
        title: "Readable AWS credential in environment",
        detail: "AWS_SECRET_ACCESS_KEY readable by the agent process (evidence scrubbed).",
      },
      {
        agent_id: "support-copilot",
        check_id: "MCP-02",
        finding_type: "blastcontain.mcp.unauthenticated_server",
        severity: "HIGH",
        title: "MCP server without authentication",
        detail: "MCP server 'kb-search' accepts unauthenticated connections.",
      },
    ],
    total: 3,
  };
}

// ── The wizard's charter store ───────────────────────────────────────────────

let draft: CharterDocument | null = null;

const ACTION_ORDER: Record<string, number> = { deny: 0, require_approval: 1, allow: 2 };

/** Python-repr scalars, so conflict text matches compiler.py byte-for-byte. */
const py = (v: unknown) =>
  v === true ? "True" : v === false ? "False" : v === null || v === undefined ? "None" : String(v);

/** Conflicts exactly as compiler.py raises them (constraint mismatches are
 *  blocking iff the objective is mandatory — §3.6). */
function computeConflicts(doc: CharterDocument): CompileConflict[] {
  const conflicts: CompileConflict[] = [];
  const constraints = (doc.environment_constraints ?? {}) as Record<string, unknown>;
  for (const obj of doc.objectives ?? []) {
    const entry = byId.get(obj.id);
    if (!entry) {
      conflicts.push({
        objective_id: obj.id,
        reason: `unknown objective id '${obj.id}' — not in the catalog`,
        blocking: true,
      });
      continue;
    }
    for (const [field, required] of entry.constraints ?? []) {
      const actual = constraints[field];
      if (actual !== required) {
        conflicts.push({
          objective_id: obj.id,
          reason: `environment_constraints.${field} is ${py(actual)} but the objective requires ${py(required)}`,
          blocking: obj.enforcement_level === "mandatory",
        });
      }
    }
    if (obj.id === "no-user-manipulation" && !doc.transparency_label) {
      conflicts.push({
        objective_id: obj.id,
        reason: "transparency_label is unset (EU AI Act Art. 50 disclosure)",
        blocking: false,
      });
    }
  }
  return conflicts;
}

export function compilePreview(doc: CharterDocument): CompiledPolicy {
  const autonomy = (doc.autonomy_mode ?? "interactive") as Autonomy;
  const rules: NonNullable<CompiledPolicy["rules"]> = [];

  // 1. Objective-derived rules; the autonomy switch picks the action and the
  //    enforcement level hardens it (§3.7).
  for (const obj of doc.objectives ?? []) {
    const entry = byId.get(obj.id);
    if (!entry?.rules) continue;
    for (const t of entry.rules) {
      let action = autonomy === "interactive" ? t.interactive : t.autonomous;
      if (obj.enforcement_level === "mandatory" && action === "require_approval") {
        action = "deny";
      }
      rules.push({
        name: `${obj.id}-${t.suffix}`,
        condition: t.condition,
        action,
        ...(action === "require_approval"
          ? { approvers: ["self" as const] }
          : action === "deny"
            ? { approvers: ["central" as const] }
            : {}),
        concern: obj.id,
      });
    }
  }

  // 2. Environment-derived hard deny: egress-blocked deployments deny sends.
  if (
    doc.environment_constraints?.egress_blocked &&
    !rules.some((r) => r.condition === "action.type == 'send'" && r.action === "deny")
  ) {
    rules.push({
      name: "env-egress-blocked",
      condition: "action.type == 'send'",
      action: "deny",
      approvers: ["central" as const],
      concern: "block-exfiltration",
    });
  }

  // 3. The structural allowlist on top of default-deny (always when tools exist).
  const tools = [...(doc.permitted_tools ?? [])].sort();
  if (tools.length) {
    rules.push({
      name: "allow-permitted-tools",
      condition: `tool_name in [${tools.map((t) => `'${t}'`).join(", ")}]`,
      action: "allow",
      concern: "approved-tools-only",
    });
  }

  // 4. Most-restrictive first (stable sort), then dedupe by condition.
  rules.sort((a, b) => (ACTION_ORDER[a.action ?? ""] ?? 1) - (ACTION_ORDER[b.action ?? ""] ?? 1));
  const seen = new Set<string>();
  const deduped = rules.filter((r) => {
    if (seen.has(r.condition ?? "")) return false;
    seen.add(r.condition ?? "");
    return true;
  });

  return {
    apiVersion: "governance.toolkit/v1",
    name: `${doc.agent_id}-${doc.environment}`,
    agent_id: doc.agent_id,
    environment: doc.environment,
    autonomy_mode: autonomy,
    default_action: "deny",
    rules: deduped,
  };
}

export async function deriveCharter(
  agentId: string,
  env: string,
  body: {
    autonomy_mode?: string;
    base_strictness?: string;
    owner?: string;
    observed?: { tools?: string[]; trust_tier?: number };
  },
): Promise<DeriveResponse> {
  const observedTools = body.observed?.tools ?? ["query_invoice", "send_receipt", "delete_order"];
  const seeded = observedTools.filter((t) => !t.startsWith("mcp:"));
  const strictness = (body.base_strictness ?? "balanced") as Strictness;
  const ids = Array.from(new Set([...defaultsFor(strictness), ...MOCK_STANDARD_MANDATORY]));
  const doc: CharterDocument = {
    agent_id: agentId,
    environment: env,
    version: "1.0.0",
    trust_tier: body.observed?.trust_tier ?? 1,
    permitted_tools: seeded,
    autonomy_mode: (body.autonomy_mode ?? "interactive") as CharterDocument["autonomy_mode"],
    base_strictness: strictness,
    objectives: ids.map((id) =>
      MOCK_STANDARD_MANDATORY.includes(id)
        ? { id, enforcement_level: "mandatory" as const, inherited_from: "org-baseline" }
        : { id },
    ),
    environment_constraints: {
      read_only_rootfs: true,
      // The scan observed OPEN egress — derive reports reality, and the
      // mandatory block-exfiltration constraint turns it into the blocking
      // conflict Screen 3 reconciles.
      egress_blocked: false,
      max_trust_tier: 1,
      verify_required: true,
    },
    owner: body.owner ?? null,
    derived_from_scan: `verify:${agentId}:${env}:${now()}`,
    draft: true,
  };
  draft = doc;
  return {
    accepted: true,
    charter_id: `${agentId}:${env}`,
    state: "draft",
    document: doc,
    conflicts: computeConflicts(doc),
  };
}

export async function createDraft(doc: CharterDocument): Promise<CreateDraftResponse> {
  draft = { ...doc, draft: true };
  return {
    accepted: true,
    charter_id: `${doc.agent_id}:${doc.environment}`,
    state: "draft",
    draft_row: 1,
    conflicts: computeConflicts(draft),
  };
}

export async function getDraftPolicy(agentId: string, env: string): Promise<CompiledPolicy> {
  if (!draft || draft.agent_id !== agentId || draft.environment !== env) {
    throw new ApiError(404, "no draft for this agent");
  }
  return compilePreview(draft);
}

export async function signCharter(agentId: string, env: string, actor: string): Promise<SignResponse> {
  if (!draft || draft.agent_id !== agentId || draft.environment !== env) {
    throw new ApiError(404, "no draft to sign");
  }
  const conflicts = computeConflicts(draft);
  if (conflicts.some((c) => c.blocking)) {
    throw new ApiError(409, {
      message: "blocking compile conflicts — reconcile or file an Exception",
      conflicts,
    });
  }
  const policy = compilePreview(draft);
  const signedAt = now();
  const bundle: SignResponse = {
    signed: true,
    state: "active",
    version: draft.version ?? "1.0.0",
    advisory_signature: true,
    conflicts,
    bundle: {
      packet: {
        ...draft,
        draft: false,
        state: "active",
        signed_at: signedAt,
        signed_by: actor,
        signing_key_id: "platform-dev",
        compiled_policy: policy,
      },
      signature: {
        algorithm: "sha256-hmac",
        key_id: "platform-dev",
        value: "bW9jay1zaWduYXR1cmU=",
        value_encoding: "base64",
        canonical: "json-sort-keys-tight",
        signed_at: signedAt,
        advisory: true,
      },
    },
  };
  draft = null;
  return bundle;
}
