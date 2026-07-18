/**
 * The Objective Catalog (charter-spec §4) — plain-language concerns.
 *
 * Mirrors server/blastcontain/charter/catalog.py (the authoritative copy).
 * TODO: serve this from the platform (GET /v1/catalog) so the GUI can't drift.
 */

export type Autonomy = "interactive" | "autonomous";
export type Strictness = "locked" | "balanced" | "permissive";
export type RuleAction = "allow" | "deny" | "require_approval";

export interface CatalogRule {
  suffix: string;
  condition: string;
  interactive: RuleAction;
  autonomous: RuleAction;
}

export interface CatalogObjective {
  id: string;
  label: string;
  category: string;
  risk: string; // "MIT <subdomain> · OWASP <T#>"
  provenBy: string[]; // Verify check ids / Drill scenario names
  kind: "rule" | "constraint" | "runtime";
  rules?: CatalogRule[];
  constraints?: [string, boolean | number][];
  enforcers?: string[];
  defaultIn: Strictness[];
  requiresParam?: string;
}

export const CATEGORY_LABELS: Record<string, string> = {
  "data-integrity": "Data integrity & exfiltration",
  secrets: "Secrets & identity",
  tools: "Tool & MCP control",
  runtime: "Code & runtime isolation",
  memory: "Memory & model integrity",
  delegation: "Delegation & identity",
  content: "Content safety",
};

const DESTRUCTIVE = "action.type in ['delete', 'drop', 'truncate']";

export const CATALOG: CatalogObjective[] = [
  // ── ① Data integrity & exfiltration ──────────────────────────────────────
  {
    id: "no-prod-data-mutation",
    label: "Never change (delete/mutate) production data",
    category: "data-integrity",
    risk: "MIT 2.2 · OWASP T2",
    provenBy: ["API-01", "MCP-03"],
    kind: "rule",
    rules: [{ suffix: "destructive", condition: DESTRUCTIVE, interactive: "require_approval", autonomous: "deny" }],
    defaultIn: ["locked", "balanced"],
  },
  {
    id: "block-exfiltration",
    label: "Block all data-exfiltration paths",
    category: "data-integrity",
    risk: "MIT 2.1 · OWASP T2",
    provenBy: ["ENV-02", "NET-01", "SKILL-01", "MCP-03"],
    kind: "rule",
    rules: [{ suffix: "send", condition: "action.type == 'send'", interactive: "deny", autonomous: "deny" }],
    constraints: [["egress_blocked", true]],
    defaultIn: ["locked"],
  },
  {
    id: "no-pii-egress",
    label: "No PII/PHI may leave the agent",
    category: "data-integrity",
    risk: "MIT 2.1 · OWASP T2",
    provenBy: ["MEM-01", "MEM-05"],
    kind: "rule",
    rules: [{ suffix: "send", condition: "action.type == 'send'", interactive: "require_approval", autonomous: "deny" }],
    enforcers: ["agt", "cisco", "nemo"],
    defaultIn: ["locked", "balanced"],
  },
  // ── ② Secrets & identity ─────────────────────────────────────────────────
  {
    id: "no-readable-secrets",
    label: "The agent holds no readable secrets",
    category: "secrets",
    risk: "MIT 2.2 · OWASP T3",
    provenBy: ["CRED-01", "CRED-02"],
    kind: "rule",
    rules: [{ suffix: "credential-access", condition: "action.type == 'credential_access'", interactive: "deny", autonomous: "deny" }],
    defaultIn: ["locked", "balanced"],
  },
  {
    id: "no-wildcard-capabilities",
    label: "No wildcard / over-broad capabilities",
    category: "secrets",
    risk: "MIT 2.2 · OWASP T3",
    provenBy: ["CRED-03"],
    kind: "constraint",
    defaultIn: ["locked"],
  },
  // ── ③ Tool & MCP control ─────────────────────────────────────────────────
  {
    id: "approved-tools-only",
    label: "Only approved tools may run",
    category: "tools",
    risk: "MIT 2.2 · OWASP T2",
    provenBy: ["MCP-01", "SKILL-01"],
    kind: "rule", // structural: permitted_tools allowlist + default deny
    defaultIn: ["locked", "balanced", "permissive"],
  },
  {
    id: "no-dangerous-tool-combos",
    label: "No dangerous tool combinations (Read+Send, Credential+Send, Execute+Write)",
    category: "tools",
    risk: "MIT 2.2 · OWASP T2",
    provenBy: ["MCP-03"],
    kind: "constraint",
    defaultIn: ["locked"],
  },
  {
    id: "mcp-auth-required",
    label: "Every MCP server authenticated & encrypted",
    category: "tools",
    risk: "MIT 2.2 · OWASP T12",
    provenBy: ["MCP-02", "TLS-01"],
    kind: "constraint",
    defaultIn: ["locked", "balanced"],
  },
  // ── ④ Code & runtime isolation ───────────────────────────────────────────
  {
    id: "no-dangerous-code-exec",
    label: "No dangerous code execution",
    category: "runtime",
    risk: "MIT 2.2 · OWASP T11",
    provenBy: ["CODE-01"],
    kind: "rule",
    rules: [{ suffix: "exec", condition: "action.type == 'exec'", interactive: "deny", autonomous: "deny" }],
    defaultIn: ["locked", "balanced"],
  },
  {
    id: "isolated-least-privilege",
    label: "The agent runs isolated & least-privilege",
    category: "runtime",
    risk: "MIT 2.2 · OWASP T3",
    provenBy: ["ENV-01", "PRIV-01", "CAP-01", "DISK-02", "PERM-01"],
    kind: "constraint",
    constraints: [["read_only_rootfs", true]],
    defaultIn: ["locked"],
  },
  {
    id: "no-workstation-prod",
    label: "Never run a prod agent on a developer workstation",
    category: "runtime",
    risk: "MIT 6.5 · OWASP T8",
    provenBy: ["LOCAL-01", "DISK-01"],
    kind: "constraint",
    defaultIn: ["locked"],
  },
  // ── ⑤ Memory & model integrity ───────────────────────────────────────────
  {
    id: "tenant-memory-isolation",
    label: "Tenant memory is namespace-isolated",
    category: "memory",
    risk: "MIT 2.1 · OWASP T1",
    provenBy: ["MEM-03"],
    kind: "constraint",
    defaultIn: ["locked"],
  },
  {
    id: "model-weights-attested",
    label: "Model weights attested & immutable (self-hosted only)",
    category: "memory",
    risk: "MIT 2.2 · supply-chain",
    provenBy: ["SUP-01", "ENV-03"],
    kind: "constraint",
    defaultIn: [],
    requiresParam: "self_hosted",
  },
  // ── ⑥ Delegation, identity & content safety ──────────────────────────────
  {
    id: "no-delegation-escalation",
    label: "No autonomous privilege escalation via delegation",
    category: "delegation",
    risk: "MIT 7.6 · OWASP T3/T13",
    provenBy: ["ledger:blast-radius"],
    kind: "rule",
    rules: [{ suffix: "delegate", condition: "action.type == 'delegate'", interactive: "require_approval", autonomous: "deny" }],
    defaultIn: ["locked"],
  },
  {
    id: "injection-resistant",
    label: "The agent resists jailbreak & prompt injection",
    category: "content",
    risk: "MIT 7.1 · OWASP T6",
    provenBy: ["drill:prompt_injection", "drill:jailbreak"],
    kind: "runtime",
    enforcers: ["agt", "cisco", "nemo"],
    defaultIn: ["locked", "balanced"],
  },
  {
    id: "content-safe-outputs",
    label: "Agent outputs are content-safe",
    category: "content",
    risk: "MIT 1.2 · OWASP T7",
    provenBy: ["runtime:content-filter"],
    kind: "runtime",
    enforcers: ["nemo", "cisco"],
    defaultIn: ["locked", "balanced"],
  },
  {
    id: "validate-upstream-output",
    label: "Don't blindly trust upstream agent output",
    category: "content",
    risk: "MIT 7.6 · OWASP T5",
    provenBy: ["drill:cascading"],
    kind: "runtime",
    defaultIn: ["locked"],
  },
  {
    id: "inter-agent-auth",
    label: "Inter-agent messages authenticated & integrity-checked",
    category: "delegation",
    risk: "MIT 7.6 · OWASP T14",
    provenBy: ["drill:trust_boundary"],
    kind: "runtime",
    defaultIn: ["locked"],
  },
  {
    id: "no-user-manipulation",
    label: "The agent must not manipulate the user; discloses it is AI",
    category: "content",
    risk: "MIT 5.2 · OWASP T15",
    provenBy: ["drill:manipulation"],
    kind: "constraint",
    defaultIn: ["locked"],
  },
];

export const byId = new Map(CATALOG.map((o) => [o.id, o]));

/** Objective ids pre-selected for a base_strictness level (§3.4). */
export function defaultsFor(strictness: Strictness): string[] {
  return CATALOG.filter((o) => o.defaultIn.includes(strictness)).map((o) => o.id);
}

/** Categories in display order, with their objectives. */
export function grouped(): { category: string; label: string; objectives: CatalogObjective[] }[] {
  const order = ["data-integrity", "secrets", "tools", "runtime", "memory", "delegation", "content"];
  return order.map((category) => ({
    category,
    label: CATEGORY_LABELS[category],
    objectives: CATALOG.filter((o) => o.category === category),
  }));
}
