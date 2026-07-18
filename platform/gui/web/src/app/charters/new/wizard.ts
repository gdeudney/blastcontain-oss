/** Shared wizard state + transitions for the authoring flow (Screens 1–4). */
import type { Autonomy, Strictness } from "@/lib/catalog";
import type { CompileConflict } from "@/lib/api/client";

export type ConflictResolution = "constraint-applied" | "exception-requested";

export interface WizardConflict extends CompileConflict {
  resolution?: ConflictResolution;
}

export interface Suggestion {
  tool: string;
  source: string; // e.g. "MCP tool observed by Verify"
  action?: "added" | "dismissed";
}

export interface WizardState {
  step: 1 | 2 | 3 | 4;
  // Screen 1 — scope & posture
  agentId: string;
  environment: string;
  owner: string;
  autonomy: Autonomy;
  strictness: Strictness;
  trustTier: number;
  seedFromScan: boolean;
  // Screen 2 — concerns
  selected: string[];
  lockedIds: string[]; // inherited mandatory (org Standard)
  // Screen 3 — reconcile
  permittedTools: string[];
  observedTools: string[];
  /** Declared egress constraint. Derive seeds it from observed reality (open
   *  egress → false); reconciling a block-exfiltration conflict tightens it. */
  egressBlocked: boolean;
  conflicts: WizardConflict[];
  suggestions: Suggestion[];
  coveredCount: number;
}

/** What a Verify/Discovery scan reported for the demo agent — in real mode
 *  this comes from the latest scan and is passed INTO derive (per the spec). */
export const OBSERVED = {
  tools: ["query_invoice", "send_receipt", "delete_order"],
  mcpTools: ["query_ledger_db"],
  trust_tier: 1,
};

/** The org Standard's mandatory objectives (mock; served by /v1/standards).
 *  block-exfiltration carries an egress_blocked=true constraint, so deriving
 *  from a scan that observed open egress raises a real blocking conflict —
 *  the same one compiler.py raises (mandatory constraint mismatch, §3.6). */
export const STANDARD_MANDATORY = ["no-prod-data-mutation", "block-exfiltration"];

export const initialWizard: WizardState = {
  step: 1,
  agentId: "invoice-bot",
  environment: "prod",
  owner: "",
  autonomy: "interactive",
  strictness: "balanced",
  trustTier: 1,
  seedFromScan: true,
  selected: [],
  lockedIds: STANDARD_MANDATORY,
  permittedTools: [],
  observedTools: [],
  egressBlocked: true, // tight until a scan says otherwise
  conflicts: [],
  suggestions: [],
  coveredCount: 0,
};

export function openBlocking(s: WizardState): WizardConflict[] {
  return s.conflicts.filter((c) => c.blocking && !c.resolution);
}
