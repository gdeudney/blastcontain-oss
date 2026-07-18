"use client";

/** Charter authoring wizard — Screens 1–4 (the make-or-break flow).
 *  Scope & posture → Concerns → Reconcile reality → Review & sign. */
import { useCallback, useRef, useState } from "react";
import { defaultsFor } from "@/lib/catalog";
import {
  ApiError,
  createDraft,
  deriveCharter,
  getDraftPolicy,
  signCharter,
  type CharterDocument,
  type CompiledPolicy,
  type SignResponse,
} from "@/lib/api/client";
import {
  initialWizard,
  OBSERVED,
  openBlocking,
  STANDARD_MANDATORY,
  type WizardState,
} from "./wizard";
import { StepScope } from "./step-scope";
import { StepConcerns } from "./step-concerns";
import { StepReconcile } from "./step-reconcile";
import { StepReview } from "./step-review";

const STEPS = ["Scope", "Concerns", "Reconcile", "Sign"] as const;

function buildDoc(s: WizardState): CharterDocument {
  return {
    agent_id: s.agentId,
    environment: s.environment,
    version: "1.0.0",
    trust_tier: s.trustTier,
    permitted_tools: s.permittedTools,
    autonomy_mode: s.autonomy,
    base_strictness: s.strictness,
    objectives: s.selected.map((id) =>
      s.lockedIds.includes(id)
        ? { id, enforcement_level: "mandatory" as const, inherited_from: "org-baseline" }
        : { id },
    ),
    environment_constraints: {
      read_only_rootfs: true,
      egress_blocked: s.egressBlocked,
      max_trust_tier: s.trustTier,
      verify_required: true,
    },
    owner: s.owner || null,
    draft: true,
  };
}

export default function NewCharterPage() {
  const [s, setS] = useState<WizardState>(initialWizard);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [policy, setPolicy] = useState<CompiledPolicy | null>(null);
  const [signed, setSigned] = useState<SignResponse | null>(null);
  const [signConflictMsg, setSignConflictMsg] = useState<string | null>(null);

  // The ref is the synchronous source of truth; React state mirrors it for
  // rendering. Async transitions (draft POST, sign) MUST read sRef, not the
  // render closure: a resolution click and "Next" landing in the same tick
  // once signed a draft missing the just-added tool — the Review pane showed
  // state the server never received. What you review must be what is signed.
  const sRef = useRef<WizardState>(initialWizard);

  const patch = useCallback(
    (p: Partial<WizardState> | ((prev: WizardState) => Partial<WizardState>)) => {
      const base = sRef.current;
      const next = { ...base, ...(typeof p === "function" ? p(base) : p) };
      sRef.current = next;
      setS(next);
    },
    [],
  );

  /** Screen 1 → 2: seed selections (and optionally derive from the scan). */
  async function nextFromScope() {
    const cur = sRef.current;
    setBusy(true);
    setError(null);
    try {
      const preselected = Array.from(
        new Set([...defaultsFor(cur.strictness), ...STANDARD_MANDATORY]),
      );
      if (cur.seedFromScan) {
        const res = await deriveCharter(cur.agentId, cur.environment, {
          autonomy_mode: cur.autonomy,
          base_strictness: cur.strictness,
          owner: cur.owner || undefined,
          observed: { tools: OBSERVED.tools, trust_tier: OBSERVED.trust_tier },
        });
        const doc = res.document;
        patch({
          step: 2,
          selected: Array.from(
            new Set([...(doc?.objectives ?? []).map((o) => o.id), ...STANDARD_MANDATORY]),
          ),
          egressBlocked: doc?.environment_constraints?.egress_blocked ?? true,
          permittedTools: doc?.permitted_tools ?? [],
          observedTools: [...OBSERVED.tools, ...OBSERVED.mcpTools],
          conflicts: res.conflicts ?? [],
          suggestions: OBSERVED.mcpTools.map((tool) => ({
            tool,
            source: "MCP tool observed by Verify",
          })),
        });
      } else {
        patch({
          step: 2,
          selected: preselected,
          permittedTools: [],
          observedTools: [],
          conflicts: [],
          suggestions: [],
        });
      }
    } catch (e) {
      setError(String((e as Error).message ?? e));
    } finally {
      setBusy(false);
    }
  }

  /** Screen 2 → 3: persist the draft; the server's compile gate previews conflicts. */
  async function nextFromConcerns() {
    const cur = sRef.current;
    setBusy(true);
    setError(null);
    try {
      const res = await createDraft(buildDoc(cur));
      const fresh = res.conflicts ?? [];
      // keep resolutions the user already made on re-raised conflicts
      const merged = fresh.map((c) => {
        const prior = cur.conflicts.find((p) => p.objective_id === c.objective_id && p.resolution);
        return prior ? { ...c, resolution: prior.resolution } : c;
      });
      const covered = cur.permittedTools.filter((t) => cur.observedTools.includes(t)).length;
      patch({ step: 3, conflicts: merged, coveredCount: covered });
    } catch (e) {
      setError(String((e as Error).message ?? e));
    } finally {
      setBusy(false);
    }
  }

  /** Screen 3 → 4: re-persist (post-reconcile) and fetch the compiled policy.
   *  Reads sRef so the draft the server signs includes every reconcile action,
   *  even when the resolving click and Next land in the same tick. */
  async function nextFromReconcile() {
    const cur = sRef.current;
    setBusy(true);
    setError(null);
    try {
      await createDraft(buildDoc(cur));
      const pol = await getDraftPolicy(cur.agentId, cur.environment);
      setPolicy(pol);
      patch({ step: 4 });
    } catch (e) {
      setError(String((e as Error).message ?? e));
    } finally {
      setBusy(false);
    }
  }

  async function doSign(actor: string) {
    const cur = sRef.current;
    setBusy(true);
    setError(null);
    setSignConflictMsg(null);
    try {
      const res = await signCharter(cur.agentId, cur.environment, actor);
      setSigned(res);
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        const detail = e.detail as { message?: string } | string | null;
        setSignConflictMsg(
          typeof detail === "object" && detail?.message
            ? detail.message
            : "Signing blocked by compile conflicts.",
        );
      } else {
        setError(String((e as Error).message ?? e));
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mx-auto max-w-4xl space-y-4">
      <div className="flex items-baseline justify-between">
        <h1 className="font-display text-xl font-bold tracking-tight">
          New Charter
          {s.step > 1 ? (
            <span className="ml-2 font-mono text-sm font-normal text-ink-3">
              {s.agentId}/{s.environment}
            </span>
          ) : null}
        </h1>
        <ol className="flex gap-4 font-mono text-[11px] uppercase tracking-[0.14em]">
          {STEPS.map((label, i) => {
            const n = (i + 1) as WizardState["step"];
            const here = s.step === n;
            const done = s.step > n;
            return (
              <li
                key={label}
                className={here ? "font-bold text-blast" : done ? "text-contain" : "text-ink-3"}
              >
                {here ? "●" : done ? "✓" : "○"} {label}
              </li>
            );
          })}
        </ol>
      </div>

      {error ? (
        <div className="rounded-md border border-danger/40 bg-danger/10 p-3 text-sm text-danger">
          {error}
        </div>
      ) : null}

      {signed ? (
        <SignedPanel signed={signed} />
      ) : (
        <>
          {s.step === 1 && <StepScope s={s} patch={patch} busy={busy} onNext={nextFromScope} />}
          {s.step === 2 && (
            <StepConcerns
              s={s}
              patch={patch}
              busy={busy}
              onBack={() => patch({ step: 1 })}
              onNext={nextFromConcerns}
            />
          )}
          {s.step === 3 && (
            <StepReconcile
              s={s}
              patch={patch}
              busy={busy}
              onBack={() => patch({ step: 2 })}
              onNext={nextFromReconcile}
            />
          )}
          {s.step === 4 && (
            <StepReview
              s={s}
              policy={policy}
              busy={busy}
              signConflictMsg={signConflictMsg}
              openBlockingCount={openBlocking(s).length}
              onBack={() => patch({ step: 3 })}
              onSign={doSign}
            />
          )}
        </>
      )}
    </div>
  );
}

function SignedPanel({ signed }: { signed: SignResponse }) {
  return (
    <div className="rounded-md border border-contain/40 bg-contain/10 p-6">
      <div className="font-display text-lg font-bold text-contain">
        ✓ Charter signed &amp; registered — v{signed.version}
      </div>
      <p className="mt-1 text-sm text-ink-2">
        State: {signed.state}. The signed bundle is now served to Guard
        (`Guard.from_charter` consumes it end-to-end).
      </p>
      {signed.advisory_signature ? (
        <p className="mt-3 rounded-md border border-amber/40 bg-amber/10 p-2.5 font-mono text-[11.5px] leading-relaxed text-amber">
          ⚠ Signed with the shared dev HMAC key (advisory) — integrity only, not attestation.
          Guard rejects advisory signatures unless explicitly allowed. Configure an Ed25519 key
          for production.
        </p>
      ) : null}
      <a
        href="/fleet"
        className="mt-4 inline-block text-sm font-medium text-blast underline-offset-2 hover:underline"
      >
        → Back to Fleet
      </a>
    </div>
  );
}
