"use client";

/** Screen 3 — Reconcile reality. Scan-observed behavior vs declared concerns.
 *  A mandatory conflict cannot be waved through: Remove the tool, or request
 *  an Exception (separation of duties — central sign-off). */
import { Badge, Button, Card } from "@/components/ui";
import { byId } from "@/lib/catalog";
import type { WizardState } from "./wizard";

/** Parse a compiler constraint-mismatch reason into an applicable fix.
 *  (Reason text matches compiler.py byte-for-byte in both modes.) */
function constraintFix(reason: string): { field: string; required: boolean } | null {
  const m = reason.match(
    /environment_constraints\.(\w+) is \S+ but the objective requires (True|False)/,
  );
  return m ? { field: m[1], required: m[2] === "True" } : null;
}

/** Wizard fields a constraint fix can tighten (extend as constraints grow). */
const CONSTRAINT_FIELDS: Record<string, keyof WizardState> = {
  egress_blocked: "egressBlocked",
};

export function StepReconcile({
  s,
  patch,
  busy,
  onBack,
  onNext,
}: {
  s: WizardState;
  patch: (p: Partial<WizardState> | ((prev: WizardState) => Partial<WizardState>)) => void;
  busy: boolean;
  onBack: () => void;
  onNext: () => void;
}) {
  const open = s.conflicts.filter((c) => !c.resolution);
  const blockingOpen = open.filter((c) => c.blocking);

  // All resolution patches are functional: two clicks landing in one tick must
  // both apply (a stale-closure overwrite here once dropped a resolution).
  const applyConstraint = (idx: number) => {
    patch((prev) => {
      const fix = constraintFix(prev.conflicts[idx]?.reason ?? "");
      const stateKey = fix ? CONSTRAINT_FIELDS[fix.field] : undefined;
      if (!fix || !stateKey) return {};
      return {
        [stateKey]: fix.required,
        conflicts: prev.conflicts.map((x, i) =>
          i === idx ? { ...x, resolution: "constraint-applied" } : x,
        ),
      } as Partial<WizardState>;
    });
  };

  const requestException = (idx: number) => {
    patch((prev) => ({
      conflicts: prev.conflicts.map((x, i) =>
        i === idx ? { ...x, resolution: "exception-requested" } : x,
      ),
    }));
  };

  const addSuggestion = (tool: string) => {
    patch((prev) => ({
      permittedTools: [...prev.permittedTools, tool],
      suggestions: prev.suggestions.map((x) => (x.tool === tool ? { ...x, action: "added" } : x)),
    }));
  };

  const dismissSuggestion = (tool: string) => {
    patch((prev) => ({
      suggestions: prev.suggestions.map((x) =>
        x.tool === tool ? { ...x, action: "dismissed" } : x,
      ),
    }));
  };

  return (
    <Card className="space-y-4">
      <div className="flex items-baseline justify-between">
        <h2 className="font-mono text-[11px] font-semibold uppercase tracking-[0.18em] text-ink-3">
          We scanned the agent — reality vs your concerns
        </h2>
        <span className="font-mono text-[11px] text-ink-3">
          {s.seedFromScan ? "Verify · 2 min ago" : "no scan seeded"}
        </span>
      </div>

      {s.conflicts.length === 0 && s.suggestions.length === 0 ? (
        <p className="text-sm text-ink-2">
          Nothing to reconcile — no scan was seeded, or observed behavior is fully covered.
        </p>
      ) : null}

      {s.conflicts.map((c, i) => {
        const label = byId.get(c.objective_id ?? "")?.label ?? c.objective_id;
        const fix = constraintFix(c.reason ?? "");
        const fixable = fix !== null && CONSTRAINT_FIELDS[fix.field] !== undefined;
        return (
          <div
            key={`${c.objective_id}-${i}`}
            className={`rounded-md border p-3 ${
              c.blocking ? "border-danger/50 bg-danger/10" : "border-amber/50 bg-amber/10"
            }`}
          >
            <div className="flex items-center gap-2 text-sm font-semibold">
              {c.blocking ? "⛔ CONFLICT — violates a mandatory concern" : "⚠ Tension with a concern"}
              {c.resolution === "constraint-applied" ? (
                <Badge tone="ok">resolved — constraint applied</Badge>
              ) : null}
              {c.resolution === "exception-requested" ? (
                <Badge tone="warn">exception requested ⏳ pending central sign-off</Badge>
              ) : null}
            </div>
            <div className="mt-1 font-mono text-[12px] text-ink-2">{c.reason}</div>
            <div className="mt-1 font-mono text-[11px] text-ink-3">
              Concern: <span className="font-medium text-ink-2">{label}</span>
            </div>
            {!c.resolution ? (
              <div className="mt-2 flex gap-2">
                {fixable ? (
                  <Button variant="secondary" onClick={() => applyConstraint(i)}>
                    Apply the constraint ({fix.field} = {String(fix.required)})
                  </Button>
                ) : null}
                <Button variant="ghost" onClick={() => requestException(i)}>
                  Request Exception
                </Button>
                {c.blocking ? (
                  <span className="self-center font-mono text-[10.5px] text-ink-3">
                    ⓘ mandatory → needs central sign-off (separation of duties)
                  </span>
                ) : null}
              </div>
            ) : null}
          </div>
        );
      })}

      {s.suggestions.map((sg) => (
        <div
          key={sg.tool}
          className="rounded-md border border-blast/40 bg-blast/10 p-3"
        >
          <div className="text-sm font-semibold">➕ SUGGESTION — observed, not yet allowed</div>
          <div className="mt-1 text-sm">
            Observed: <span className="font-mono">{sg.tool}</span>
            <span className="ml-2 font-mono text-[11px] text-ink-3">({sg.source})</span>
            {sg.action === "added" ? <Badge tone="ok">added to allowlist</Badge> : null}
            {sg.action === "dismissed" ? <Badge tone="info">dismissed</Badge> : null}
          </div>
          {!sg.action ? (
            <div className="mt-2 flex gap-2">
              <Button variant="secondary" onClick={() => addSuggestion(sg.tool)}>
                Add to allowlist
              </Button>
              <Button variant="ghost" onClick={() => dismissSuggestion(sg.tool)}>
                Dismiss
              </Button>
            </div>
          ) : null}
        </div>
      ))}

      {s.seedFromScan ? (
        <p className="text-sm text-contain">
          ✓ {s.coveredCount} observed capabilities already covered by your concerns.
        </p>
      ) : null}

      <div className="flex items-center justify-between border-t border-line pt-4">
        <span className="font-mono text-xs text-ink-3">
          {blockingOpen.length > 0 ? `${blockingOpen.length} conflict open` : "no open conflicts"}
        </span>
        <div className="flex gap-2">
          <Button variant="secondary" onClick={onBack}>
            ← Back
          </Button>
          <Button onClick={onNext} disabled={busy}>
            {busy ? "Compiling…" : "Next →"}
          </Button>
        </div>
      </div>
    </Card>
  );
}
