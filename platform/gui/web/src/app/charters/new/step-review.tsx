"use client";

/** Screen 4 — Review & sign. The human sees their intent beside the compiled
 *  machine policy; the attest checkbox + Sign is a deliberate commitment gate. */
import { useState } from "react";
import { Badge, Button, Card, inputCls } from "@/components/ui";
import { byId } from "@/lib/catalog";
import type { CompiledPolicy } from "@/lib/api/client";
import type { WizardState } from "./wizard";

export function StepReview({
  s,
  policy,
  busy,
  signConflictMsg,
  openBlockingCount,
  onBack,
  onSign,
}: {
  s: WizardState;
  policy: CompiledPolicy | null;
  busy: boolean;
  signConflictMsg: string | null;
  openBlockingCount: number;
  onBack: () => void;
  onSign: (actor: string) => void;
}) {
  const [attested, setAttested] = useState(false);
  const [actor, setActor] = useState(s.owner || "");
  const pendingExceptions = s.conflicts.filter((c) => c.resolution === "exception-requested").length;

  return (
    <Card className="space-y-4">
      <h2 className="font-mono text-[11px] font-semibold uppercase tracking-[0.18em] text-ink-3">
        Review the compiled policy, then sign
      </h2>

      {signConflictMsg ? (
        <div className="rounded-md border border-danger/40 bg-danger/10 p-3 text-sm text-danger">
          ✋ {signConflictMsg}
          <button onClick={onBack} className="ml-2 font-medium underline underline-offset-2">
            back to Reconcile
          </button>
        </div>
      ) : null}

      <div className="grid grid-cols-2 gap-4">
        <section>
          <h3 className="mb-2 font-mono text-[10.5px] font-semibold uppercase tracking-[0.18em] text-ink-3">
            Intent (what you said)
          </h3>
          <ul className="space-y-1 text-sm">
            {s.selected.map((id) => (
              <li key={id}>
                • {byId.get(id)?.label ?? id}
                {s.lockedIds.includes(id) ? <span className="ml-1 text-xs">🔒</span> : null}
              </li>
            ))}
          </ul>
          <div className="mt-3 space-y-1 text-sm text-ink-2">
            <div>
              Autonomy: <span className="font-medium">{s.autonomy}</span> · Trust tier:{" "}
              <span className="font-medium">{s.trustTier}</span>
            </div>
            <div>
              Tools allowed:{" "}
              <span className="font-mono text-xs">{s.permittedTools.join(", ") || "(none)"}</span>
            </div>
            {s.owner ? <div>Owner: {s.owner}</div> : null}
            {pendingExceptions > 0 ? (
              <div>
                <Badge tone="warn">{pendingExceptions} Exception pending ⏳ — blocks registration</Badge>
              </div>
            ) : null}
          </div>
        </section>

        <section className="min-w-0">
          <h3 className="mb-2 font-mono text-[10.5px] font-semibold uppercase tracking-[0.18em] text-ink-3">
            Compiled AGT policy (governance.toolkit/v1)
          </h3>
          {/* The compiled artifact — always terminal-dark, like every artifact on the site. */}
          <pre className="terminal max-h-80 overflow-auto rounded-lg p-3 font-mono text-xs leading-relaxed">
            {policy ? JSON.stringify(policy, null, 2) : "(compiling…)"}
          </pre>
        </section>
      </div>

      <div className="space-y-3 border-t border-line pt-4">
        <div className="flex items-end gap-3">
          <label className="block grow-0">
            <span className="mb-1 block text-sm font-medium text-ink-2">Signing as</span>
            <input
              className={inputCls}
              style={{ maxWidth: 280 }}
              value={actor}
              onChange={(e) => setActor(e.target.value)}
              placeholder="alice@example.com"
            />
          </label>
          <label className="flex items-center gap-2 pb-2 text-sm">
            <input
              type="checkbox"
              checked={attested}
              onChange={(e) => setAttested(e.target.checked)}
            />
            I attest this Charter is correct and complete.
          </label>
        </div>
        <div className="flex items-center justify-between">
          <span className="font-mono text-xs text-ink-3">
            {openBlockingCount > 0
              ? `${openBlockingCount} blocking conflict unresolved — signing will be refused (409)`
              : "compile gate clear"}
          </span>
          <div className="flex gap-2">
            <Button variant="secondary" onClick={onBack}>
              ← Back
            </Button>
            <Button onClick={() => onSign(actor)} disabled={busy || !attested || !actor}>
              {busy ? "Signing…" : "✎ Sign & register"}
            </Button>
          </div>
        </div>
      </div>
    </Card>
  );
}
