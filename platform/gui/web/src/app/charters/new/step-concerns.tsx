"use client";

/** Screen 2 — Concerns (the catalog). Plain language is the label; the
 *  technical detail ("compiles to") is one expand away. Inherited mandatory
 *  concerns are visibly locked. */
import { useState } from "react";
import { Badge, Button, Card, inputCls } from "@/components/ui";
import { grouped, type CatalogObjective } from "@/lib/catalog";
import type { WizardState } from "./wizard";

export function StepConcerns({
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
  const [q, setQ] = useState("");
  const needle = q.trim().toLowerCase();

  const toggle = (id: string) => {
    if (s.lockedIds.includes(id)) return;
    patch((prev) => ({
      selected: prev.selected.includes(id)
        ? prev.selected.filter((x) => x !== id)
        : [...prev.selected, id],
    }));
  };

  const matches = (o: CatalogObjective) =>
    !needle ||
    o.label.toLowerCase().includes(needle) ||
    o.id.includes(needle) ||
    o.risk.toLowerCase().includes(needle);

  return (
    <Card className="space-y-4">
      <div className="flex flex-wrap items-baseline justify-between gap-3">
        <h2 className="font-mono text-[11px] font-semibold uppercase tracking-[0.18em] text-ink-3">
          What do you care about?
        </h2>
        <div className="flex items-center gap-3">
          <input
            className={`${inputCls} w-56`}
            placeholder="search concerns…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            aria-label="Search concerns"
          />
          <span className="font-mono text-xs text-ink-3">
            Autonomy: <span className="font-medium text-ink-2">{s.autonomy}</span>
          </span>
        </div>
      </div>

      <div className="space-y-3">
        {grouped().map((g) => {
          const visible = g.objectives.filter(matches);
          if (needle && visible.length === 0) return null;
          const selectedHere = g.objectives.filter((o) => s.selected.includes(o.id)).length;
          return (
            <details key={g.category} open={needle ? true : selectedHere > 0} className="group">
              <summary className="cursor-pointer select-none text-sm font-medium">
                <span className="mr-2 inline-block w-3 text-ink-3 group-open:rotate-90">▸</span>
                {g.label}
                <span className="ml-2 font-mono text-[11px] text-ink-3">
                  ({selectedHere} of {g.objectives.length})
                </span>
              </summary>
              <ul className="mt-2 space-y-2 pl-5">
                {visible.map((o) => (
                  <ConcernRow
                    key={o.id}
                    o={o}
                    autonomy={s.autonomy}
                    checked={s.selected.includes(o.id)}
                    locked={s.lockedIds.includes(o.id)}
                    onToggle={() => toggle(o.id)}
                  />
                ))}
              </ul>
            </details>
          );
        })}
        {needle && grouped().every((g) => g.objectives.filter(matches).length === 0) ? (
          <p className="text-sm text-ink-3">No concerns match “{q}”.</p>
        ) : null}
      </div>

      <div className="flex items-center justify-between border-t border-line pt-4">
        <span className="text-sm text-ink-3">
          🔒 inherited from Org Standard (cannot weaken) ·{" "}
          <span className="font-medium text-ink">{s.selected.length} concerns selected</span>
        </span>
        <div className="flex gap-2">
          <Button variant="secondary" onClick={onBack}>
            ← Back
          </Button>
          <Button onClick={onNext} disabled={busy}>
            {busy ? "Checking…" : "Next →"}
          </Button>
        </div>
      </div>
    </Card>
  );
}

function ConcernRow({
  o,
  autonomy,
  checked,
  locked,
  onToggle,
}: {
  o: CatalogObjective;
  autonomy: "interactive" | "autonomous";
  checked: boolean;
  locked: boolean;
  onToggle: () => void;
}) {
  const ruleCount = o.rules?.length ?? 0;
  const compileNote =
    o.kind === "rule"
      ? ruleCount > 0
        ? `→ ${ruleCount} AGT rule${ruleCount > 1 ? "s" : ""}`
        : "→ allowlist + default deny"
      : o.kind === "constraint"
        ? "→ environment constraint (Verify-gated)"
        : "→ guardrail layer (runtime plugin)";

  const actionTone: Record<string, string> = {
    allow: "text-contain",
    deny: "text-danger",
    require_approval: "text-amber",
  };

  return (
    <li className="rounded-md border border-line p-2.5">
      <div className="flex items-start gap-2.5">
        <input
          type="checkbox"
          className="mt-0.5 accent-[var(--blast)]"
          checked={checked}
          disabled={locked}
          onChange={onToggle}
        />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <span className={locked ? "font-medium" : ""}>{o.label}</span>
            {locked ? <Badge tone="warn">🔒 inherited · mandatory</Badge> : null}
          </div>
          <details className="mt-1">
            <summary className="cursor-pointer font-mono text-[11px] text-ink-3 transition-colors hover:text-ink-2">
              {compileNote} ⌄
            </summary>
            {/* Compiled-rule annotation: an artifact, so it reads terminal-dark in both themes. */}
            <div className="terminal mt-1.5 space-y-1 rounded-lg p-2.5 font-mono text-[11.5px] leading-relaxed text-ink-2">
              {(o.rules ?? []).map((r) => {
                // §3.7 honesty line: a mandatory concern never degrades to a
                // user prompt — show the action the compiler will emit.
                const raw = r[autonomy];
                const action = locked && raw === "require_approval" ? "deny" : raw;
                return (
                  <div key={r.suffix}>
                    {r.condition} →{" "}
                    <span className={`font-semibold ${actionTone[action] ?? ""}`}>{action}</span>
                    {action !== raw ? (
                      <span className="text-ink-3"> ← mandatory hardens the ask</span>
                    ) : null}
                  </div>
                );
              })}
              {(o.constraints ?? []).map(([k, v]) => (
                <div key={k}>
                  constraint: {k} = {String(v)}
                </div>
              ))}
              {o.kind === "runtime" ? (
                <div>enforced by: {(o.enforcers ?? []).join(", ")}</div>
              ) : null}
              <div className="text-ink-3">
                proven by {o.provenBy.join(", ")} · risk {o.risk}
              </div>
            </div>
          </details>
        </div>
      </div>
    </li>
  );
}
