"use client";

/** Screen 1 — Scope & posture. Scope + autonomy first (the axes that change
 *  everything); strictness/tier secondary. Seeding makes it review-not-blank-form. */
import { Button, Card, Field, inputCls, Radio } from "@/components/ui";
import type { Strictness } from "@/lib/catalog";
import type { WizardState } from "./wizard";

export function StepScope({
  s,
  patch,
  busy,
  onNext,
}: {
  s: WizardState;
  patch: (p: Partial<WizardState>) => void;
  busy: boolean;
  onNext: () => void;
}) {
  return (
    <Card className="space-y-6">
      <section className="space-y-2">
        <h2 className="font-mono text-[11px] font-semibold uppercase tracking-[0.18em] text-ink-3">Scope</h2>
        <div className="grid grid-cols-2 gap-3">
          <Radio
            name="scope"
            checked={false}
            onChange={() => {}}
            title="Org Standard"
            detail="applies to every agent in the tenant (governance group only) — coming soon"
          />
          <Radio
            name="scope"
            checked
            onChange={() => {}}
            title="Agent Charter"
            detail="this agent only"
          />
        </div>
        <div className="grid grid-cols-2 gap-3 pt-1">
          <Field label="Agent ID" hint="Identity = (agent_id, environment)">
            <input
              className={inputCls}
              value={s.agentId}
              onChange={(e) => patch({ agentId: e.target.value })}
              placeholder="invoice-bot"
            />
          </Field>
          <Field label="Environment">
            <select
              className={inputCls}
              value={s.environment}
              onChange={(e) => patch({ environment: e.target.value })}
            >
              <option value="prod">prod</option>
              <option value="staging">staging</option>
              <option value="dev">dev</option>
            </select>
          </Field>
        </div>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={s.seedFromScan}
            onChange={(e) => patch({ seedFromScan: e.target.checked })}
          />
          <span>
            Seed from <span className="font-medium">↻ latest Verify scan</span>
            <span className="text-ink-3"> — derive-then-ratify: review, not data entry</span>
          </span>
        </label>
      </section>

      <section className="space-y-2">
        <h2 className="font-mono text-[11px] font-semibold uppercase tracking-[0.18em] text-ink-3">
          Autonomy <span className="normal-case tracking-normal text-ink-3">(sets how every concern compiles)</span>
        </h2>
        <div className="grid grid-cols-2 gap-3">
          <Radio
            name="autonomy"
            checked={s.autonomy === "autonomous"}
            onChange={() => patch({ autonomy: "autonomous" })}
            title="Autonomous — runs unattended"
            detail="concerns compile to DENY"
          />
          <Radio
            name="autonomy"
            checked={s.autonomy === "interactive"}
            onChange={() => patch({ autonomy: "interactive" })}
            title="Copilot — human present"
            detail="concerns compile to REQUIRE APPROVAL (≈ zero added latency: the human is already there)"
          />
        </div>
      </section>

      <section className="space-y-2">
        <h2 className="font-mono text-[11px] font-semibold uppercase tracking-[0.18em] text-ink-3">
          Posture <span className="normal-case tracking-normal text-ink-3">(secondary)</span>
        </h2>
        <div className="grid grid-cols-3 gap-3">
          <Field label="Strictness" hint="pre-selects concerns; you adjust next">
            <select
              className={inputCls}
              value={s.strictness}
              onChange={(e) => patch({ strictness: e.target.value as Strictness })}
            >
              <option value="locked">Locked</option>
              <option value="balanced">Balanced</option>
              <option value="permissive">Permissive</option>
            </select>
          </Field>
          <Field label="Trust tier">
            <select
              className={inputCls}
              value={s.trustTier}
              onChange={(e) => patch({ trustTier: Number(e.target.value) })}
            >
              {[0, 1, 2, 3].map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Owner" hint="named accountability — no vacuum">
            <input
              className={inputCls}
              value={s.owner}
              onChange={(e) => patch({ owner: e.target.value })}
              placeholder="alice@example.com"
            />
          </Field>
        </div>
      </section>

      <div className="flex justify-end gap-2 border-t border-line pt-4">
        <Button onClick={onNext} disabled={busy || !s.agentId}>
          {busy ? "Deriving…" : "Next →"}
        </Button>
      </div>
    </Card>
  );
}
