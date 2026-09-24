/** Dossier UI primitives — panel cards with hairline borders, stamped
 *  statuses (mono, uppercase, 1px currentColor border), 2px radii.
 *  All colors come from the design-system tokens (globals.css). */
import type { ReactNode } from "react";

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <div className={`rounded-md border border-line-2 bg-panel p-5 ${className}`}>{children}</div>
  );
}

/** Stamped status: text color carries the meaning; border is currentColor. */
const stampTones: Record<string, string> = {
  active: "text-contain",
  ok: "text-contain",
  draft: "text-blast",
  info: "text-blast",
  paused: "text-amber",
  warn: "text-amber",
  HIGH: "text-amber",
  quarantined: "text-danger",
  CRITICAL: "text-danger",
  discovered: "text-ink-3",
  decommissioned: "text-ink-3",
  archived: "text-ink-3",
};

export function Badge({ tone, children }: { tone: string; children: ReactNode }) {
  const cls = stampTones[tone] ?? "text-ink-3";
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border border-current px-2 py-0.5 font-mono text-[10px] font-medium uppercase tracking-[0.12em] ${cls}`}
    >
      {children}
    </span>
  );
}

export function Button({
  children,
  onClick,
  variant = "primary",
  disabled = false,
  type = "button",
}: {
  children: ReactNode;
  onClick?: () => void;
  variant?: "primary" | "secondary" | "danger" | "ghost";
  disabled?: boolean;
  type?: "button" | "submit";
}) {
  const variants: Record<string, string> = {
    primary: "bg-blast text-btn-ink hover:-translate-y-px",
    secondary: "border border-ink-2 text-ink hover:-translate-y-px hover:border-ink",
    danger: "bg-danger text-white hover:-translate-y-px",
    ghost: "text-ink-2 hover:bg-paper-soft hover:text-ink",
  };
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={`rounded-md px-4 py-2 text-sm font-semibold tracking-[0.01em] transition-all disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:translate-y-0 ${variants[variant]}`}
    >
      {children}
    </button>
  );
}

export function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block text-sm font-medium text-ink-2">{label}</span>
      {children}
      {hint ? (
        <span className="mt-1 block font-mono text-[11px] text-ink-3">{hint}</span>
      ) : null}
    </label>
  );
}

export const inputCls =
  "w-full rounded-md border border-line-2 bg-panel px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus:border-ink-3 focus:outline-none";

export function Radio({
  name,
  checked,
  onChange,
  title,
  detail,
}: {
  name: string;
  checked: boolean;
  onChange: () => void;
  title: string;
  detail: string;
}) {
  return (
    <label
      className={`flex cursor-pointer items-start gap-3 rounded-md border p-3 transition-colors ${
        checked
          ? "border-ink bg-paper-soft"
          : "border-line-2 hover:border-ink-3"
      }`}
    >
      <input type="radio" name={name} checked={checked} onChange={onChange} className="mt-1 accent-[var(--blast)]" />
      <span>
        <span className="block text-sm font-medium text-ink">{title}</span>
        <span className="block text-xs text-ink-3">{detail}</span>
      </span>
    </label>
  );
}
