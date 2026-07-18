"use client";

/** Screen 5 — Fleet dashboard (wireframes §5): lifecycle state per agent,
 *  violations, one click into trouble. Backed by /fleet + /violations.
 *  Search / state filter / column sort are client-side: the fleet payload is
 *  small and /fleet takes no query params. (Owner filter waits on the server
 *  enriching /fleet rows with owner — not in the contract yet.) */
import { useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { Badge, Card, inputCls } from "@/components/ui";
import {
  getFleet,
  listViolations,
  type FleetResponse,
  type ViolationsResponse,
} from "@/lib/api/client";

type FleetAgent = NonNullable<FleetResponse["agents"]>[number];
type SortKey = "agent" | "last_scan" | "status" | "critical";

function timeAgo(iso: string | null | undefined): string {
  if (!iso) return "—";
  const mins = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 60_000));
  if (mins < 60) return `${mins}m`;
  if (mins < 1440) return `${Math.round(mins / 60)}h`;
  return `${Math.round(mins / 1440)}d`;
}

// First click per column starts from the direction you'd actually want.
const DEFAULT_DIR: Record<SortKey, 1 | -1> = {
  agent: 1, // A→Z
  last_scan: -1, // newest first
  status: 1,
  critical: -1, // worst first
};

function compare(a: FleetAgent, b: FleetAgent, key: SortKey): number {
  switch (key) {
    case "agent":
      return (a.agent_id ?? "").localeCompare(b.agent_id ?? "");
    case "status":
      return (a.status ?? "").localeCompare(b.status ?? "");
    case "critical":
      return (a.critical ?? 0) - (b.critical ?? 0);
    case "last_scan":
      return Date.parse(a.last_scan ?? "") - Date.parse(b.last_scan ?? "");
  }
}

/** Unscanned agents (no last_scan) pin to the end in either direction. */
function sortRows(rows: FleetAgent[], key: SortKey, dir: 1 | -1): FleetAgent[] {
  return [...rows].sort((a, b) => {
    if (key === "last_scan") {
      const aMissing = !a.last_scan;
      const bMissing = !b.last_scan;
      if (aMissing || bMissing) return Number(aMissing) - Number(bMissing);
    }
    return dir * compare(a, b, key);
  });
}

export default function FleetPage() {
  const [fleet, setFleet] = useState<FleetResponse | null>(null);
  const [violations, setViolations] = useState<ViolationsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [stateFilter, setStateFilter] = useState("all");
  const [sevFilter, setSevFilter] = useState<"CRITICAL" | "HIGH" | null>(null);
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 } | null>(null);

  useEffect(() => {
    Promise.all([getFleet(), listViolations()])
      .then(([f, v]) => {
        setFleet(f);
        setViolations(v);
      })
      .catch((e) => setError(String(e?.message ?? e)));
  }, []);

  // Filters live in the URL (?q=&state=&sev=) so a view is shareable and
  // survives reload. Read once on mount; write back on every change.
  const urlSynced = useRef(false);

  useEffect(() => {
    const p = new URLSearchParams(window.location.search);
    const sev = p.get("sev");
    if (sev === "CRITICAL" || sev === "HIGH") setSevFilter(sev);
    const st = p.get("state");
    if (st) setStateFilter(st);
    const qq = p.get("q");
    if (qq) setQ(qq);
  }, []);

  useEffect(() => {
    if (!urlSynced.current) {
      urlSynced.current = true; // skip the mount run — the URL is the source then
      return;
    }
    const p = new URLSearchParams();
    if (q.trim()) p.set("q", q.trim());
    if (stateFilter !== "all") p.set("state", stateFilter);
    if (sevFilter) p.set("sev", sevFilter);
    const qs = p.toString();
    window.history.replaceState(null, "", qs ? `?${qs}` : window.location.pathname);
  }, [q, stateFilter, sevFilter]);

  const allAgents = useMemo(() => fleet?.agents ?? [], [fleet]);

  const presentStates = useMemo(() => {
    const states: string[] = Array.from(
      new Set(allAgents.flatMap((a) => Object.values(a.charters ?? {}))),
    ).sort();
    // A URL-supplied state stays selectable even if no agent currently has it.
    if (stateFilter !== "all" && !states.includes(stateFilter)) states.unshift(stateFilter);
    return states;
  }, [allAgents, stateFilter]);

  // Agents that currently have a finding of the selected severity.
  const violatingAgents = useMemo(() => {
    if (!sevFilter) return null;
    return new Set(
      (violations?.violations ?? [])
        .filter((v) => v.severity === sevFilter)
        .map((v) => v.agent_id),
    );
  }, [violations, sevFilter]);

  const rows = useMemo(() => {
    let r = allAgents;
    const needle = q.trim().toLowerCase();
    if (needle) {
      r = r.filter(
        (a) =>
          (a.agent_id ?? "").toLowerCase().includes(needle) ||
          Object.keys(a.charters ?? {}).some((env) => env.toLowerCase().includes(needle)),
      );
    }
    if (stateFilter !== "all") {
      r = r.filter((a) => Object.values(a.charters ?? {}).some((st) => st === stateFilter));
    }
    if (violatingAgents) r = r.filter((a) => violatingAgents.has(a.agent_id));
    if (sort) r = sortRows(r, sort.key, sort.dir);
    return r;
  }, [allAgents, q, stateFilter, violatingAgents, sort]);

  const clickSort = (key: SortKey) =>
    setSort((prev) =>
      prev?.key === key ? { key, dir: prev.dir === 1 ? -1 : 1 } : { key, dir: DEFAULT_DIR[key] },
    );

  if (error) {
    return (
      <Card>
        <div className="text-sm text-danger">Could not reach the platform: {error}</div>
      </Card>
    );
  }
  if (!fleet) return <div className="font-mono text-xs text-ink-3">Loading fleet…</div>;

  const states = allAgents.flatMap((a) => Object.values(a.charters ?? {}));
  const count = (s: string) => states.filter((x) => x === s).length;
  const crit = violations?.violations?.filter((v) => v.severity === "CRITICAL").length ?? 0;
  const high = violations?.violations?.filter((v) => v.severity === "HIGH").length ?? 0;
  const filtered = rows.length !== allAgents.length;

  const SortHeader = ({ label, k, alignRight }: { label: string; k: SortKey; alignRight?: boolean }) => (
    <th className={`px-4 py-2.5 ${alignRight ? "text-right" : "text-left"}`}>
      <button
        onClick={() => clickSort(k)}
        className="inline-flex items-center gap-1 uppercase tracking-[0.14em] transition-colors hover:text-ink"
        title={`sort by ${label.toLowerCase()}`}
      >
        {label}
        <span className="w-3 text-[9px]">{sort?.key === k ? (sort.dir === 1 ? "▲" : "▼") : ""}</span>
      </button>
    </th>
  );

  return (
    <div className="space-y-4">
      <div className="flex items-baseline justify-between">
        <h1 className="font-display text-xl font-bold tracking-tight">Fleet</h1>
        <div className="flex gap-3 font-mono text-xs text-ink-2">
          <span>Agents {fleet.total}</span>
          <span className="text-contain">● Active {count("active")}</span>
          <span className="text-amber">⏸ Paused {count("paused")}</span>
          <span className="text-danger">⚠ Quarantined {count("quarantined")}</span>
        </div>
      </div>

      <div className="flex gap-3 text-sm">
        <Card className="flex-1">
          <div className="font-mono text-[10.5px] uppercase tracking-[0.18em] text-ink-3">
            Open violations <span className="normal-case tracking-normal">(click to filter)</span>
          </div>
          <div className="mt-1.5 flex items-center gap-3">
            {(
              [
                ["CRITICAL", crit],
                ["HIGH", high],
              ] as const
            ).map(([sev, n]) => {
              const active = sevFilter === sev;
              const dimmed = sevFilter !== null && !active;
              return (
                <button
                  key={sev}
                  onClick={() => setSevFilter((f) => (f === sev ? null : sev))}
                  aria-pressed={active}
                  title={`show only agents with ${sev} findings`}
                  className={`rounded-md transition-all ${active ? "ring-2 ring-current" : ""} ${
                    dimmed ? "opacity-40" : ""
                  } ${sev === "CRITICAL" ? "text-danger" : "text-amber"}`}
                >
                  <Badge tone={sev}>
                    {sev} {n}
                  </Badge>
                </button>
              );
            })}
            {sevFilter ? (
              <button
                onClick={() => setSevFilter(null)}
                className="font-mono text-[11px] text-ink-3 underline underline-offset-2 transition-colors hover:text-ink"
              >
                clear
              </button>
            ) : null}
          </div>
        </Card>
        <Card className="flex-1">
          <div className="font-mono text-[10.5px] uppercase tracking-[0.18em] text-ink-3">Author</div>
          <div className="mt-1.5 text-sm">
            <Link
              href="/charters/new"
              className="font-medium text-blast underline-offset-2 hover:underline"
            >
              New Charter →
            </Link>{" "}
            <span className="text-ink-3">(derive from a scan, then ratify)</span>
          </div>
        </Card>
      </div>

      <Card className="overflow-x-auto p-0">
        <div className="flex flex-wrap items-center gap-2 border-b border-line-2 px-4 py-2.5">
          <input
            className={`${inputCls} max-w-60`}
            placeholder="Search agent / env…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            aria-label="Search agents"
          />
          <div className="w-44">
            <select
              className={inputCls}
              value={stateFilter}
              onChange={(e) => setStateFilter(e.target.value)}
              aria-label="Filter by lifecycle state"
            >
              <option value="all">all states</option>
              {presentStates.map((st) => (
                <option key={st} value={st}>
                  {st}
                </option>
              ))}
            </select>
          </div>
          <span className="ml-auto font-mono text-[11px] text-ink-3">
            {filtered ? `${rows.length} of ${allAgents.length} agents` : `${allAgents.length} agents`}
          </span>
        </div>
        <table className="w-full text-sm">
          <thead>
            {/* Dossier table rule: a solid ink line under the header row. */}
            <tr className="border-b border-ink text-left font-mono text-[10.5px] text-ink-3">
              <SortHeader label="Agent" k="agent" />
              <th className="px-4 py-2.5 uppercase tracking-[0.14em]">Charters (env → state)</th>
              <SortHeader label="Last scan" k="last_scan" />
              <SortHeader label="Scan status" k="status" />
              <SortHeader label="Crit" k="critical" alignRight />
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-4 py-6 text-center text-ink-3">
                  No agents match{q ? ` “${q}”` : ""}
                  {stateFilter !== "all" ? ` in state “${stateFilter}”` : ""}
                  {sevFilter ? ` with ${sevFilter} findings` : ""}.
                </td>
              </tr>
            ) : (
              rows.map((a) => (
                <tr key={a.agent_id} className="border-b border-line last:border-0">
                  <td className="px-4 py-2.5 font-medium">{a.agent_id}</td>
                  <td className="px-4 py-2.5">
                    <div className="flex flex-wrap gap-1.5">
                      {Object.entries(a.charters ?? {}).map(([env, st]) => (
                        <Badge key={env} tone={st ?? "discovered"}>
                          {env ? `${env}: ` : ""}
                          {st}
                        </Badge>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-2.5 font-mono text-xs text-ink-3">{timeAgo(a.last_scan)}</td>
                  <td className="px-4 py-2.5">
                    <Badge
                      tone={
                        a.status === "PASSED"
                          ? "ok"
                          : ["FAILED", "REJECTED", "QUARANTINED"].includes(a.status ?? "")
                            ? "CRITICAL"
                            : "discovered"
                      }
                    >
                      {a.status}
                    </Badge>
                  </td>
                  <td
                    className={`px-4 py-2.5 text-right font-mono text-xs font-semibold ${
                      (a.critical ?? 0) > 0 ? "text-danger" : "text-ink-3"
                    }`}
                  >
                    {a.critical}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </Card>

      <Card>
        <div className="mb-2 font-mono text-[10.5px] uppercase tracking-[0.18em] text-ink-3">
          {sevFilter ? `${sevFilter} findings` : "CRITICAL / HIGH findings"}
        </div>
        <ul className="space-y-1.5 text-sm">
          {(violations?.violations ?? [])
            .filter((v) => !sevFilter || v.severity === sevFilter)
            .map((v, i) => (
              <li key={i} className="flex items-center gap-2">
                <Badge tone={v.severity ?? "HIGH"}>{v.severity}</Badge>
                <span className="font-medium">{v.agent_id}</span>
                <span className="text-ink-3">
                  {v.check_id} · {v.title}
                </span>
              </li>
            ))}
        </ul>
      </Card>
    </div>
  );
}
