/** Cage→platform reachability probe: confirms the dev proxy's upstream works
 *  from inside the container. Run: node scripts/probe-api.mjs */
const base = process.env.BLASTCONTAIN_API_URL ?? "http://host.containers.internal:8080";

async function probe(path) {
  const t0 = Date.now();
  try {
    const res = await fetch(`${base}${path}`, { signal: AbortSignal.timeout(5000) });
    const body = await res.json().catch(() => null);
    return { path, status: res.status, ms: Date.now() - t0, body };
  } catch (e) {
    return { path, error: String(e?.cause ?? e), ms: Date.now() - t0 };
  }
}

const health = await probe("/health");
const fleet = await probe("/fleet");
console.log(`base: ${base}`);
console.log(`health: ${health.status ?? "FAIL"} ${health.body ? JSON.stringify(health.body) : health.error}`);
console.log(
  `fleet:  ${fleet.status ?? "FAIL"} ${
    fleet.body?.agents ? "agents=" + fleet.body.agents.map((a) => a.agent_id).join(",") : (fleet.error ?? "")
  }`,
);
process.exit(health.status === 200 && fleet.status === 200 ? 0 : 1);
