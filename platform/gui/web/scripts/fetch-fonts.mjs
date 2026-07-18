/**
 * Self-host the Dossier design-system fonts (one-off; run inside the cage):
 *
 *   podman run --rm <cage flags + mounts> -w /app blastcontain-gui-toolbox \
 *     node scripts/fetch-fonts.mjs
 *
 * Fetches the latin-subset woff2 files for the exact families/weights the
 * BlastContain website loads, from Google's font CDN, into src/fonts/ —
 * so the console never fetches Google at runtime and the offline cage build
 * works. Validates the WOFF2 magic and writes a provenance manifest
 * (source URL + sha256 per file).
 */
import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

const FAMILIES = [
  { family: "Space Grotesk", slug: "space-grotesk", weights: [500, 700] },
  { family: "Inter", slug: "inter", weights: [400, 500, 600, 700] },
  { family: "JetBrains Mono", slug: "jetbrains-mono", weights: [400, 500, 700] },
];

// A modern-Chrome UA makes the css2 API serve woff2 sources.
const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36";

const OUT = path.resolve("src/fonts");

async function cssFor(f) {
  const url = `https://fonts.googleapis.com/css2?family=${f.family.replaceAll(" ", "+")}:wght@${f.weights.join(";")}&display=swap`;
  const res = await fetch(url, { headers: { "User-Agent": UA } });
  if (!res.ok) throw new Error(`css2 ${res.status} for ${f.family}`);
  return res.text();
}

/** Pull the latin-subset url per weight out of a css2 response. */
function latinUrls(css, weights) {
  const found = new Map();
  const blocks = css.split("/*").map((b) => "/*" + b);
  for (const block of blocks) {
    if (!block.startsWith("/* latin */")) continue;
    const weight = block.match(/font-weight:\s*(\d+)/)?.[1];
    const src = block.match(/src:\s*url\((https:[^)]+\.woff2)\)/)?.[1];
    if (weight && src && weights.includes(Number(weight))) found.set(Number(weight), src);
  }
  return found;
}

await mkdir(OUT, { recursive: true });
const manifest = { fetched_at: new Date().toISOString(), license: "OFL-1.1", files: [] };

for (const f of FAMILIES) {
  const css = await cssFor(f);
  const urls = latinUrls(css, f.weights);
  for (const w of f.weights) {
    const src = urls.get(w);
    if (!src) throw new Error(`no latin woff2 for ${f.family} ${w}`);
    const res = await fetch(src, { headers: { "User-Agent": UA } });
    if (!res.ok) throw new Error(`woff2 ${res.status} for ${f.family} ${w}`);
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.subarray(0, 4).toString("ascii") !== "wOF2") {
      throw new Error(`${f.family} ${w}: not a WOFF2 file (magic=${buf.subarray(0, 4).toString("hex")})`);
    }
    const name = `${f.slug}-${w}.woff2`;
    await writeFile(path.join(OUT, name), buf);
    manifest.files.push({
      file: name,
      family: f.family,
      weight: w,
      subset: "latin",
      source: src,
      bytes: buf.length,
      sha256: createHash("sha256").update(buf).digest("hex"),
    });
    console.log(`✓ ${name}  ${(buf.length / 1024).toFixed(1)} KB`);
  }
}

await writeFile(path.join(OUT, "MANIFEST.json"), JSON.stringify(manifest, null, 2) + "\n");
console.log(`\n${manifest.files.length} files → src/fonts/ (MANIFEST.json has sources + sha256)`);
