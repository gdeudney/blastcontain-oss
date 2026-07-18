import type { Metadata } from "next";
import localFont from "next/font/local";
import "./globals.css";
import { Nav } from "@/components/nav";
import { ThemeToggle } from "@/components/theme-toggle";
import { Badge } from "@/components/ui";
import { API_MODE } from "@/lib/api/client";

// Self-hosted (src/fonts + MANIFEST.json provenance) — the console never
// fetches Google at runtime, and the offline cage build works.
const inter = localFont({
  src: [
    { path: "../fonts/inter-400.woff2", weight: "400" },
    { path: "../fonts/inter-500.woff2", weight: "500" },
    { path: "../fonts/inter-600.woff2", weight: "600" },
    { path: "../fonts/inter-700.woff2", weight: "700" },
  ],
  variable: "--font-inter",
  display: "swap",
});
const jbmono = localFont({
  src: [
    { path: "../fonts/jetbrains-mono-400.woff2", weight: "400" },
    { path: "../fonts/jetbrains-mono-500.woff2", weight: "500" },
    { path: "../fonts/jetbrains-mono-700.woff2", weight: "700" },
  ],
  variable: "--font-jbmono",
  display: "swap",
});
const sgrotesk = localFont({
  src: [
    { path: "../fonts/space-grotesk-500.woff2", weight: "500" },
    { path: "../fonts/space-grotesk-700.woff2", weight: "700" },
  ],
  variable: "--font-sgrotesk",
  display: "swap",
});

export const metadata: Metadata = {
  title: "BlastContain Console",
  description: "Agent governance that contains the blast radius",
};

// Apply the saved theme before paint (same key the website uses).
const themeInit =
  "(function(){try{if(localStorage.getItem('bc-theme')==='dark')document.documentElement.setAttribute('data-theme','dark')}catch(e){}})()";

function BrandMark() {
  return (
    <svg width="26" height="26" viewBox="0 0 26 26" fill="none" aria-hidden="true">
      <rect x="1.5" y="1.5" width="23" height="23" rx="5" stroke="var(--contain)" strokeWidth="1.6" opacity=".55" />
      <path d="M13 6.5 L14.7 11.3 L19.5 13 L14.7 14.7 L13 19.5 L11.3 14.7 L6.5 13 L11.3 11.3 Z" fill="var(--blast)" />
      <circle cx="13" cy="13" r="2.1" fill="var(--bg)" />
    </svg>
  );
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${inter.variable} ${jbmono.variable} ${sgrotesk.variable}`}
      suppressHydrationWarning
    >
      <body className="antialiased">
        <script dangerouslySetInnerHTML={{ __html: themeInit }} />
        <div className="flex min-h-screen">
          <aside className="flex w-56 shrink-0 flex-col border-r border-line-2 bg-paper-soft">
            <div className="px-5 py-5">
              <a href="/fleet" className="flex items-center gap-2.5 no-underline">
                <BrandMark />
                <span>
                  <span className="block font-display text-[17px] font-bold leading-tight tracking-tight text-ink">
                    Blast<span className="text-blast">Contain</span>
                  </span>
                  <span className="block font-mono text-[9.5px] uppercase tracking-[0.22em] text-ink-3">
                    governance console
                  </span>
                </span>
              </a>
            </div>
            <Nav />
            <div className="mt-auto px-5 py-4 font-mono text-[10px] uppercase tracking-[0.16em] text-ink-3">
              control plane · v0.2
            </div>
          </aside>
          <div className="flex min-w-0 flex-1 flex-col">
            {/* Dossier rule: a strong ink line under the header, like a document head. */}
            <header className="flex items-center justify-end gap-3 border-b-2 border-ink bg-panel px-6 py-3">
              {API_MODE === "mock" ? (
                <Badge tone="warn">demo data — no backend</Badge>
              ) : (
                <Badge tone="ok">live</Badge>
              )}
              <ThemeToggle />
            </header>
            <main className="min-w-0 flex-1 p-6">{children}</main>
          </div>
        </div>
      </body>
    </html>
  );
}
