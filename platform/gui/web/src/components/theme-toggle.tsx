"use client";

/** Light ("dossier") ⇄ dark ("ops room"). Same data-theme attribute and
 *  'bc-theme' storage key as the website, so brand behavior matches. The
 *  icon swap is pure CSS (globals.css) — no hydration-sensitive state. */
export function ThemeToggle() {
  const toggle = () => {
    const root = document.documentElement;
    const dark = root.getAttribute("data-theme") === "dark";
    try {
      if (dark) {
        root.removeAttribute("data-theme");
        localStorage.setItem("bc-theme", "light");
      } else {
        root.setAttribute("data-theme", "dark");
        localStorage.setItem("bc-theme", "dark");
      }
    } catch {
      /* storage unavailable — toggle still applies for this page */
    }
  };
  return (
    <button
      onClick={toggle}
      aria-label="Toggle light/dark theme"
      title="Toggle light/dark"
      className="rounded-md border border-line-2 p-2 text-ink-2 transition-colors hover:border-ink-3 hover:text-ink"
    >
      <svg className="t-sun" width="15" height="15" viewBox="0 0 16 16" fill="none" aria-hidden="true">
        <circle cx="8" cy="8" r="3" stroke="currentColor" strokeWidth="1.4" />
        <path
          d="M8 1v2M8 13v2M1 8h2M13 8h2M3 3l1.4 1.4M11.6 11.6L13 13M3 13l1.4-1.4M11.6 4.4L13 3"
          stroke="currentColor"
          strokeWidth="1.4"
          strokeLinecap="round"
        />
      </svg>
      <svg className="t-moon" width="15" height="15" viewBox="0 0 16 16" fill="none" aria-hidden="true">
        <path
          d="M13.5 10.2A5.5 5.5 0 1 1 5.8 2.5a4.5 4.5 0 0 0 7.7 7.7z"
          stroke="currentColor"
          strokeWidth="1.4"
          strokeLinejoin="round"
        />
      </svg>
    </button>
  );
}
