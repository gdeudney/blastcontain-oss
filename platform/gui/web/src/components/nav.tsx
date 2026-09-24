"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const items = [
  { href: "/fleet", label: "Fleet" },
  { href: "/charters/new", label: "New Charter" },
];

const soon = ["Standards", "Exceptions", "Plugins"];

export function Nav() {
  const pathname = usePathname();
  return (
    <nav className="flex flex-col gap-0.5 px-3">
      {items.map((it) => {
        const active = pathname?.startsWith(it.href);
        return (
          <Link
            key={it.href}
            href={it.href}
            className={`rounded-md px-2 py-1.5 text-[13.5px] font-medium transition-colors ${
              active ? "text-blast" : "text-ink-2 hover:text-ink"
            }`}
          >
            {it.label}
          </Link>
        );
      })}
      {soon.map((label) => (
        <span
          key={label}
          className="cursor-not-allowed rounded-md px-2 py-1.5 text-[13.5px] text-ink-3 opacity-70"
          title="coming soon"
        >
          {label}
          <span className="ml-1.5 font-mono text-[9px] uppercase tracking-[0.18em]">soon</span>
        </span>
      ))}
    </nav>
  );
}
