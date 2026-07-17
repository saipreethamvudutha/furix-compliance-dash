"use client";

import { useEffect, useState } from "react";
import { Moon, Sun } from "lucide-react";

type Mode = "dark" | "light";

export function ThemeToggle() {
  const [mode, setMode] = useState<Mode>("dark");

  // load
  useEffect(() => {
    const saved = (typeof window !== "undefined" &&
      (localStorage.getItem("byoc-theme") as Mode)) || "dark";
    setMode(saved);
    document.documentElement.setAttribute("data-theme", saved);
  }, []);

  const toggle = () => {
    const next: Mode = mode === "dark" ? "light" : "dark";
    setMode(next);
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("byoc-theme", next); } catch {}
  };

  return (
    <button
      onClick={toggle}
      aria-label="Toggle theme"
      className="flex h-9 w-9 items-center justify-center rounded-lg"
      style={{
        background:
          "linear-gradient(180deg, var(--tile-grad-top), var(--tile-grad-bot))",
        boxShadow:
          "inset 0 1px 0 rgba(255,255,255,0.08), inset 0 -2px 4px rgba(0,0,0,0.35)",
        color: "var(--tile-text)",
        border: "1px solid var(--tile-border)",
      }}
    >
      {mode === "dark" ? (
        <Sun className="h-[18px] w-[18px]" strokeWidth={1.8} />
      ) : (
        <Moon className="h-[18px] w-[18px]" strokeWidth={1.8} />
      )}
    </button>
  );
}
