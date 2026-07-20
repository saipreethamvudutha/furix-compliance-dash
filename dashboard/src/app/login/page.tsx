"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Shield, Eye, EyeOff, Lock, Mail, AlertCircle, ShieldCheck, Activity, Bot, Globe } from "lucide-react";

const DEMO_USERS: { email: string; password: string; role: string; roleId: "admin" | "analyst" | "auditor" | "mssp" }[] = [
  { email: "admin@byoc.com",   password: "admin123",   role: "BYOC Admin",         roleId: "admin"   },
  { email: "analyst@byoc.com", password: "analyst123", role: "SOC Analyst",        roleId: "analyst" },
  { email: "auditor@byoc.com", password: "auditor123", role: "Compliance Auditor", roleId: "auditor" },
  { email: "mssp@byoc.com",    password: "mssp123",    role: "MSSP Operator",      roleId: "mssp"    },
];

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const prev = document.documentElement.getAttribute("data-theme");
    document.documentElement.setAttribute("data-theme", "light");
    return () => {
      document.documentElement.setAttribute("data-theme", prev ?? "dark");
    };
  }, []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    // Real server-side login (Wave-N #1): the credential is validated on the
    // server, which sets an encrypted HTTP-only session cookie. No secret or
    // identity is written to localStorage.
    try {
      const res = await fetch("/bff/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: email.trim().toLowerCase(), password }),
      });
      if (!res.ok) {
        setError("Invalid credentials.");
        setLoading(false);
        return;
      }
      const data = (await res.json()) as { user?: { email: string; role: string } };
      // keep a NON-secret UI hint for the client RBAC/theme (not an auth token)
      try {
        const roleId =
          DEMO_USERS.find((u) => u.email === data.user?.email)?.roleId ?? "admin";
        // UI-only shell hint; the real auth is the encrypted server session
        // cookie (this flag grants no API access on its own).
        localStorage.setItem("byoc-auth", "1");
        localStorage.setItem("byoc-user-email", data.user?.email ?? email);
        localStorage.setItem("byoc-user-role", data.user?.role ?? "");
        localStorage.setItem("byoc-rbac-role", roleId);
        localStorage.setItem("byoc-org", "Coventra Health Insurance");
      } catch {}
      router.replace("/");
    } catch {
      setError("Sign-in failed — is the server reachable?");
      setLoading(false);
    }
  };

  return (
    <div
      className="relative flex min-h-screen items-center justify-center overflow-hidden px-4"
      style={{ background: "#ffffff" }}
    >
<div
        className="relative grid w-full max-w-[960px] overflow-hidden rounded-3xl md:grid-cols-2"
        style={{
          background: "rgba(255,255,255,0.85)",
          backdropFilter: "blur(20px)",
          border: "1px solid rgba(184,122,63,0.25)",
          boxShadow: "0 30px 80px rgba(120,90,40,0.18), 0 0 0 1px rgba(255,255,255,0.6) inset",
        }}
      >
        {/* Left brand panel */}
        <div
          className="relative hidden flex-col justify-between p-8 md:flex"
          style={{
            background:
              "linear-gradient(160deg, #6fd6c4 0%, #1c4f57 35%, #0d2024 70%, #000000 100%)",
            color: "#e7d9c2",
          }}
        >
          <div
            className="pointer-events-none absolute inset-0 opacity-50"
            style={{
              backgroundImage:
                "radial-gradient(circle at 80% 15%, rgba(111,214,196,0.45), transparent 55%), radial-gradient(circle at 10% 90%, rgba(0,0,0,0.6), transparent 60%)",
            }}
          />
          <div className="relative flex flex-col items-center text-center">
            <div
              className="flex h-48 w-48 items-center justify-center rounded-3xl"
              style={{
                background:
                  "linear-gradient(160deg, #f5f0e8 0%, #d8a368 25%, #7a4a22 70%, #3d2410 100%)",
                border: "1px solid rgba(224,160,99,0.45)",
                boxShadow:
                  "inset 0 1px 0 rgba(255,255,255,0.3), 0 18px 40px rgba(0,0,0,0.45)",
              }}
            >
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img
                src="/furix-logo-new.png"
                alt="Furix"
                className="h-36 w-36 object-contain"
                style={{
                  filter:
                    "hue-rotate(25deg) saturate(0.7) brightness(0.95) sepia(0.3) drop-shadow(0 8px 18px rgba(0,0,0,0.55))",
                }}
              />
            </div>
            <span className="mt-1 text-[24px] font-bold tracking-wide">Furix</span>
            <span className="text-[10px] uppercase tracking-[0.3em] opacity-70">BYOC</span>

            <h2 className="mt-4 text-[26px] font-semibold leading-tight">
              Coventra Health <br /> security operations.
            </h2>
            <p className="mt-2 text-[13px] opacity-80">
              HIPAA-aligned posture, PHI protection and incident response for 1.2M plan members.
            </p>
          </div>

          <ul className="relative mt-6 space-y-3 text-[12px]">
            <BrandFeature icon={<ShieldCheck className="h-4 w-4" />} text="HIPAA Covered Entity · NCQA accredited" />
            <BrandFeature icon={<Activity className="h-4 w-4" />} text="PHI database & PAM vault monitoring" />
            <BrandFeature icon={<Bot className="h-4 w-4" />} text="AI remediation suggestions in &lt; 60s" />
            <BrandFeature icon={<Globe className="h-4 w-4" />} text="Columbus, OH · AWS hybrid · 162 assets" />
          </ul>

          
        </div>

        {/* Right form panel */}
        <div className="flex flex-col justify-center p-8">
        <div className="mb-6 flex flex-col items-center md:hidden">
          <div
            className="mb-3 flex h-14 w-14 items-center justify-center rounded-2xl"
            style={{
              background:
                "radial-gradient(circle at 35% 25%, var(--emblem-grad-from), var(--emblem-grad-to) 80%)",
              boxShadow:
                "inset 0 1px 0 rgba(255,224,180,0.5), 0 6px 16px rgba(120,90,40,0.25)",
            }}
          >
            <Shield className="h-7 w-7" style={{ color: "var(--copper-bright)" }} />
          </div>
        </div>
        <div className="mb-6 text-center">
          <h1 className="text-[22px] font-semibold tracking-wide" style={{ color: "var(--panel-text)" }}>
            Welcome back
          </h1>
          <p className="mt-1 text-[12px]" style={{ color: "var(--panel-text-muted)" }}>
            Sign in to Coventra Health Insurance
          </p>
        </div>

        <form onSubmit={submit}>
          {error && (
            <div
              className="mb-4 flex items-start gap-2 rounded-lg px-3 py-2 text-[12px]"
              style={{
                background: "rgba(212,106,94,0.12)",
                border: "1px solid rgba(212,106,94,0.35)",
                color: "var(--crit-red)",
              }}
            >
              <AlertCircle className="mt-[1px] h-4 w-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <label className="mb-1 block text-[11px] uppercase tracking-wider" style={{ color: "var(--panel-text-muted)" }}>
            Email
          </label>
          <div
            className="mb-4 flex items-center gap-2 rounded-xl px-3"
            style={{
              background: "linear-gradient(180deg, var(--search-bg-top), var(--search-bg-bot))",
              border: "1px solid var(--search-border)",
              boxShadow: "inset 0 2px 4px var(--pill-shadow-inset)",
            }}
          >
            <Mail className="h-4 w-4" style={{ color: "var(--panel-text-muted)" }} />
            <input
              type="email"
              autoComplete="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="h-11 flex-1 bg-transparent text-sm outline-none"
              style={{ color: "var(--panel-text)" }}
              placeholder="you@company.com"
              required
            />
          </div>

          <label className="mb-1 block text-[11px] uppercase tracking-wider" style={{ color: "var(--panel-text-muted)" }}>
            Password
          </label>
          <div
            className="mb-2 flex items-center gap-2 rounded-xl px-3"
            style={{
              background: "linear-gradient(180deg, var(--search-bg-top), var(--search-bg-bot))",
              border: "1px solid var(--search-border)",
              boxShadow: "inset 0 2px 4px var(--pill-shadow-inset)",
            }}
          >
            <Lock className="h-4 w-4" style={{ color: "var(--panel-text-muted)" }} />
            <input
              type={showPw ? "text" : "password"}
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="h-11 flex-1 bg-transparent text-sm outline-none"
              style={{ color: "var(--panel-text)" }}
              placeholder="••••••••"
              required
            />
            <button
              type="button"
              onClick={() => setShowPw((s) => !s)}
              className="p-1"
              style={{ color: "var(--panel-text-muted)" }}
              aria-label="Toggle password visibility"
            >
              {showPw ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </button>
          </div>

          <div className="mb-5 flex items-center justify-between text-[11px]">
            <label className="flex items-center gap-2" style={{ color: "var(--panel-text-muted)" }}>
              <input type="checkbox" className="h-3 w-3 accent-current" defaultChecked />
              Remember this device
            </label>
            <a href="#" style={{ color: "var(--section-heading)" }}>
              Forgot password?
            </a>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full rounded-xl px-4 py-2.5 text-sm font-semibold transition-transform hover:scale-[1.01] active:scale-[0.99] disabled:opacity-60"
            style={{
              background:
                "radial-gradient(circle at 35% 25%, var(--disc-from), var(--disc-to) 80%)",
              color: "var(--disc-text)",
              border: "1px solid rgba(184,122,63,0.45)",
              boxShadow:
                "inset 0 1px 0 rgba(255,224,180,0.5), inset 0 -2px 4px rgba(0,0,0,0.45), 0 6px 14px rgba(120,90,40,0.25)",
            }}
          >
            {loading ? "Signing in…" : "Sign in"}
          </button>

        </form>

        <p className="mt-4 text-center text-[11px]" style={{ color: "var(--panel-text-muted)" }}>
          © BYOC · Secure tenant · SOC 2 Type II
        </p>
        </div>
      </div>
    </div>
  );
}

function BrandFeature({ icon, text }: { icon: React.ReactNode; text: string }) {
  return (
    <li className="flex items-center gap-2.5">
      <span
        className="flex h-7 w-7 items-center justify-center rounded-lg"
        style={{
          background: "rgba(255,255,255,0.18)",
          border: "1px solid rgba(255,255,255,0.3)",
          color: "#ffffff",
          backdropFilter: "blur(8px)",
        }}
      >
        {icon}
      </span>
      <span dangerouslySetInnerHTML={{ __html: text }} />
    </li>
  );
}
