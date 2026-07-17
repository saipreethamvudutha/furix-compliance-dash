$files = @(
  'src/app/users/page.tsx',
  'src/app/ai-actions/triage-queue/page.tsx',
  'src/app/assets/databases/page.tsx',
  'src/app/backup/page.tsx',
  'src/app/detection-rules/page.tsx',
  'src/app/findings/page.tsx',
  'src/app/knowledge-graph/page.tsx',
  'src/app/reports/technical-volumes/page.tsx',
  'src/app/risk-scoring/top-risks/page.tsx',
  'src/app/threat-intel/page.tsx'
)
$pattern = 'function Kpi\(\{ label, value, sub, tone = "teal" \}: \{ label: string; value: string; sub: string; tone\?: "teal" \| "copper" \}\) \{\s*return \(\s*<div className="skeuo-panel p-4">\s*<p className="text-\[11px\] uppercase tracking-wider" style=\{\{ color: "var\(--panel-text-muted\)" \}\}>\{label\}</p>\s*<p className="numeric-glow mt-2 text-\[\d+px\] font-light leading-none" style=\{\{ color: tone === "teal" \? "var\(--metric-teal\)" : "var\(--metric-copper\)" \}\}>\{value\}</p>\s*<p className="mt-1 text-\[11\.5px\]" style=\{\{ color: "var\(--panel-text-muted\)" \}\}>\{sub\}</p>\s*</div>\s*\);\s*\}'

$replacement = @'
function Kpi({ label, value, sub, tone = "teal" }: { label: string; value: string; sub: string; tone?: "teal" | "copper" }) {
  return (
    <div className="skeuo-panel p-4">
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0 flex-1">
          <p className="text-[11px] uppercase tracking-wider" style={{ color: "var(--panel-text-muted)" }}>{label}</p>
          <p className="numeric-glow mt-1.5 text-[28px] font-light leading-none" style={{ color: tone === "teal" ? "var(--metric-teal)" : "var(--metric-copper)" }}>{value}</p>
          <p className="mt-1 text-[11px] truncate" style={{ color: "var(--panel-text-muted)" }}>{sub}</p>
        </div>
        <KpiBgIcon label={label} tone={tone === "copper" ? "copper" : "teal"} size={44} opacity={0.28} />
      </div>
    </div>
  );
}
'@

foreach ($f in $files) {
  $c = Get-Content $f -Raw
  if ($c -match $pattern) {
    $c = [System.Text.RegularExpressions.Regex]::Replace($c, $pattern, $replacement)
    if ($c -notmatch 'from "@/lib/kpi-icon"') {
      $c = $c -replace '(import \{[^}]*\} from "lucide-react";)', "`$1`r`nimport { KpiBgIcon } from `"@/lib/kpi-icon`";"
    }
    Set-Content $f -Value $c -NoNewline
    Write-Host "PATCHED: $f"
  } else {
    Write-Host "SKIP (no match): $f"
  }
}
