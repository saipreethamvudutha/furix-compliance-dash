import {
  Server, AlertTriangle, ShieldAlert, Activity, Cloud, ShieldCheck, Gauge, Radar, Bell, Clock,
  CheckCircle2, Database, Bug, FileText, Network as NetIcon, Eye, Users as UsersIcon, Zap, Bot, Layers,
  Lock, Key, Workflow, Inbox, Send, GitBranch, BarChart3, LineChart, Cpu, HardDrive, ScanLine,
  Calendar, BookOpen, Globe, Building2, FileCheck2, Fingerprint, Mail, CreditCard,
  Compass, Wrench, WifiOff, Box, Sparkles, Power, Hash, Filter as FilterIcon,
} from "lucide-react";

const tests: { rx: RegExp; el: React.ReactNode }[] = [
  { rx: /running|in flight|active scans|busy/i, el: <Activity /> },
  { rx: /progress|completion|saturation|utilization/i, el: <Gauge /> },
  { rx: /discover|auto.?detect|auto/i, el: <Compass /> },
  { rx: /configur|manual|registered|onboard/i, el: <Wrench /> },
  { rx: /unreach|offline|disconnect|dead|dlq/i, el: <WifiOff /> },
  { rx: /enrolled|enroll/i, el: <Sparkles /> },
  { rx: /session|active sessions|connected/i, el: <Power /> },
  { rx: /locked|lock(?:ed)? accounts?/i, el: <Lock /> },
  { rx: /tenant|client|org|company|customer/i, el: <Building2 /> },
  { rx: /total assets|assets monitored|managed assets|^assets$/i, el: <Server /> },
  { rx: /vulnerable assets|asset count/i, el: <Server /> },
  { rx: /critical findings|critical/i, el: <ShieldAlert /> },
  { rx: /high|escalat/i, el: <AlertTriangle /> },
  { rx: /medium|warn/i, el: <Eye /> },
  { rx: /low|healthy|pass|verified|^ok$/i, el: <CheckCircle2 /> },
  { rx: /open finding|finding|vuln|cve|patch|kev|epss/i, el: <Bug /> },
  { rx: /scan|nmap|nessus|dast|posture|prowler/i, el: <Radar /> },
  { rx: /scheduled|cadence|cron|timer/i, el: <Calendar /> },
  { rx: /scanner fleet|worker|pool|saturation/i, el: <Cpu /> },
  { rx: /queue|pending|backlog|inbox/i, el: <Inbox /> },
  { rx: /alert|p1|p2/i, el: <AlertTriangle /> },
  { rx: /bell|notification/i, el: <Bell /> },
  { rx: /mttr|mtta|time|eta|age|latency|duration|window/i, el: <Clock /> },
  { rx: /risk|score|posture|gauge|severity/i, el: <Gauge /> },
  { rx: /cloud|aws|azure|gcp|s3|ec2/i, el: <Cloud /> },
  { rx: /network|subnet|firewall|vpn|switch/i, el: <NetIcon /> },
  { rx: /db|database|sql|oracle|postgres|maria|redis/i, el: <Database /> },
  { rx: /backup|restore|snapshot|disk|storage/i, el: <HardDrive /> },
  { rx: /compliance|hipaa|soc|pci|nist|iso|cmmc|frameworks/i, el: <ShieldCheck /> },
  { rx: /attestation|signed|evidence/i, el: <FileCheck2 /> },
  { rx: /audit|chain|hash|integrity/i, el: <Lock /> },
  { rx: /mfa|webauthn|password|key|credential|vault|secret/i, el: <Key /> },
  { rx: /identity|user|member|account|role|directory/i, el: <UsersIcon /> },
  { rx: /event|stream|throughput|rate|ingest|logs?\b/i, el: <Activity /> },
  { rx: /ai|model|llm|agent|bot|inference/i, el: <Bot /> },
  { rx: /report|export|volume|archive|bundle/i, el: <FileText /> },
  { rx: /policy|playbook|workflow|pipeline|rule/i, el: <Workflow /> },
  { rx: /rule|detection/i, el: <ShieldAlert /> },
  { rx: /branch|version|commit|deploy/i, el: <GitBranch /> },
  { rx: /trend|chart|distribution/i, el: <LineChart /> },
  { rx: /metric|kpi|stat|count|total/i, el: <BarChart3 /> },
  { rx: /web|http|portal|url|domain|dns/i, el: <Globe /> },
  { rx: /email|smtp|gateway|phish/i, el: <Mail /> },
  { rx: /license|tier|billing|invoice|cost|mrr|usage/i, el: <CreditCard /> },
  { rx: /endpoint|wks|workstation|desktop|laptop/i, el: <ScanLine /> },
  { rx: /book|docs|knowledge|article/i, el: <BookOpen /> },
  { rx: /id|fingerprint|hash\b/i, el: <Fingerprint /> },
  { rx: /sent|delivered|outbound|push/i, el: <Send /> },
  { rx: /layer|stack|tier/i, el: <Layers /> },
];

export function getKpiIcon(label: string): React.ReactNode {
  for (const t of tests) if (t.rx.test(label)) return t.el;
  return <Zap />;
}

export function KpiBgIcon({ label, tone = "teal", size = 44, opacity = 0.22 }: {
  label: string;
  tone?: "teal" | "copper" | "red";
  size?: number;
  opacity?: number;
}) {
  const color =
    tone === "red"    ? "var(--crit-red)" :
    tone === "copper" ? "var(--metric-copper)" : "var(--metric-teal)";
  return (
    <div
      aria-hidden
      className="shrink-0 [&_svg]:h-full [&_svg]:w-full"
      style={{ width: size, height: size, color, opacity }}
    >
      {getKpiIcon(label)}
    </div>
  );
}
