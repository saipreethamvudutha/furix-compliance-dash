import type { DataSensitivity } from "./permissions";

/* Rank: higher number = more sensitive. User's scope must be ≥ data's rank. */
export const SENSITIVITY_RANK: Record<DataSensitivity, number> = {
  public: 0,
  internal: 1,
  confidential: 2,
  restricted: 3,
};

export type SensitivityMeta = {
  label: string;
  short: string;
  color: string;     // text + accent
  bg: string;        // chip background
  border: string;    // chip border
  dot: string;       // small dot color
};

/* Tone palette aligned with the existing skeuo design tokens. */
export const SENSITIVITY_META: Record<DataSensitivity, SensitivityMeta> = {
  public: {
    label: "Public",
    short: "PUB",
    color: "var(--metric-teal)",
    bg: "rgba(111,214,196,0.14)",
    border: "rgba(111,214,196,0.40)",
    dot: "#6fd6c4",
  },
  internal: {
    label: "Internal",
    short: "INT",
    color: "#7fb8d6",
    bg: "rgba(127,184,214,0.14)",
    border: "rgba(127,184,214,0.40)",
    dot: "#7fb8d6",
  },
  confidential: {
    label: "Confidential",
    short: "CONF",
    color: "var(--metric-copper)",
    bg: "rgba(224,160,99,0.16)",
    border: "rgba(224,160,99,0.42)",
    dot: "#e0a063",
  },
  restricted: {
    label: "Restricted",
    short: "RSTR",
    color: "var(--crit-red)",
    bg: "rgba(212,106,94,0.18)",
    border: "rgba(212,106,94,0.45)",
    dot: "#d46a5e",
  },
};

/* Highest sensitivity the role's scope allows. */
export function maxAllowedSensitivity(
  allowed: DataSensitivity[]
): DataSensitivity {
  return (allowed.slice().sort(
    (a, b) => SENSITIVITY_RANK[b] - SENSITIVITY_RANK[a]
  )[0] ?? "public") as DataSensitivity;
}

/* Can the user see a value tagged at this sensitivity? */
export function canSeeSensitivity(
  allowed: DataSensitivity[],
  required: DataSensitivity
): boolean {
  return allowed.includes(required);
}
