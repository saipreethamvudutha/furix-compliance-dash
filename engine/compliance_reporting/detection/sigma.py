"""
sigma.py
========
A deterministic, dependency-free matcher for the subset of the Sigma detection
format that Furix uses. A Sigma rule is portable, human-editable, and tagged
with MITRE ATT&CK technique ids — replacing the hand-maintained keyword table
with a schema-checked, community-standard artifact.

Pipeline: raw log text/dict → field environment → per-selection match →
condition evaluation → (matched?, rule).

Supported detection features:
  * logsource match on product / service / category (against Furix log_type)
  * selections: mapping of `field[|modifier...]: value(s)`, or a list of such
    mappings (OR); all keys in one mapping must match (AND)
  * modifiers: contains, startswith, endswith, re, all  (chainable, e.g.
    `field|contains|all`); base (no modifier) = case-insensitive equality
  * value lists = OR, unless `|all` makes them AND
  * special field `_raw` = the entire raw log line (for text logs)
  * condition grammar: and / or / not / parentheses / bare selection names /
    `1 of them` / `all of them` / `N of them` / `1 of prefix*` / `all of prefix*`

Determinism: no randomness, no clocks; identical (rule, log) always yields the
identical verdict. Regex is compiled per call and bounded by input size.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import sigmayaml

_VALID_LEVELS = ("informational", "low", "medium", "high", "critical")


class SigmaRuleError(ValueError):
    """A rule file is structurally invalid."""


@dataclass(frozen=True)
class SigmaRule:
    rule_id: str
    title: str
    level: str
    logsource: dict[str, str]
    detection: dict[str, Any]
    condition: str
    tags: tuple[str, ...]
    source_path: str = ""

    @property
    def technique_ids(self) -> tuple[str, ...]:
        """ATT&CK technique ids from tags, e.g. attack.t1110.001 → T1110.001."""
        out = []
        for tag in self.tags:
            t = tag.lower()
            if t.startswith("attack.t") and t[8:9].isdigit():
                out.append("T" + tag.split(".", 1)[1][1:].upper())
        return tuple(dict.fromkeys(out))  # de-dup, order-preserving

    @property
    def selection_names(self) -> tuple[str, ...]:
        return tuple(k for k in self.detection if k != "condition")


def load_rule(path: Path) -> SigmaRule:
    """Load and validate one Sigma rule file."""
    doc = sigmayaml.load(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        raise SigmaRuleError(f"{path.name}: rule is not a mapping")
    _require(doc, ("title", "id", "logsource", "detection", "level"), path)
    detection = doc["detection"]
    if not isinstance(detection, dict) or "condition" not in detection:
        raise SigmaRuleError(f"{path.name}: detection must be a mapping with a condition")
    level = str(doc["level"]).lower()
    if level not in _VALID_LEVELS:
        raise SigmaRuleError(f"{path.name}: level {level!r} not in {_VALID_LEVELS}")
    tags = tuple(doc.get("tags") or ())
    logsource = {k: str(v).lower() for k, v in (doc["logsource"] or {}).items()}
    return SigmaRule(
        rule_id=str(doc["id"]),
        title=str(doc["title"]),
        level=level,
        logsource=logsource,
        detection={k: v for k, v in detection.items() if k != "condition"},
        condition=str(detection["condition"]),
        tags=tags,
        source_path=path.name,
    )


def _require(doc: dict, keys, path) -> None:
    missing = [k for k in keys if k not in doc]
    if missing:
        raise SigmaRuleError(f"{path.name}: missing required keys {missing}")


# ── field environment ─────────────────────────────────────────────────────────
def build_env(raw_log: str, log_type: str) -> dict[str, list[str]]:
    """
    Turn a raw log into a field→values map for matching. JSON logs are
    flattened (dotted paths AND leaf names, both lowercased); every log also
    exposes `_raw` (whole text) and `_log_type`.
    """
    env: dict[str, list[str]] = {"_raw": [raw_log], "_log_type": [log_type.lower()]}
    text = raw_log.strip()
    # a log line may be a JSON object (CloudTrail, Okta, …) — flatten it
    for candidate in _json_objects(text):
        _flatten(candidate, "", env)
    return env


def _json_objects(text: str):
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                yield json.loads(line)
            except ValueError:
                continue


def _flatten(obj: Any, prefix: str, env: dict[str, list[str]]) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            _flatten(v, path, env)
    elif isinstance(obj, list):
        for item in obj:
            _flatten(item, prefix, env)
    else:
        val = _stringify(obj)
        if prefix:
            env.setdefault(prefix.lower(), []).append(val)
            leaf = prefix.split(".")[-1].lower()
            if leaf != prefix.lower():
                env.setdefault(leaf, []).append(val)


def _stringify(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


# ── selection matching ────────────────────────────────────────────────────────
def _match_selection(env: dict[str, list[str]], selection: Any) -> bool:
    if isinstance(selection, list):  # list of maps → OR
        return any(_match_selection(env, s) for s in selection)
    if not isinstance(selection, dict):
        return False
    return all(_match_fieldspec(env, spec, val) for spec, val in selection.items())


def _match_fieldspec(env: dict[str, list[str]], spec: str, value: Any) -> bool:
    name, *mods = spec.split("|")
    candidates = env.get(name.lower(), [])
    if not candidates:
        return False
    require_all = "all" in mods
    op_mods = [m for m in mods if m != "all"]
    values = value if isinstance(value, list) else [value]
    values = [_stringify(v) for v in values]

    def one(target: str) -> bool:
        return any(_apply(op_mods, cand, target) for cand in candidates)

    return all(one(v) for v in values) if require_all else any(one(v) for v in values)


def _apply(op_mods: list[str], candidate: str, target: str) -> bool:
    c, t = candidate.lower(), target.lower()
    if not op_mods:
        return c == t
    op = op_mods[0]
    if op == "contains":
        return t in c
    if op == "startswith":
        return c.startswith(t)
    if op == "endswith":
        return c.endswith(t)
    if op == "re":
        try:
            return re.search(target, candidate) is not None
        except re.error:
            return False
    return c == t  # unknown modifier → safe fallback to equality


# ── condition evaluation ──────────────────────────────────────────────────────
def evaluate(rule: SigmaRule, env: dict[str, list[str]]) -> bool:
    """Return True iff the rule's condition holds against the log environment."""
    selection_results = {
        name: _match_selection(env, sel) for name, sel in rule.detection.items()
    }
    tokens = _tokenize(rule.condition)
    parser = _ConditionParser(tokens, selection_results)
    result = parser.parse()
    if not parser.at_end():
        raise SigmaRuleError(f"{rule.source_path}: bad condition {rule.condition!r}")
    return result


_TOKEN_RE = re.compile(r"\(|\)|\b(?:and|or|not|of|them|all)\b|[A-Za-z0-9_*]+")


def _tokenize(condition: str) -> list[str]:
    return _TOKEN_RE.findall(condition.strip())


class _ConditionParser:
    """Recursive-descent evaluator for the Sigma condition grammar (booleans)."""

    def __init__(self, tokens: list[str], selections: dict[str, bool]):
        self.tokens = tokens
        self.pos = 0
        self.sel = selections

    def at_end(self) -> bool:
        return self.pos >= len(self.tokens)

    def _peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _next(self) -> str:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def parse(self) -> bool:
        return self._or()

    def _or(self) -> bool:
        val = self._and()
        while self._peek() == "or":
            self._next()
            val = self._and() or val
        return val

    def _and(self) -> bool:
        val = self._not()
        while self._peek() == "and":
            self._next()
            val = self._not() and val
        return val

    def _not(self) -> bool:
        if self._peek() == "not":
            self._next()
            return not self._not()
        return self._atom()

    def _atom(self) -> bool:
        tok = self._peek()
        if tok == "(":
            self._next()
            val = self._or()
            if self._peek() == ")":
                self._next()
            return val
        # quantifiers: "1 of them", "all of them", "N of prefix*"
        if tok == "all" or (tok and tok.isdigit()):
            return self._quantifier()
        # bare selection name
        self._next()
        return self.sel.get(tok, False)

    def _quantifier(self) -> bool:
        count_tok = self._next()  # 'all' or a number
        if self._peek() == "of":
            self._next()
        target = self._next() if not self.at_end() else "them"
        if target == "them":
            names = list(self.sel)
        elif target.endswith("*"):
            prefix = target[:-1]
            names = [n for n in self.sel if n.startswith(prefix)]
        else:
            names = [target] if target in self.sel else []
        truths = [self.sel.get(n, False) for n in names]
        if count_tok == "all":
            return all(truths) if truths else False
        need = int(count_tok)
        return sum(1 for t in truths if t) >= need


# ── ruleset ───────────────────────────────────────────────────────────────────
@dataclass
class Ruleset:
    rules: list[SigmaRule] = field(default_factory=list)

    @classmethod
    def from_dir(cls, directory: Path) -> "Ruleset":
        rules = [load_rule(p) for p in sorted(directory.glob("*.yml"))]
        rules += [load_rule(p) for p in sorted(directory.glob("*.yaml"))]
        seen: dict[str, str] = {}
        for r in rules:
            if r.rule_id in seen:
                raise SigmaRuleError(
                    f"duplicate rule id {r.rule_id} in {r.source_path} and {seen[r.rule_id]}"
                )
            seen[r.rule_id] = r.source_path
        return cls(rules=sorted(rules, key=lambda r: r.rule_id))

    def _logsource_matches(self, rule: SigmaRule, log_type: str) -> bool:
        """
        A rule applies if its logsource is compatible with the log type.

        Only `product` and `service` gate — Furix log_type names bundle those
        (e.g. 'windows_evtx', 'cloudtrail', 'okta_sso'). `category`
        (process_creation, authentication, …) is cross-cutting and NOT encoded
        in log_type, so a category-only rule applies to all logs and is gated
        by its detection content instead. Empty logsource = applies to all.
        """
        gates = [rule.logsource.get(k) for k in ("product", "service")]
        gates = [g for g in gates if g]
        if not gates:
            return True
        lt = log_type.lower()
        return any(g in lt or lt in g for g in gates)

    def match(self, raw_log: str, log_type: str) -> list[SigmaRule]:
        """Return every rule that fires on this log, ordered by rule id."""
        env = build_env(raw_log, log_type)
        fired = [
            r for r in self.rules
            if self._logsource_matches(r, log_type) and evaluate(r, env)
        ]
        return fired
