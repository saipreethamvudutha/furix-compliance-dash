"""
sigmayaml.py
============
A small, dependency-free YAML loader for the subset that Sigma detection rules
use. Furix ships no third-party packages on its critical path, so we cannot
rely on PyYAML being installed — but we still want rules authored in real,
human-editable YAML (the same files load in pySigma).

Supported subset (everything Sigma rules in this repo use):
  * block mappings         key: value   /   key:\\n  nested
  * block sequences        - item
  * inline flow sequences  [a, b, c]
  * scalars                plain, 'single', "double"   (with \\escapes in double)
  * comments               # to end of line (outside quotes)
  * booleans / ints        true/false/null → py; digit-only → int
  * blank lines

Explicitly NOT supported (and rejected or ignored): anchors/aliases, tags,
multiline block scalars (| >), flow mappings {a: b}, multi-document streams.
Rule files are kept within this subset; test_detection.py loads every rule so
any drift fails loudly.
"""

from __future__ import annotations

from typing import Any


class SigmaYAMLError(ValueError):
    """Raised on malformed YAML within the supported subset."""


def load(text: str) -> Any:
    """Parse a YAML document (the subset above) into Python objects."""
    lines = _logical_lines(text)
    if not lines:
        return None
    value, idx = _parse_block(lines, 0, lines[0][0])
    if idx != len(lines):
        raise SigmaYAMLError(f"trailing content at line {lines[idx][2]}")
    return value


# ── tokenisation ──────────────────────────────────────────────────────────────
def _logical_lines(text: str) -> list[tuple[int, str, int]]:
    """
    Return [(indent, content, lineno)] for every non-blank, non-comment line.
    Comments and trailing inline comments are stripped (quote-aware).
    """
    out: list[tuple[int, str, int]] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        stripped = _strip_comment(raw)
        if not stripped.strip():
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        if "\t" in raw[:indent]:
            raise SigmaYAMLError(f"tab indentation at line {lineno}")
        out.append((indent, stripped.strip(), lineno))
    return out


def _strip_comment(line: str) -> str:
    in_single = in_double = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            # a '#' only starts a comment at start of token (preceded by space)
            if i == 0 or line[i - 1] == " ":
                return line[:i]
    return line


# ── block parser ──────────────────────────────────────────────────────────────
def _parse_block(
    lines: list[tuple[int, str, int]], idx: int, indent: int
) -> tuple[Any, int]:
    first = lines[idx][1]
    if first.startswith("- "):
        return _parse_sequence(lines, idx, indent)
    return _parse_mapping(lines, idx, indent)


def _parse_mapping(
    lines: list[tuple[int, str, int]], idx: int, indent: int
) -> tuple[dict[str, Any], int]:
    result: dict[str, Any] = {}
    while idx < len(lines):
        cur_indent, content, lineno = lines[idx]
        if cur_indent < indent:
            break
        if cur_indent > indent:
            raise SigmaYAMLError(f"unexpected indent at line {lineno}")
        if ":" not in content:
            raise SigmaYAMLError(f"expected 'key: value' at line {lineno}: {content!r}")
        key, _, inline = content.partition(":")
        key = key.strip()
        inline = inline.strip()
        if inline:
            result[key] = _parse_scalar_or_flow(inline, lineno)
            idx += 1
        else:
            # nested block belongs to deeper-indented following lines
            if idx + 1 < len(lines) and lines[idx + 1][0] > indent:
                child_indent = lines[idx + 1][0]
                value, idx = _parse_block(lines, idx + 1, child_indent)
                result[key] = value
            else:
                result[key] = None
                idx += 1
    return result, idx


def _parse_sequence(
    lines: list[tuple[int, str, int]], idx: int, indent: int
) -> tuple[list[Any], int]:
    result: list[Any] = []
    while idx < len(lines):
        cur_indent, content, lineno = lines[idx]
        if cur_indent < indent or not content.startswith("- "):
            if cur_indent < indent:
                break
            if not content.startswith("-"):
                break
        if cur_indent > indent:
            raise SigmaYAMLError(f"unexpected indent at line {lineno}")
        item = content[2:].strip()
        if ":" in item and not (item.startswith("'") or item.startswith('"') or item.startswith("[")):
            # a mapping item that begins on the dash line: reparse as a one-line
            # + possibly nested mapping by synthesising an adjusted view
            key, _, inline = item.partition(":")
            entry: dict[str, Any] = {}
            if inline.strip():
                entry[key.strip()] = _parse_scalar_or_flow(inline.strip(), lineno)
                idx += 1
            else:
                if idx + 1 < len(lines) and lines[idx + 1][0] > indent:
                    child_indent = lines[idx + 1][0]
                    value, idx = _parse_block(lines, idx + 1, child_indent)
                    entry[key.strip()] = value
                else:
                    entry[key.strip()] = None
                    idx += 1
            # absorb further keys at the item's inner indent
            inner_indent = indent + 2
            while idx < len(lines) and lines[idx][0] == inner_indent and ":" in lines[idx][1] \
                    and not lines[idx][1].startswith("- "):
                k2, _, v2 = lines[idx][1].partition(":")
                if v2.strip():
                    entry[k2.strip()] = _parse_scalar_or_flow(v2.strip(), lines[idx][2])
                    idx += 1
                else:
                    if idx + 1 < len(lines) and lines[idx + 1][0] > inner_indent:
                        ci = lines[idx + 1][0]
                        val, idx = _parse_block(lines, idx + 1, ci)
                        entry[k2.strip()] = val
                    else:
                        entry[k2.strip()] = None
                        idx += 1
            result.append(entry)
        else:
            result.append(_parse_scalar_or_flow(item, lineno))
            idx += 1
    return result, idx


# ── scalars & flow ────────────────────────────────────────────────────────────
def _parse_scalar_or_flow(token: str, lineno: int) -> Any:
    if token.startswith("[") and token.endswith("]"):
        inner = token[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(p.strip(), lineno) for p in _split_flow(inner)]
    return _parse_scalar(token, lineno)


def _split_flow(inner: str) -> list[str]:
    parts, buf, in_s, in_d = [], [], False, False
    for ch in inner:
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        if ch == "," and not in_s and not in_d:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    return parts


def _parse_scalar(token: str, lineno: int) -> Any:
    if not token:
        return ""
    if token[0] == '"' and token[-1] == '"' and len(token) >= 2:
        return _unescape_double(token[1:-1])
    if token[0] == "'" and token[-1] == "'" and len(token) >= 2:
        return token[1:-1].replace("''", "'")
    low = token.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if low in ("null", "~"):
        return None
    if token.lstrip("-").isdigit():
        return int(token)
    return token


def _unescape_double(s: str) -> str:
    out, i = [], 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            out.append({"n": "\n", "t": "\t", '"': '"', "\\": "\\"}.get(nxt, nxt))
            i += 2
        else:
            out.append(s[i])
            i += 1
    return "".join(out)
