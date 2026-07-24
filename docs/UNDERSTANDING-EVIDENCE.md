# Understanding Furix Evidence (Field & Concept Guide)

A plain-language reference for the evidence model behind every finding — for the
team, and for explaining it to a client. Companion to the engineering write-up in
[EVIDENCE-VIEWER.md](EVIDENCE-VIEWER.md).

---

## 1. What `furix-evidence://<hash>` is

Every finding in Furix points at a reference like:

```
furix-evidence://a624bf3172ee8d2c9e897d2457c0d21d970cae055427734087da191e80145d8f
```

That long string is a **SHA-256 cryptographic hash** of the exact raw bytes of
the log event that triggered the finding. It is **content-addressed storage**:
the hash is simultaneously

1. **the storage address** — the event is saved on disk as `<hash>.raw`, and
2. **the tamper seal** — a fingerprint of those exact bytes.

Content *is* the address. The same event always lands at the same address; a
different event can never collide onto it.

---

## 2. The hash, and why it can be trusted

`a624bf31…45d8f` — **64 hexadecimal characters = 256 bits** — is the output of
the SHA-256 function over the event bytes. Three properties make it useful:

| Property | Meaning | Why it matters |
|---|---|---|
| **Deterministic** | Same bytes → same hash, always, anywhere | Anyone can reproduce it |
| **Avalanche** | Change one character → a *completely* different hash | You can't quietly edit evidence |
| **One-way** | Can't reverse the hash into the content | Verify without exposing data |

Change `mwilliams72` to `mwilliams73` and the hash is not "close" — it's entirely
different. That's what makes tampering detectable.

---

## 3. What "Integrity verified ✓" actually proves

The green badge is a **live re-check**, not a stored flag. When you open the
evidence viewer, Furix:

1. reads the stored bytes back off disk (transparently decrypting if sealed),
2. re-computes SHA-256 over them,
3. compares the result to the address in the URI.

If they match → **Integrity verified** (untampered). If a single byte had changed
since ingestion, the re-hash would differ and you'd see a red **Integrity check
FAILED**. So the badge means "these exact bytes still hash to this exact address,
right now."

---

## 4. Reading the evidence viewer — field by field

Using the `CreateUser` example:

| Field | Example | What it means |
|---|---|---|
| **Original event** | the `CreateUser` JSON | The exact raw log line, byte-for-byte as ingested (pretty-printed if JSON) |
| **Source** | `cloudtrail` | The log type / source system it came from |
| **Size** | `144 bytes` | Size of the stored raw event |
| **Observed at (event)** | `—` | The event's own timestamp *from the log*. A dash means this log had no extractable event time |
| **Collected at (ingest)** | `2026-07-22T20:08:21+00:00` | When Furix ingested it. Volatile metadata — never part of the identity/hash |
| **Collector / parser** | `2.2.0 / 2.2.0` | Engine + parser versions that processed it (provenance/reproducibility) |
| **Encrypted at rest** | `No` | Whether the stored bytes are sealed with a per-tenant AES-256-GCM key. `No` unless `FURIX_EVIDENCE_MASTER_KEY` is configured |
| **Tenant / boundary** | `default / default` | Which tenant and scope owns this evidence (isolation) |
| **Schema** | `2.0` | Evidence envelope schema version |

> **Observed vs. Collected** is an audit distinction: *observed_at* is when the
> event actually happened (from the log), *collected_at* is when Furix saw it.
> The identity/hash is derived from the content, never from the volatile
> collection time — re-ingesting the same event yields the same evidence id.

---

## Retention & legal hold

Evidence isn't kept forever — and sometimes it must be kept *longer*. The viewer
shows both under **Retention & legal hold**:

- **Retained until `<date>` (HIPAA)** — the mandated minimum retention window,
  computed from the event's *collected-at* plus the governing policy. Regulatory
  floors: **HIPAA 6 years**, PCI DSS 1 year, SOX 7 years, SOC 2 1 year, ISO 27001
  3 years. Default is HIPAA 6y (apt for a health insurer); the strictest
  applicable framework wins (`FURIX_RETENTION_CLASS` / `FURIX_RETENTION_DAYS`).
- **Days remaining** counts down to that date. Past it, the badge turns red
  (**Retention expired**) — a signal it *may* be purged, never a silent deletion.
- **Legal hold** freezes an object against expiry and deletion (litigation or
  audit hold). While a hold is active the object is **never** treated as expired,
  regardless of the retention clock.

Because evidence is write-once, retention is computed fresh on every read (so a
policy change applies everywhere at once), and legal holds live in a separate
mutable registry. Placing a hold is an **auditor/admin** action; releasing one is
**admin-only** (it re-enables expiry). Both are recorded in the admin audit log.

> Client line: *"We prove we keep evidence for the legally required window — six
> years for HIPAA — and a legal hold can freeze anything indefinitely for
> litigation, with who placed it and why on the record."*

## 5. Verify it yourself (don't trust — check)

Because the address is a plain SHA-256, an auditor can reproduce it independently
with standard tools — no Furix required:

```bash
# hash the exact event bytes and compare to the address in the URI
printf '%s' '<the exact raw event bytes>' | sha256sum
# → a624bf31…45d8f   (must match the furix-evidence:// address)
```

This is **chain of custody without trusting the vendor**: the auditor confirms
the evidence is the original with a one-line command.

> Note: the hash is over the *exact* stored bytes (whitespace and ordering
> included), so reproduce it against the raw event, not a reformatted copy.

---

## 6. Where the bytes actually live

Content-addressed, write-once, on the persistent Docker volume:

```
<data>/evidence/objects/<hash>.raw     # the exact bytes (optionally encrypted)
<data>/evidence/objects/<hash>.json    # the provenance envelope
```

Write-once means re-ingesting the same event is a no-op — it never overwrites.
The backend is filesystem today and **S3-Object-Lock-ready** for true WORM
(write-once-read-many) immutability in production. The evidence viewer footer
shows the live posture — **write-once · filesystem** (dev) or **WORM · S3 Object
Lock** (production) — plus an *encrypted at rest* badge when a master key is set.

You can see your own stored evidence on the server:

```bash
cd ~/furix-compliance-dash/deploy
docker compose exec api sh -c 'find /data -path "*evidence/objects*" | head'
```

---

## 7. Access is itself audited

Opening evidence is not silent. Every retrieval writes an `evidence.access` entry
to the tenant's administrative audit log (who viewed which hash, when, and the
integrity result). Auditors require exactly this: a record of who looked at what.

---

## 8. Why this matters (regulatory grounding)

Evidence retention and integrity are legal obligations, not nice-to-haves:

- **HIPAA** — 6 years of documentation/audit records; audit controls are a
  *required* implementation spec (45 CFR §164.316(b)(2)(i), §164.312(b)).
- **PCI DSS 4.0** — 12 months of audit logs, last 3 months immediately available
  (Req 10.5.1).
- **SOC 2 / ISO 27001** — continuous, timestamped, control-mapped evidence.
- **SEC 17a-4** — WORM or a tamper-evident audit trail with independent
  verification.

Most GRC tools store a *copy* of evidence and ask you to trust the timestamp.
Furix stores it **content-addressed, write-once, and cryptographically
verifiable** — the forensic-grade posture regulators and auditors actually want.

---

## 9. Client talking points

- *"That hash is the event's tamper-proof fingerprint — it's both where the
  evidence lives and the proof it hasn't been touched."*
- *"The green badge isn't a saved flag — we re-hash the stored bytes on the spot
  and confirm they still match. Change one byte and it fails."*
- *"Your auditor can verify any piece of evidence themselves in one command,
  without trusting us."*
- *"Every finding traces to a sealed copy of the exact source event, retained
  write-once — and every time someone opens it, that's logged too."*

---

## 10. Demo script

1. Sign in as `auditor@byoc.com` (the realistic evidence consumer).
2. **Ingest** → *Generate demo logs* (or *Upload file*) → **Compliance**.
3. Expand an at-risk / gap control → **Evidence lineage** → click a
   `furix-evidence://…` chip.
4. Point at **Integrity verified ✓**, the **original event**, and the
   **provenance** — then (optional) reproduce the hash with `sha256sum` to prove
   independent verification.
