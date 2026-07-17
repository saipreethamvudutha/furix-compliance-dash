# Furix Deterministic Compliance Pipeline — Architecture Reference

## 1. What this pipeline is

Furix is a **deterministic-first security-log compliance pipeline**. It ingests a raw security log (syslog, Windows EVTX, CloudTrail, Azure AD, Okta, EDR alerts, firewall logs, etc.), extracts findings from it using regex-based entity extraction and a weighted keyword rule engine (not an LLM on the critical path), maps those findings to **CIS Controls v8.1**, evaluates them against **15 deterministic compliance policy rules**, cross-walks the results to **NIST CSF 2.0** and **HIPAA Security Rule** citations using an ingested **SCF (Secure Controls Framework) 2026.1** crosswalk, retrieves supporting evidence chunks from a **pgvector** similarity store enriched by an **Apache AGE** knowledge graph, and finally serialises everything into **OSCAL** (Open Security Controls Assessment Language) Assessment Results JSON.

The design goal is **zero LLM latency for all known log formats** — a local LLM (Gemma, via an OpenAI-compatible NIM/Ollama endpoint) exists in the codebase only as a fallback for unrecognised/unstructured log formats, and even then its output is never trusted for compliance mapping (the keyword engine always overrides it). Everything that determines severity, CIS control mapping, and policy violations is deterministic and reproducible.

Three PostgreSQL databases back the system:
- **`furix_compliance`** — pgvector table `compliance_chunks` (embedded CIS/NIST/HIPAA text chunks) + Apache AGE graph `compliance_graph` (Control/Safeguard/NISTCategory nodes and their relationships)
- **`furix_det`** — the SCF 2026.1 crosswalk tables (`scf_controls`, `cis_to_nist`, `hipaa_to_nist`) that are the single source of truth for CIS→NIST→HIPAA mapping

---

## 2. Environment & package installs

The pipeline runs on the remote Linux box (paths in `config.py` are already Linux paths, e.g. `/home/yashwanth/Furix_compliance/Compliance/...`). There is no `requirements.txt` in the repo — the third-party packages actually imported across the codebase are:

| Package | Used for | Imported in |
|---|---|---|
| `psycopg2-binary` (or `psycopg2`) | PostgreSQL driver | `db_connections.py`, `phase1_scf_ingest.py`, `setup_ingestion.py` |
| `pgvector` | Registers the `vector` type + `<=>` cosine-distance operator on psycopg2 connections | `db_connections.py` (`from pgvector.psycopg2 import register_vector`) |
| `openai` | OpenAI-compatible client used to call the local Gemma/Ollama endpoint | `db_connections.py` (`nim_client = OpenAI(...)`) |
| `sentence-transformers` | Loads the SecureBERT bi-encoder (embeddings) and cross-encoder (reranker) | `models.py` |
| `pdfplumber` | Extracts text from the CIS Controls v8.1 PDF and NIST CSF 2.0 PDF during ingestion | `setup_ingestion.py` |
| `openpyxl` | Reads the SCF 2026.1 Excel workbook during crosswalk ingestion | `phase1_scf_ingest.py` |

Standard-library only otherwise: `re`, `json`, `os`, `sys`, `time`, `threading`, `datetime`, `collections`, `concurrent.futures`, `dataclasses`, `typing`, `uuid`, `warnings`.

A minimal install on the remote box:

```bash
pip install psycopg2-binary pgvector openai sentence-transformers pdfplumber openpyxl
```

`sentence-transformers` pulls in `torch` and `transformers` as transitive dependencies — expect that install to be the heaviest one. PostgreSQL itself must have the **pgvector** extension and **Apache AGE** extension installed and loadable (`CREATE EXTENSION vector;` and `LOAD 'age';`).

### Required source data files (paths from `config.py`)

| Variable | Path | Purpose |
|---|---|---|
| `PDF_PATH` | `Source_data/CIS_Controls_Guide_v8.1.2_0325_v2 (1).pdf` | CIS Controls v8.1 text, chunked into `compliance_chunks` |
| `NIST_DATA_PATH` | `Source_data/NIST.CSWP.29.pdf` | NIST CSF 2.0 text, chunked into `compliance_chunks` |
| `HIPAA_JSON_PATH` | `Source_data/hipaa_security_rule.json` | Structured HIPAA Security Rule data (loaded by `hipaa_data.py` and chunked by `setup_ingestion.py`) |
| SCF Excel workbook | referenced inside `phase1_scf_ingest.py` (sheet `"SCF 2026.1"`) | Source of the CIS↔NIST↔HIPAA crosswalk |
| `OUTPUT_DIR` | `Output/` | Pipeline run logs, DLQ JSON files, OSCAL output JSON |

### One-time setup order (before the pipeline can run)

1. `phase1_scf_ingest.py` — creates `furix_det`, parses the SCF 2026.1 Excel workbook, builds `scf_controls`, then derives `cis_to_nist` and `hipaa_to_nist`.
2. `setup_ingestion.py` — creates `furix_compliance`'s pgvector table `compliance_chunks` and the Apache AGE graph `compliance_graph`; ingests the CIS PDF, NIST PDF, and HIPAA JSON as embedded chunks; builds AGE nodes/edges (including `MAPS_TO` edges sourced from `CIS_TO_NIST_MAPPINGS`/`HIPAA_TO_NIST_MAPPINGS`, which are only populated after step 1 has run).
3. `db_connections.py` — on **any** subsequent import, loads `CIS_TO_NIST_MAPPINGS` / `HIPAA_TO_NIST_MAPPINGS` into memory from `furix_det` (fails soft with a warning if `furix_det` isn't populated yet).
4. `models.py` — on import, loads the SecureBERT bi-encoder (`cisco-ai/SecureBERT2.0-biencoder`) and cross-encoder (`cisco-ai/SecureBERT2.0-cross_encoder`) once, CPU-only.
5. `pipeline.py` — the orchestrator; importing it triggers `analyze_log_with_llm`, `evaluate_policy`, `retrieve_cis_controls_llm` to become available, and (as currently written) **also runs a full batch of sample logs at import time** — see §7 caveat.

---

## 3. File map

| File | Role |
|---|---|
| `config.py` | Single source of configuration: DB credentials, model names, RAG tuning constants, severity tables, the Gemma `SYSTEM_PROMPT`. All other files import from here; nothing writes back. |
| `db_connections.py` | All DB connection helpers (`get_pg_connection`, `get_age_connection`, `get_age_read_connection`, `get_det_connection`), the Gemma/NIM client (`nim_client`), and the SCF crosswalk loader (`CIS_TO_NIST_MAPPINGS`, `HIPAA_TO_NIST_MAPPINGS`). |
| `models.py` | Loads `embedder` (SecureBERT bi-encoder) and `reranker` (SecureBERT cross-encoder) exactly once. |
| `hipaa_data.py` | Parses the HIPAA JSON into `HIPAA_SPEC_REGISTRY`, `CSF_TO_HIPAA_SPECS`, `MITRE_TACTIC_TO_CSF`, `BEHAVIOR_TO_HIPAA_SPEC`. |
| `detection_engine.py` | Stage A ("Findings Engine"): threat density gate, deterministic entity extraction, keyword-driven CIS control mapping, severity correction, benign suppression, per-control query builder. |
| `policy_engine.py` | Phase 3: 15 signal-based compliance policy rules (`POL-001`…`POL-015`), each producing a `PolicyFinding` with CIS/NIST/HIPAA citations. |
| `retrieval_engine.py` | Stage B ("Crosswalk and Retrieval Engine"): pgvector similarity search, Apache AGE graph expansion, HIPAA signal mapping, cross-encoder reranking with guaranteed per-framework slots. |
| `phase1_scf_ingest.py` | One-time script: builds `furix_det` (SCF 2026.1 raw + derived CIS↔NIST / HIPAA↔NIST crosswalk tables). |
| `setup_ingestion.py` | One-time script: builds `compliance_chunks` (pgvector) and `compliance_graph` (Apache AGE) from the CIS PDF, NIST PDF, and HIPAA JSON. |
| `oscal_serialiser.py` | Phase 4: serialises a completed pipeline run into OSCAL Assessment Results JSON. |
| `oscal_plan_builder.py` | Builds the companion OSCAL Assessment Plan artifact. |
| `pipeline.py` | Orchestrator (`run_full_pipeline`), the Dead Letter Queue, and the batch-run driver (`complete_log_pipeline_run`, `run_dlq_and_malformed`). |

---

## 4. End-to-end: how one log moves through the pipeline

Entry point: `run_full_pipeline(raw_log: str, log_type: str = "auto") -> dict` in `pipeline.py`.

### Step 0 — Input validation
- `None`, non-string (best-effort `str()` coercion), empty/whitespace-only, or logs over 500,000 characters (truncated) are all handled before any processing. A failure here returns immediately with `_failure_stage = "input_validation"`.

### Phase 0 — Threat density gate (`detection_engine.compute_threat_density`)
- Scans the raw log against two compiled regex pattern lists:
  - `THREAT_SIGNAL_PATTERNS` (~30 patterns: CVE strings, `mimikatz`, `cobaltstr`, `beacon.exe`, failed-password-for-invalid-user, EventID 4625/4720/4732/7045, `DeleteBucket`, `GetSecretValue`, SQL injection, PowerShell `-enc`, etc.)
  - `BENIGN_SIGNAL_PATTERNS` (~15 patterns: `accepted publickey`, health-check GETs, `kube-probe`, `Prometheus/`, internal `ufw allow`, etc.)
- Counts `threat_hits` / `benign_hits`, normalises by line count into `threat_score` / `benign_score`, computes `net_score = threat_score - benign_score`.
- Special-cases EventID 4698 (scheduled task creation): benign if the task name matches Windows Update patterns and no malicious command indicators are present, otherwise counted as a threat hit (`is_benign_scheduled_task`).
- `is_structured_risk = log_type in STRUCTURED_RISK_LOG_TYPES` (`zeek`, `cisco_asa`, `dhcp`, `vpn`, `paloalto`, `suricata`) — these formats carry risk without matching text patterns, so they are exempted from being auto-classified benign.
- `is_benign` is True only if **not** structured-risk AND (`threat_hits == 0 and benign_hits > 0`) OR (`net_score < -0.3 and threat_hits <= 1`).
- On exception, falls back to safe all-zero defaults rather than aborting the pipeline.

### Phase 1 — Deterministic analysis (`detection_engine.analyze_log_with_llm`)
Runs with `enrich_with_llm=False` for all 25 known log types (the LLM path only activates when `log_type` is `"auto"`/`"generic"`/`"unknown"`).

1. Builds a **findings skeleton** with `severity="low"` and empty entity lists.
2. **Regex entity extraction** directly against the raw log:
   - Source IPs via a keyed pattern (`src=`, `source=`, `ipAddress=`, `RemoteAddressIP4`, `callerIp`, etc.), with a bare-IP fallback capped at 5 matches if the keyed pattern finds nothing.
   - CVE IDs via `CVE-\d{4}-\d{4,}` (defaults to `["NAN"]` if none).
   - Usernames via a keyed pattern (`user=`, `username=`, `UserId=`, `srcuser=`, etc.), filtered to drop `null/none/unknown/nan/true/false/root/system`.
   - Boolean flags set by targeted regex: `failed_logins`, `successful_logins`, `privilege_escalation_detected` (incl. Okta "Super Administrator" grants), `account_creation_detected` (incl. Okta backdoor-account provisioning), `lateral_movement_detected`.
   - `primary_finding` = first log line containing a high-signal keyword (`cve-`, `mimikatz`, `cobalt`, `beacon`, `payload`, `backdoor`, `exploit`, `malware`, `injection`, `escalat`, `brute`, `failed password`), else a generic "`{log_type} security event detected.`"
3. **Gemma enrichment (non-critical path only, `enrich_with_llm=True`)**: calls `_call_gemma_for_extraction()` — an OpenAI-compatible chat completion against the local Gemma model, 3 retries with rising temperature, response parsed by a 4-strategy JSON recovery pipeline (`_parse_llm_json`: direct parse → outer-brace extraction → truncation repair → last-resort field-by-field regex extraction). Gemma output only **fills empty fields** in the deterministic skeleton (never overwrites populated ones), and **its CIS control mapping is discarded outright** — Phase 1d is always authoritative.
4. `_sanitize_findings()` guarantees every expected key exists, coerces severity to one of the 5 valid values, reclassifies any MITRE tactic-names that leaked into `attack_techniques` back into `mitre_attack_tactics` (and vice versa for real `T####.###` technique IDs), strips `"unknown"` placeholder values, and validates CVE ID format.
5. `investigation_query` is built by `_build_fallback_query()` — concatenates primary finding, source IPs, ports, protocols, MITRE tactics/techniques, security domains, and mapped CIS controls into one descriptive sentence-set (used later to drive RAG retrieval).

### Phase 1d — CIS control validator/corrector (`detection_engine.validate_and_correct_cis_mapping`)
This is the **authoritative** CIS control mapping step — deterministic, always overrides whatever came before.

1. `run_keyword_detector(raw_log)`: scans the raw log against `KEYWORD_CONTROL_MAP` — roughly 200 keyword→control(s) mappings, each with a confidence weight (e.g. `"mimikatz"` → Control 2 weight 2, Control 10 weight 2; `"nmap scan report for"` → Control 1 weight 2, Control 7 weight 2). Weights are summed per control across all matching keywords; a control is only kept if its total weight ≥ `KEYWORD_MIN_WEIGHT` (2).
2. `validate_cis_mapping()`: checks whether the LLM-suggested `security_domains` are consistent with the LLM-suggested `control_ids` via `DOMAIN_CONTROL_MAP` (e.g. "Access Control" domain implies Control 6).
3. If **inconsistent** → the final control set is the union of the LLM's controls and the keyword-detected controls (deterministic set wins on conflict).
4. If **consistent** → a finer-grained merge: keywords are split into high-confidence (weight ≥ 3) and low-confidence (2 ≤ weight < 3) buckets; high-confidence keyword controls not already in the LLM set are always added; low-confidence keyword controls are only added if they're also expected by the LLM's declared security domains.
5. **Log-type-specific suppression** (`LOG_TYPE_SUPPRESSED_CONTROLS`): removes known false-positive controls per log type, e.g. `wazuh_siem` suppresses Controls 5/7/9, `syslog` suppresses Controls 12/7 (a curl-based C2 callback isn't infra management), `vpn` suppresses Control 5, `gcp_audit` suppresses Control 6.
6. Result is written back into `findings["cis_controls_mapping"]["control_ids"]`.

### Phase 1e — Severity corrections (three sub-stages, all in `pipeline.py`)

1. **`post_llm_severity_correction(findings, raw_log, log_type)`** — content-aware correction against three compiled regex sets (`_FAILED_ATTEMPT`, `_SUCCESS_CONFIRM`, `_CONFIRMED_EXPLOIT`):
   - Rule 1: severity is `critical` but the log shows only failed attempts and no confirmed post-exploitation indicator → downgrade to `high`.
   - Rule 2: a confirmed exploit/C2 indicator is present (Mimikatz, Cobalt Strike, ransomware, PowerShell `-enc`, `AdministratorAccess` attach, Okta Super Admin grant, etc.) but severity is rated `low`/`medium`/`informational` → raise to `high` (floor).
2. **Density-based severity gate** (inline in `pipeline.py`):
   - If `density["is_benign"]` and current severity is `medium`/`high`/`critical`, it is corrected down to `get_benign_severity(density, log_type)` — which itself caps at `BENIGN_SEVERITY_CEILING[log_type]` (e.g. `benign_network`→`informational`, `benign_auth`→`low`).
   - Else if `density["is_structured_risk"]`, `SEVERITY_FLOOR[log_type]` (e.g. `cisco_asa`→`medium`, `nmap`→`medium`, `zeek`/`dhcp`/`vpn`→`low`) is applied as a floor — severity can only be raised to meet it, never lowered.
3. **`apply_benign_suppression(findings, log_type, density)`** — removes known-false-positive CIS controls per benign log type via `BENIGN_SUPPRESSED_CONTROLS` (e.g. `benign_cloudtrail` strips Controls 12/13/5/6, keeping only the genuinely correct Controls 3/15). If suppression empties `control_ids` entirely, a minimal seed control is injected (`BENIGN_EMPTY_SEED`) so Phase 2 retrieval always has something to scope against.

### Phase 3 — Policy evaluation (`policy_engine.evaluate_policy`)
Runs **after** findings and severity are final, and does **not** mutate them. Evaluates 15 signal-based rules in a fixed priority order (composite/highest-severity rules first) and returns `(policy_findings, policy_summary)`.

**Rule catalogue** (`_RULES`, evaluated in this order):

| Rule | Title | Fires when | CIS Control | Severity |
|---|---|---|---|---|
| POL-009 | Privilege Escalation from External Source | `privilege_escalation_detected` AND external (non-RFC1918) source IP present | 6 + 12 | critical |
| POL-015 | Cloud Privileged Role Assignment | Control 6 AND Control 15 both mapped AND severity ≥ high | 6 + 15 | high |
| POL-003 | Brute Force with Successful Authentication | `failed_logins` AND `successful_logins` both true | 6 | critical |
| POL-007 | Multi-Stage Attack | Control 17 mapped AND severity ≥ high | 17 | critical |
| POL-006 | Malware or C2 Activity Confirmed | Control 10 mapped AND severity ≥ high | 10 | critical |
| POL-001 | Unauthorised Account Creation | `account_creation_detected` | 5 | high |
| POL-002 | Privilege Escalation Detected | `privilege_escalation_detected` | 6 | high |
| POL-005 | Known CVE Exploitation | at least one real CVE ID present | 7 | high |
| POL-011 | CVE + Unpatched Vulnerability Management Gap | Control 7 mapped AND CVE present | 7 | high |
| POL-008 | External Source IP on High-Severity Event | external source IP AND severity ≥ high | 12 | high |
| POL-010 | Data Exfiltration / Sensitive Data Access | Control 3 mapped AND severity ≥ medium | 3 | high |
| POL-014 | Lateral Movement Detected | `lateral_movement_detected` | 13 | high |
| POL-004 | Failed Authentication — Standalone | `failed_logins` AND NOT `successful_logins` | 6 | medium |
| POL-012 | Secure Configuration Failure | Control 4 mapped AND severity ≥ medium | 4 | medium |
| POL-013 | Audit Log Integrity Event | Control 8 mapped AND severity ≥ medium | 8 | medium |

Each rule that fires returns a `PolicyFinding`:

```
rule_id, title, description, verdict ("FAIL" — only value ever produced),
cis_control, nist_csf_ids, hipaa_cfr, severity,
triggered_field, triggered_value, scf_version, timestamp, finding_uuid
```

- `nist_csf_ids` is resolved from the in-memory `CIS_TO_NIST_MAPPINGS` dict (`_nist_ids_for()`), no DB call at evaluation time.
- `hipaa_cfr` is resolved from a small hand-typed `_CIS_TO_HIPAA` dict inside `policy_engine.py` (e.g. Control 5 → `164.308`, Control 3/4/8/12 → `164.312`).
- Only `FAIL` verdicts are produced — there is no PASS sweep; silence means the rule didn't fire, not that the control passed.
- `is_benign=True` (passed in from Phase 0's density gate) suppresses several rules outright to avoid false positives on confirmed-benign logs.
- `policy_summary` records `rules_evaluated` (15), `violations_found`, `rules_fired`, `controls_violated`, `controls_rule_only` (fired for a control that wasn't in the mapped set), `controls_evaluated_clean` (mapped but no rule fired), `log_severity`, `scf_version` ("2026.1").

### Phase 2 — RAG evidence retrieval (`retrieval_engine.retrieve_cis_controls_llm`)
Called last (despite the "Phase 2" numbering, it runs after Phase 3 in the actual pipeline order) with `embedder`, `reranker`, the finalised `findings`, `investigation_query`, `log_type`, and `density`. Five internal stages:

**Stage 2a — Per-control scoped retrieval**
- `build_per_control_queries_from_llm(findings)` turns each mapped CIS control into a fixed descriptive sentence from `_CONTROL_SENTENCES` (e.g. Control 6 → "Enforce least-privilege access controls; require MFA...").
- All per-control queries are embedded in **one batched encoder call**.
- For each control, a scoped pgvector query:
  ```sql
  SELECT id, document, control_id, safeguard_id, type
  FROM compliance_chunks
  WHERE framework_id = 'cis_v8'
    AND type IN ('safeguard', 'control_overview')
    AND control_id = %s
  ORDER BY embedding <=> %s::vector
  LIMIT 4;   -- TOP_K_PER_CTRL
  ```
- Results are deduplicated by chunk ID as they're collected.

**Stage 2b — Unscoped CIS + NIST + HIPAA sweeps**
- The shared `investigation_query` is embedded once, then an unscoped CIS sweep runs immediately (`LIMIT 35` — `TOP_K`).
- NIST candidate IDs are resolved from `CIS_TO_NIST_MAPPINGS` for every mapped control (this is the SCF-2026.1-derived crosswalk).
- HIPAA CFR sections are resolved via `map_log_to_hipaa_specs(findings)` — a **5-signal mapper**:
  1. CIS controls → `CIS_TO_NIST_MAPPINGS` → NIST subcategory → `CSF_TO_HIPAA_SPECS` → spec codes
  2. MITRE tactics → `MITRE_TACTIC_TO_CSF` → `CSF_TO_HIPAA_SPECS` → spec codes
  3. `user_activity` booleans → `BEHAVIOR_TO_HIPAA_SPEC` (direct lookup)
  4. Fallback: extract `§164.XXX` anchors directly out of `investigation_query` text
  5. Safety net: if all else produces nothing, seed with `{164.308, 164.312}`
  - Spec codes are resolved to parent CFR sections via `HIPAA_SPEC_REGISTRY`.
- Investigation query, NIST query (same text), and a purpose-built `hipaa_query` (constructed from attack-signal vocabulary + fired HIPAA spec names, to anchor the embedding toward the right spec space rather than generic response/recovery language) are embedded together in **one batched call**.
- The three framework queries then run **in parallel** via `ThreadPoolExecutor(max_workers=3)`:
  ```sql
  -- CIS (unscoped)
  SELECT id, document, control_id, safeguard_id, type FROM compliance_chunks
  WHERE framework_id='cis_v8' AND type IN ('safeguard','control_overview')
  ORDER BY embedding <=> %s::vector LIMIT 35;

  -- NIST (scoped to SCF-derived IDs)
  SELECT id, document, control_id, safeguard_id, type FROM compliance_chunks
  WHERE framework_id='nist_csf'
    AND (node_id IN (...) OR safeguard_id IN (...) OR control_id IN (...))
  ORDER BY embedding <=> %s::vector LIMIT 35;

  -- HIPAA (scoped to CFR sections, or unscoped if no section resolved)
  SELECT id, document, control_id, safeguard_id, type FROM compliance_chunks
  WHERE framework_id='hipaa_security_rule' AND control_id IN (...)
  ORDER BY embedding <=> %s::vector LIMIT 35;
  ```
- Results merge into the same candidate pool, deduplicated by chunk ID.

**Stage 2c — Quality filter + safeguard-level dedup**
- `_is_quality_chunk(doc, meta)`: for CIS chunks, verifies the safeguard ID literally appears in the first 400 characters ("`Safeguard 6.2: ...`"); for HIPAA chunks, verifies a HIPAA category header is present; for NIST chunks, verifies the subcategory ID appears in the header. All chunk types additionally require at least one of `ACTION_WORDS` (safeguard, control, implement, detect, protect, etc.) to appear in the first ~600 characters.
- Deduplicates by `safeguard_id` (first occurrence wins), falling back to a `control_id::type` combo key when no safeguard ID is present.
- **Zero-result recovery**: if quality filtering + dedup empties the candidate pool entirely, a broad unfiltered fallback sweep runs (`LIMIT 2×TOP_K_RERANK`, no framework/type filter) so Stage 3 is never handed zero candidates.

**Stage 2c.5 — Pre-rerank cap**
- Cross-encoder cost scales linearly with candidate count, so the pool is capped at `TOP_K_RERANK + 10` (30) before reranking — but **framework-aware**: a guaranteed floor per framework (CIS ≥7, NIST ≥5, HIPAA ≥5) is filled first, then the cap backfills with whatever's left, so no framework gets crowded out purely by candidate volume.

**Stage 2d — Graph expansion (Apache AGE)**
- `graph_expand_controls(control_ids)` runs exactly **two** Cypher queries total (not one per control) against `compliance_graph`, and caches the result by the sorted tuple of control IDs so repeated calls with the same controls never hit the DB twice:
  ```sql
  -- NIST mappings for all controls in one call
  SELECT * FROM ag_catalog.cypher('compliance_graph', $$
      MATCH (c:Control)-[:MAPS_TO]->(n:NISTCategory)
      WHERE c.id IN [ 'Control 5', 'Control 6', ... ]
      RETURN c.id, n.id, n.function_id
  $$) AS (ctrl_id agtype, nist_id agtype, function_id agtype);

  -- Related-control edges for all controls in one call
  SELECT * FROM ag_catalog.cypher('compliance_graph', $$
      MATCH (a:Control)-[:RELATED_TO]->(b:Control)
      WHERE a.id IN [ 'Control 5', 'Control 6', ... ]
      RETURN a.id, b.id
  $$) AS (src_id agtype, dst_id agtype);
  ```
- The expansion result attaches `nist_mappings` and `related_controls` metadata onto each result later, via `enrich_results_with_graph()`.

**Stage 3 — Rerank with guaranteed per-framework slots**
- Every candidate is scored against **two** query variants — its own per-control/HIPAA/NIST query and the global `investigation_query` — in one batched `reranker.predict()` call; the final score is `max(control_score, global_score)`.
- Results are split into CIS/NIST/HIPAA pools.
- **CIS coverage guarantee**: one result per mapped control is boosted to a score floor (`COVERAGE_SCORE_FLOOR = 0.50`) and always kept; remaining CIS candidates are kept only if they belong to a mapped control or score ≥ `CROSS_CONTROL_THRESHOLD` (0.75).
- **NIST guaranteed slots**: up to `NIST_GUARANTEED` (5) unique safeguard IDs, first pass score-gated at `NIST_SCORE_FLOOR = 0.40`, second pass fills any shortfall without the floor to guarantee the minimum count.
- **HIPAA guaranteed slots**: same two-pass logic, `HIPAA_GUARANTEED` (5), `HIPAA_SCORE_FLOOR = 0.68`.
- **CIS guaranteed slots**: up to `CIS_GUARANTEED` (7) unique controls, then backfilled up to the remaining `TOP_K_RERANK` budget.
- All guaranteed results are merged and sorted by score, remaining budget filled from the leftover pool, capped at `TOP_K_RERANK` (20) total.
- Final results are graph-enriched (`enrich_results_with_graph`) and printed with rank, control/safeguard label, rerank score, chunk type, coverage tag, a 600-character content preview, NIST CSF mappings, and related CIS controls.

`retrieve_cis_controls_llm()` returns the final ranked `[(score, doc, meta), ...]` list — this becomes `rag_results` in the pipeline's return dict.

### Pipeline return value

```python
{
  "findings":             {...},   # final findings dict after all corrections
  "investigation_query":  "...",
  "raw_log_reference":    {...},
  "rag_results":          [(score, doc, meta), ...],
  "policy_findings":      [PolicyFinding.to_dict(), ...],
  "policy_summary":       {...},
  "_query_fallback_used": bool,
  "_density":             {...},   # Phase 0 output
  "_failure_stage":       None | "input_validation" | "det_analysis" | "rag_retrieval",
  "_log_type":            "...",
  "_phase_timings":       {"phase_0_threat_density": 0.01, "phase_1_det_analysis": 0.02, ...},
  "_total_elapsed_sec":   0.15,
}
```

Any exception in Phase 1 (deterministic analysis) or Phase 2 (RAG retrieval) short-circuits the return with `_failure_stage` set; Phases 1d, 1e, and 3 catch their own exceptions internally and degrade gracefully (log a warning, keep going with whatever findings exist so far) rather than aborting the run.

### Dead Letter Queue (`pipeline.py`)
- `DeadLetterQueue` is a thread-safe, disk-persisted (JSON under `Output/dlq/`) three-stage queue: `attempt_1_queue` → `attempt_2_queue` → `manual_review`.
- `dlq.submit()` is called whenever `run_full_pipeline()` returns a failure (`_failure_stage` set, or `findings` empty).
- `dlq.retry_all()` re-runs every queued entry through `run_full_pipeline()` again; successes are recovered, repeat failures move to `attempt_2_queue` **and** `manual_review` simultaneously.
- All three queues are written to disk atomically (`os.replace`) on every mutation, so a crash between runs loses nothing.

### Phase 4 — OSCAL serialisation (batch runs only)
- Not part of `run_full_pipeline()` itself — invoked by `complete_log_pipeline_run()` after all sample logs finish, via `oscal_serialiser.write_oscal_file()`.
- Produces one OSCAL **Assessment Results** JSON document per batch run: metadata (tool name/version, `scf-version: "2026.1"`), one `results[]` entry containing an `observation` + a `finding` per `PolicyFinding`, each finding's `target.status.state = "not-satisfied"` (since only FAIL verdicts exist), tagged with `rule-id`, `cis-control`, `severity`, `nist-csf-id`, `hipaa-cfr` props.
- `oscal_plan_builder.py` separately builds the companion OSCAL **Assessment Plan** artifact that the Assessment Results document references via `import-ap`.

---

## 5. Batch-run driver (what actually executes when `pipeline.py` runs)

`pipeline.py` defines `SAMPLE_LOGS` — a dict of ~15+ realistic sample logs (Nmap, syslog, Windows EVTX, CloudTrail, O365, Azure AD, Wazuh SIEM, GCP audit, Microsoft Defender, Okta SSO, etc.) plus malformed/robustness fixtures, and then, at **module import time** (not inside `if __name__ == "__main__"`):

1. Runs one quick smoke test (`run_full_pipeline(SAMPLE_LOGS["syslog"], ...)`).
2. `complete_log_pipeline_run()` — runs every entry in `SAMPLE_LOGS` through `run_full_pipeline()`, tees all stdout to a timestamped `Output/<timestamp>pipeline_result.txt`, routes failures to the DLQ, prints a per-log timing table (fastest/slowest/average), then writes the OSCAL Assessment Results file for the whole batch.
3. `run_dlq_and_malformed()` — runs `dlq.retry_all()` over anything that failed in step 2, writes recoveries to `Output/<timestamp>dlq_result.txt`, and tracks anything that fails twice in `logs_failed_in_DLQ` for manual cybersecurity review.

---

## 6. Timing instrumentation

`pipeline.py` records per-phase wall-clock time in `_phase_timings` for every single-log run: `phase_0_threat_density`, `phase_1_det_analysis`, `phase_1d_cis_mapping`, `phase_1e_post_llm_severity`, `phase_1e_density_severity`, `phase_1e_benign_suppression`, `phase_3_policy_evaluation`, `phase_2_rag_retrieval`, plus `_total_elapsed_sec` for the whole run.

Within `retrieval_engine.py`, `retrieve_cis_controls_llm()` additionally times each RAG sub-stage internally (per-control embed vs. per-control DB fetch, sweep embed vs. parallel DB fetch, quality-filter/dedup, pre-rerank cap, graph expansion DB time, and the reranker `predict()` call in isolation from its coverage-guarantee bookkeeping) and prints a consolidated breakdown table before returning.

---

## 7. Known operational caveat

`pipeline.py` currently executes `complete_log_pipeline_run()` and `run_dlq_and_malformed()` unconditionally at **module import time**, not gated behind `if __name__ == "__main__":`. Any future code that does `import pipeline` (e.g. an API layer or test harness) will trigger a full batch run of every sample log as a side effect of the import. Worth guarding before building anything on top of this module.
