# TRACE prompt versions

Reference copy of the AI prompt logic before and after the false-positive /
missed-detection fixes. Only two things differ between them; the four prompt
templates (`PASS1_SYSTEM_TEMPLATE`, `PASS1_USER_TEMPLATE`,
`PASS2_SYSTEM_TEMPLATE`, `PASS2_USER_TEMPLATE`) are identical in both versions.

Test data: `Gentleman_Amcache.csv` + `Gentleman_Prefetch.csv` +
`Gentleman_Shimcache.csv` (13 known-malicious files).

| | v1 | v2 |
|---|---|---|
| Detected | 10 / 13 | 13 / 13 |
| False positives (all 3 artifacts) | 3 | 1 (`im4.txt`, arguably a true positive) |
| Missed | `Greenshot.exe`, `SyncTrayzor.exe` | none |

---

## v1 — original (as tested)

### SEVERITY_GUIDANCE

```python
SEVERITY_GUIDANCE = """Severity guidance - use these as anchors:
  10.0  Known malware, ransomware, or a confirmed malicious binary
   9.0  Reconnaissance tooling (port scanners, network/user enumeration)
   9.0  Monitoring-evasion tools (history/installation hiders, log cleaners)
   9.0  Software deployment tools used to push payloads to other machines
   8.5  Remote access / remote monitoring / remote management tools (RMM)
   8.0  File transfer, cloud storage, or cloud sync tools (exfiltration risk)
   6-8  Oddly named executables in Downloads, TEMP, AppData or other unusual
        locations - score by how unusual the name and location are
   1-5  Everything else that is merely unusual rather than suspicious

Do NOT flag standard Windows components or software legitimately installed
under a Windows system directory."""
```

### format_pass1_entry

```python
def format_pass1_entry(entry_id, row):
    entry = {
        "id":        entry_id,
        "source":    row.get("source", ""),
        "name":      row.get("name", ""),
        "full_path": row.get("full_path", ""),
        "timestamp": row.get("timestamp_utc", ""),
    }

    # --- Amcache-only identity metadata ---
    if row.get("product_name"):
        entry["product"] = row["product_name"]
    if row.get("description"):
        entry["description"] = row["description"]
    if row.get("version"):
        entry["version"] = row["version"]
    if row.get("link_date_utc"):
        entry["pe_compile_date"] = row["link_date_utc"]
    if row.get("is_os_component"):
        entry["is_os_component"] = True

    original = row.get("original_file_name", "")
    if original and original.lower() != row.get("name", "").lower():
        entry["original_file_name"] = original

    # --- Prefetch-only execution evidence ---
    if row.get("run_count"):
        entry["run_count"] = row["run_count"]
    if row.get("executed") is not None:
        entry["confirmed_executed"] = row["executed"]

    return json.dumps(entry, ensure_ascii=False)
```

---

## Why v1 failed

**Missed `Greenshot.exe` and `SyncTrayzor.exe`.** Both sit in
`C:\ProgramData\`, are unsigned, and have a zeroed `1970-01-01` PE compile
date. v1 taught the model none of those signals, and its closing line —
*"Do NOT flag ... software legitimately installed"* — gave the model explicit
permission to dismiss anything with a recognisable product name.

**3 false positives once Prefetch/ShimCache were added.** Those artifacts record
no publisher, product or version, so files appearing only there
(`svchost.exe`, `lsass.exe`, `chrome.exe`, `outlook.exe`) were judged from a
bare filename. Compounding it, the same executable was assessed once per
artifact and `max(risk_score)` won — three independent chances to be wrong
about one file.

**A parser bug underneath both.** `amcache_parser.py` never read the
`Publisher` column, so the strongest signing signal in the artifact was being
discarded before the prompt ever saw it.

---

## v2 — current

Three changes, only one of which is prompt wording:

1. **`amcache_parser.py`** now reads `Publisher`.
2. **`correlation.collapse_to_executables()`** merges artifact rows into one
   row per executable *before* the AI, copying Amcache metadata onto the
   Prefetch/ShimCache view. Each executable is judged exactly once.
3. **`SEVERITY_GUIDANCE`** rewritten as an explicit 5-step procedure
   (location → signing → capability → missing metadata → what not to flag),
   and `format_pass1_entry()` now distinguishes
   `"(none - file is UNSIGNED)"` from
   `"(not recorded - this artifact does not store publisher)"`.

The current text lives in `backend/pipeline/ai_engine.py`.

### Rolling back

Replace `SEVERITY_GUIDANCE` and `format_pass1_entry` in
`backend/pipeline/ai_engine.py` with the v1 blocks above. Note that rolling
back the prompt alone still leaves fixes 1 and 2 in place — to reproduce the
original v1 behaviour exactly you would also need to revert the parser and the
collapse step, which are in `amcache_parser.py` and `correlation.py`.
