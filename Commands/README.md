# Reviewing the evidence

Run these commands from `Scripts/` after following its [setup instructions](../Scripts/README.md). They are reproduction examples; original results and limitations are recorded in the investigation.

## Preserve and inventory

```text
python inspect_archive.py
python extract_working.py
```

The first command verifies the archive hash and lists its members. The second extracts regular files into numbered working files and records their SHA-256 hashes. Use a fresh working folder; extraction refuses to overwrite existing files.

## Read accounts and authentication artifacts

```text
python read_evidence.py list "passwd|sudoers|journal|sockstat"
python read_evidence.py "[root]/etc/sudoers.d/10-workers-rule"
python parse_journals.py
```

The journal export retains each original artifact path and record number. Those locators are used in the timeline.

## Search and verify memory remnants

```text
rg -n -a "xmrig|libymv|pty.spawn|/dev/shm/kit|gid=7823" working/01933.bin
python verify_saved_offsets.py
```

The search reads the supplied strings file. The verification helper compares the 102 saved strings with bytes in the raw memory capture. Matching strings do not supply reliable execution times by themselves.

## Check other persistence and privilege paths

```text
python summarize_checks.py
python final_scope_checks.py
```

These checks cover collected account state, startup files, service indicators, selected metadata, and SUID/SGID entries. An empty search result applies only to the collected material and the specific search performed.
