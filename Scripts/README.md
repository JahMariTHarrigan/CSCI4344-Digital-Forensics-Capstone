# Reproducibility files

These are the actual analysis scripts and saved provenance from the case, plus `verify_saved_offsets.py`, a small helper added for repeatable review of the saved checks. Original evidence, raw memory, credentials and third-party executable files are deliberately excluded.

## Setup

Use Python 3.11 or later and a separate environment. Install `requirements.txt` for journal parsing; the other analysis scripts use the standard library. Install ripgrep separately from its official source for large text searches. Dissect's dependencies are resolved by pip; the original run used an isolated `tools/` directory. No malicious program is executed by these scripts.

Obtain the designated archive from https://righteousit.com/2026/03/27/linux-forensic-scenario/ and place it in `evidence/` beside these scripts. Run from this directory. Keep the included provenance files as the original examiner's record; use a fresh copy of this folder for a new run, because scripts overwrite derived results. Extraction deliberately refuses to overwrite an existing numbered working file. Allow more than 12 GB additional free space plus the original archive.

```text
python inspect_archive.py
python extract_working.py
python read_evidence.py list "passwd|sudoers|journal|sockstat"
python read_evidence.py "[root]/etc/sudoers.d/10-workers-rule"
python parse_journals.py
python summarize_checks.py
python final_scope_checks.py
python verify_saved_offsets.py
```

The original full archive SHA-256 is 81664ab2337f3d319cfeaf0d96e6ae982b4b8ec383341a69a026cb016d4e443e. Verification compares with that acquired copy; it is not a publisher-signed checksum. `working_manifest.json` maps exact Linux archive paths to numbered local files and SHA-256 hashes. Archive header metadata belongs to the collection container; use the bodyfile for original filesystem ownership/times.

## Search and synthesis

`triage.py` contains the actual first-pass search. Its subsequent Python memory scan was interrupted because it was slow. Use ripgrep for memory strings instead. An example targeted command (redirect to a local text file if needed) is:

```text
rg -n -a "xmrig|libymv|pty.spawn|/dev/shm/kit|gid=7823" working/01933.bin
```

`verify_memory.py` is the original verification script and requires the original search-output format in `analysis/memory_rg_hits.txt`; that raw search file is not distributed. `verify_saved_offsets.py` instead reads the provided selected-check JSON and reproduces all 102 comparisons directly against `working/01931.bin`. These are raw capture file offsets, not process virtual addresses.

`carve_library.py` performs a bounded contiguous ELF recovery attempt and is optional; it scanned 9,346 candidates without finding the known 24,024-byte SHA-1 match. It is not proof that fragmented bytes are absent. `case_data.py` constructs sourced timeline/IOC/mapping records from the examined observations. `build_evidence_views.py` generates the local HTML review pages used for original browser screenshots; it does not fabricate an Ubuntu terminal.

The notes PDF records actual methods, tool limitations and competing explanations. `analysis/figures.json` retains captions and selected displayed excerpts. Supplied Volatility socket output was examined, not independently regenerated. The student must review and understand the findings before presenting them.
