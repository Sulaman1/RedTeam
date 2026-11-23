# Red Team Engineering - Laboratory Quickstart

Use the PDF field guide for explanations, not just these commands. From a terminal in this directory's `labs/` folder, run `bash setup.sh` first. All exercises are local or offline. Python 3 is the primary requirement.

| Lab | Module | Command | What to expect |
|---|---|---|---|
| 01 | 01 | `python3 01_scope_guard.py 127.0.0.1` | `IN SCOPE` |
| 02 | 02 | `python3 02_bytes.py 173 --text سلام` | binary `10101101`, hex `AD`, UTF-8 byte count |
| 03 | 03/05 | `python3 03_file_inventory.py "$HOME/rte-field-guide/data"` | JSON of filenames, byte lengths and SHA-256 |
| 04 | 04/08 | `python3 04_local_http.py --port 8765` | loopback server; stop with Ctrl+C |
| 05 | 08 | `python3 05_local_client.py` in a second terminal | HTTP `200, 200, 403, 200` |
| 06 | 07 | `python3 06_asset_review.py` | fictional unknown asset flagged for review |
| 07 | 09 | `python3 07_permissions.py` | private mode `0o600` |
| 08 | 11 | `python3 08_iam_policy.py` | second policy statement flagged |
| 09 | 12 | `python3 09_elf_header.py /bin/ls` | ELF class, endian and machine on typical Kali |
| 10 | 13 | `python3 10_fuzz_frames.py` | 400 cases, zero unexpected exceptions |
| 11 | 14 | `python3 11_detect_events.py` | Alice flagged for review at 3 failures |
| 12 | 14 | `python3 12_timeline.py` | ordered fictional events; no causation inferred |
| 13 | 16 | `python3 13_report_score.py` | portfolio checklist, initially `60/100` |

## Reproduce the evidence

Record the following for each lab: date/time and timezone; Python version; relevant command and fixture name; predicted result; actual output; explanation; limitations; and cleanup action. Never mix live institutional data with these synthetic fixtures.

## Creating and debugging a local C binary

Create `square.c` using Module 12, compile with `gcc -g -O0 -o square square.c`, then run `./square` (prints 49), `file square`, `readelf -h square`, and `python3 09_elf_header.py square`. Use `gdb ./square` only for your own self-built executable.

## Example authorization check

If the demo server is running, the request below must receive HTTP 403. It is a toy trust model and does not authenticate header values:

```bash
curl -i -H 'X-Demo-User: alice' http://127.0.0.1:8765/api/records/2
```

## Checklist

- [ ] Commands are run only on owned, local or approved lab assets.
- [ ] Fixtures use synthetic, nonsensitive data.
- [ ] Expected and observed outputs are both documented.
- [ ] Any unexpected event is investigated rather than ignored.
- [ ] The report distinguishes facts, hypotheses, and limitations.
- [ ] Temporary services are stopped and cleanup verified.
