# RED TEAM ENGINEERING - 14 PRINTABLE CHEAT SHEETS

**A quick-reference companion to the 16-module concise field guide.** Use only on owned or authorized training environments. Read the lessons for context; commands do not authorize third-party testing.

## Cheat Sheet A — Scope, risk, and evidence {#cs-a}

| Question | Required answer before testing |
|---|---|
| Whose system? | Verified legal/operational owner and written approval |
| Which assets? | Exact addresses, accounts, applications, and exclusions |
| Why test? | Business objective or hypothesis and expected result |
| What methods? | Approved tooling, request rate, safety constraints |
| When? | Maintenance or test window, stop/contact procedures |
| What data? | Synthetic if possible; minimum necessary real data |
| Where does evidence go? | Approved encrypted storage with retention plan |
| What if something breaks? | Stop, notify owner, preserve evidence, follow ROE |

**Finding sentence:** “For [identity] on [asset], [repeatable observation] showed [condition]. This could affect [supported impact] under [preconditions]. Recommend [specific control] and retest [criteria].”

**Confidence vocabulary:** observed / strongly supported / inconclusive / not observed. Never silently change “not observed” into “could not happen.”

## Cheat Sheet B — Core Kali Linux commands {#cs-b}

| Goal | Command | Caveat |
|---|---|---|
| Identity | `whoami; id` | Current effective and supplementary credentials matter |
| Path | `pwd; ls -lah` | Hidden files require `-a` |
| File info | `file F; stat F` | File type is inferred, not validated safe |
| Text | `less F; head F; tail F` | Be alert to sensitive data in logs |
| Search contents | `grep -nF 'word' F` | `-F` treats pattern literally |
| Search files | `find . -type f -name '*.log'` | Quoted glob avoids shell pre-expansion |
| Hex | `od -An -tx1 -v F` | `xxd -g1 F` if installed |
| File hash | `sha256sum F` | Integrity, not authenticity |
| Disk and mounts | `df -h; lsblk; findmnt` | Read-only inspection |
| RAM/CPU | `free -h; lscpu` | May differ within VMs/containers |
| Sockets | `ss -ltn` | Listening TCP sockets on your host |
| Routing | `ip route` | No permission to test displayed routes |
| Processes | `ps aux; top` | Do not terminate unrelated services |
| Service status | `systemctl --user status NAME` | User manager may be unavailable |
| Journal | `journalctl --user -n 30` | Availability and retention depend on setup |

**Shell operators:** `|` pipe; `>` overwrite stdout; `>>` append stdout; `2>` redirect errors; `&&` run next command on success; `;` sequence regardless of outcome; `$(...)` command substitution. Quote filenames and variables.

## Cheat Sheet C — Permissions and least privilege {#cs-c}

| Octal mode | Owner | Group | Others | Typical case |
|---|---|---|---|---|
| `600` | `rw-` | `---` | `---` | Private file |
| `640` | `rw-` | `r--` | `---` | Group-readable file |
| `700` | `rwx` | `---` | `---` | Private directory |
| `750` | `rwx` | `r-x` | `---` | Team directory |
| `755` | `rwx` | `r-x` | `r-x` | Public executable/directory |

- File `x`: execution where other conditions permit. Directory `x`: search/traverse names.
- Sticky bit on shared directories: restricts removal/renaming of others' entries.
- setuid/setgid: special execution and group-inheritance semantics; use with great care.
- `getfacl FILE`: inspect ACLs if installed; masks can reduce effective access.
- `stat -c '%a %A %U:%G' FILE`: quick metadata inspection.
- Avoid blanket `chmod -R 777` and `sudo` for ordinary labs. Use a dedicated training directory.

## Cheat Sheet D — TCP/IP and subnetting {#cs-d}

| Item | Remember |
|---|---|
| IPv4 | 32 bits; example `192.0.2.37` (documentation range) |
| IPv6 | 128 bits; `::1` is loopback |
| CIDR `/24` | 24 bits network, 8 bits host; 256 address patterns in IPv4 block |
| TCP | Ordered byte stream with connection semantics |
| UDP | Datagram transport without TCP delivery guarantees |
| DNS | Answers depend on record type, resolver, caching and TTL |
| HTTP | Application request/response protocol |
| TLS | Cryptographic transport with certificate/identity validation |
| Firewall | Network policy, not application authorization |

**Often seen ports (not proof of a service):** 22/SSH, 53/DNS, 80/HTTP, 443/HTTPS, 445/SMB, 3389/RDP, 5432/PostgreSQL, 1433/SQL Server, 3306/MySQL. Actual services can run on other ports, and a listed port may be inaccessible.

**Local inspection:** `ip -br addr`, `ip route`, `ss -ltn`, `curl -i http://127.0.0.1:8765/health` when your own demo server is running.

## Cheat Sheet E — HTTP and API security {#cs-e}

| Concept | Quick interpretation |
|---|---|
| GET | Retrieve a resource; should not intentionally change state |
| POST | Submit data or trigger an operation; semantics vary |
| PUT/PATCH | Replace/update a resource (per API semantics) |
| DELETE | Request deletion |
| 200 | Request succeeded |
| 201 | Resource created |
| 204 | Successful response with no body |
| 301/302 | Redirect |
| 400 | Bad client request |
| 401 | Lacks valid authentication credentials for requested resource |
| 403 | Server refuses the request under its policy |
| 404 | Resource not found or intentionally undisclosed |
| 429 | Rate limit applied |
| 500 | Server error |

**Top controls:** verified authentication; per-action and per-record authorization; least-privilege database access; parameterized queries; output encoding; CSRF protection where needed; strict file-upload handling; resource limits; useful audit logging; secure token handling.

**Local demonstration:** `curl -i -H 'X-Demo-User: alice' http://127.0.0.1:8765/api/records/2` should return 403 in the toy server. Header-based identity is deliberately insecure and **must not** be used in production.

## Cheat Sheet F — Python and safe Bash {#cs-f}

**Python essentials**

```python
from pathlib import Path
import argparse, csv, json, hashlib
from collections import Counter
from datetime import datetime, timezone
# Validate a file before parsing, catch errors, use explicit UTF-8.
```

**Bash essentials**

```bash
#!/usr/bin/env bash
set -euo pipefail
umask 077
# quote variables: "$path"
# protect unusual names: some_command -- "$path"
```

**Testing checklist:** normal case; empty file; malformed record; unexpected type; oversized value; permission denied; symbolic link; newline/space in name; repeatable output. Use temporary data rather than editing important files.

**Never:** `eval` on untrusted input; command strings built from unchecked parameters; print secrets in logs; disable errors without explanation; assume a successful exit code proves business correctness.

## Cheat Sheet G — Windows, AD, and identity {#cs-g}

**Windows read-only starting commands** (own/authorized machine):

```powershell
whoami /all
Get-LocalUser
Get-Service | Select-Object -First 10 Name,Status
Get-WinEvent -ListLog * | Select-Object -First 10
```

**Terminology:** SID identifies a security principal; an access token contains security context; ACL defines allowed/denied access; UAC affects elevation context; NTFS permissions and file shares both influence access; local administrator ≠ domain administrator. AD domain, forest, group, service account, GPO, LDAP, NTLM and Kerberos describe different components of enterprise identity.

**Analysis sequence:** identify principal → inspect effective token/groups → identify resource ACL → consider inheritance and policy → verify actual permitted action → record event evidence. A group listed in a directory does not automatically prove a process can exercise a specific privilege.

## Cheat Sheet H — Cloud IAM and containers {#cs-h}

**Cloud review:** principal → requested action → resource → condition → applicable allows/denies → other boundaries → logging. Review unintended `Action: *` and `Resource: *`, stale roles, public storage, excessive service-account permissions, hard-coded secrets, and missing audit trails. Provider-specific policy evaluation must be consulted.

**Container review:** image source and version; identity inside container; capabilities; privileged flag; mounts; host sockets; networking; resource limits; secrets; updates; runtime restrictions. Containers share a kernel; do not treat them as perfect isolation boundaries.

**Kubernetes review:** namespace; ServiceAccount; Roles/ClusterRoles and bindings; workload security context; NetworkPolicies; exposed services; image provenance; audit logs. NetworkPolicies depend on a compatible network implementation and do not replace RBAC.

**Offline lab:** `python3 08_iam_policy.py` flags intentionally broad statements in synthetic JSON. It does not query cloud accounts.

## Cheat Sheet I — Reverse engineering essentials {#cs-i}

| Step | Tool | Question |
|---|---|---|
| Identify | `file FILE`, hashes | What was received? |
| Format | `readelf -h FILE` | Architecture, class, endianness? |
| Strings | `strings FILE` | Which printable sequences occur? |
| Disassemble | `objdump -d FILE` | What instructions are present? |
| Analyze | Ghidra | How could control/data flow work? |
| Debug own code | GDB | What happens at runtime? |
| Record | Notebook + SHA-256 | Can a peer reproduce the finding? |

**x86-64 essentials:** `RIP` instruction pointer, `RSP` stack pointer, `RAX` common return register, and argument register sets determined by calling convention. `call` transfers execution to a function; `ret` returns. A disassembler's guess is not always semantic truth; investigate compiler optimizations and inlining.

**First binary:** Build `square.c` from Module 12. Never run unknown malware merely to learn the debugger interface.

## Cheat Sheet J — Memory safety and fuzzing {#cs-j}

**Bug family:** out-of-bounds access, use-after-free, double free, integer wrap leading to wrong sizes, invalid lifetime, race condition, unchecked parser length.

**Research loop:** specification → test cases → bounded randomized inputs → isolate unexpected behavior → minimize → reproduce → diagnose → fix → regression test → responsible report.

**What to preserve:** input bytes, seed, binary hash, exact build flags, runtime environment, stdout/stderr, stack trace if any, and a minimized reproduction case. An unexpected crash is a lead, not an automatic proof of control-flow hijack or exploitability.

**Safe starting point:** `python3 10_fuzz_frames.py` tests only the handbook's own small parser.

## Cheat Sheet K — Telemetry, ATT&CK, and incident triage {#cs-k}

| Item | Analyst's question |
|---|---|
| Event | What exactly was recorded? |
| Data source | How complete and reliable is this source? |
| Tactic | What objective might behavior support? |
| Technique | What observed behavior fits this classification? |
| Detection | What fields and thresholds identify it? |
| False positive | What benign behavior could look similar? |
| Alert | What must be investigated next? |
| Incident | Which impact or threat is actually supported? |
| Containment | What minimizes harm without undue disruption? |

**Six response stages:** triage → preserve → scope → contain → recover → improve. Real incident procedures are governed by the organization's policy and legal obligations. Keep timezone-aware timestamps; preserve original evidence separately from analysis copies.

**Synthetic practice:** `python3 11_detect_events.py` then `python3 12_timeline.py`. A detected pattern is not automatically an attack.

## Cheat Sheet L — Reporting and retesting {#cs-l}

**One-page finding template**

```text
Finding: [specific title]
Risk: [supported consequence + conditions]
Scope/identity: [approved asset and role]
Method: [reproducible, safe steps]
Evidence: [timestamp, request/response, hash/log reference]
Expected vs actual: [state both]
Confidence: [known, inferred, unknown]
Remediation: [specific, minimal, testable]
Owner/priority: [agreed action]
Retest: [same case after the change]
```

**Executive summary formula:** tested scope + critical observations + material limits + requested decision. Avoid tool catalogs in the executive summary; put technical reproduction steps in the appendix.

**Professional cautions:** redact tokens and personal data; use approved storage; state uncertainties; distinguish control failure from unsupported impact claims; provide owners and acceptance criteria; and verify cleanup.

## Cheat Sheet M — Minimum toolset and practical alternatives {#cs-m}

| Task | Good starting tool | Alternative/notes |
|---|---|---|
| Linux basics | Terminal (`bash`/`zsh`) | Core utilities |
| Python scripting | `python3` | Standard library suffices for many labs |
| HTTP inspection | `curl` | Browser DevTools for owned applications |
| Network status | `ip`, `ss` | No active probes required |
| Packet inspection | Wireshark | `tcpdump` on authorized interface |
| Binary headers | `file`, `readelf` | `objdump`, tiny Python reader |
| Reverse engineering | Ghidra | `objdump`, GDB on own binaries |
| Version history | Git | Exclude secrets from repository |
| VMs | VirtualBox | Offline localhost exercises if VM unavailable |
| Windows visibility | PowerShell/Event Viewer | Sysmon if appropriately installed |
| Detection | JSONL + Python | SIEM/Sigma in a dedicated training platform |

A tool is useful only when you know what evidence it produces, what it misses, and whether its use is permitted. Select the simplest tool that answers the security question.

## Cheat Sheet N — Your weekly revision loop {#cs-n}

**Week structure (repeat at every level):**

1. **Learn:** Read a concept and restate it from memory in your own words.
2. **Predict:** Write expected output before running commands.
3. **Execute:** Run the exercise only on approved synthetic assets.
4. **Explain:** Capture observations and note what you did *not* prove.
5. **Improve:** Change one control or test case and rerun.
6. **Report:** Write a few sentences that another analyst can reproduce.

**Ready to advance when:** You can complete the lab without copying commands blindly, explain why each command is needed, and produce a short evidence-backed note. Memorized flags alone are insufficient.

---

