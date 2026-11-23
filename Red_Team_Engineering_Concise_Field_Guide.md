# RED TEAM ENGINEERING — CONCISE FIELD GUIDE

**The essential path from beginner to advanced security researcher**  
**16 core modules · 13 Python lab programs · 14 cheat sheets · 1 integrated capstone**  
**Companion to the complete 120-chapter Red Team Engineering textbook**

## How to use this guide

Read Modules 1–6 in order, even if you already use Kali Linux; they teach the safety, computer, network, and lab fundamentals that later work assumes. Modules 7–11 build hands-on assessment and enterprise analysis skills. Modules 12–16 cover reverse engineering, testing, detection, purple-team validation, and reporting. After each module, run the relevant owned, offline or loopback-only lab, explain the expected and actual results, and write a short note. Consult the cheat sheets while working—not as a substitute for understanding the modules.

**Scope and ethics:** This book teaches authorized security assessment and defense. All included programs use synthetic inputs and/or localhost-only services. Do not probe third-party hosts, government or office systems, devices, accounts, wireless networks, or production data without explicit permission. A command's presence here is never authorization to run it against another party.

**Realistic promise:** Finishing a short handbook is not equivalent to becoming an expert. Expertise requires deep study, repeatable experiments, collaboration, and experience under professional supervision. The guide is the shortest coherent path through the **highest-value competencies** in the 120-chapter course.

**Software:** Kali Linux or another mainstream Linux host with Python 3; optional GCC, GDB, `readelf`, VirtualBox, and Windows/PowerShell for selected sections. The essential Python examples require only the standard library.

**Lab setup:** Extract the ZIP, open a terminal in its `labs/` directory, and run `bash setup.sh`. Avoid `sudo` unless a separately authorized administrative action genuinely requires it.

---

# Module 01 — The professional mindset and legal boundaries {#m01}

**Level:** Beginner · **Time:** 2–3 hours · **Outcome:** Plan a safe, measurable assessment before touching a system.

A security assessment is successful when it produces trustworthy evidence that improves defenses. Finding an issue without knowing its impact or how to fix it is incomplete work. Technical skill does not replace authorization, privacy, or operational safety.

## The essentials

- **Penetration test:** A scoped effort to discover and validate weaknesses. Its goal is usually to assess a defined set of assets and controls.
- **Red-team exercise:** Objective-driven simulation of a plausible adversary, coordinated with authorized leadership and usually measured against detection and response outcomes.
- **Blue team:** Monitors, investigates, hardens, and responds. **Purple teaming** connects offense and defense through joint testing, observation, and retesting.
- **Attack surface:** Systems, users, interfaces, services, dependencies, and trust relationships that could be used to reach an objective.
- **Rules of Engagement (ROE):** A written contract describing what may be tested, by whom, when, how, and with what stop conditions.

An attack model is not proof of an attack. The Cyber Kill Chain describes broad progression; MITRE ATT&CK classifies adversary objectives and behavior. Neither is a guaranteed sequence nor a checklist to run against real targets. An alert is not an incident until investigated, and absence of an alert is not proof that activity did not occur.

![Four-stage learning path](diagrams/path.svg){width=100%}

*Figure 1. Learning progression. Each stage builds on verified knowledge from the preceding stage.*

## One-page engagement plan

Fill in all fields *before* testing:

| Field | Example for this book |
|---|---|
| Owner and authorization | You, for your own local training environment |
| In scope | `127.0.0.1`, synthetic data, explicitly named training files |
| Out of scope | Public websites, office networks, others' accounts, live databases |
| Methods | Local server, synthetic parsing, static analysis of self-built files |
| Time window | During the study session |
| Evidence | Command, timestamp, file hash, observed result, explanation |
| Stop trigger | Unexpected network reachability, sensitive data, instability |
| Cleanup | Stop processes, delete disposable test data, verify state |

**Decision rule:** If you cannot state *who authorized the asset* and *why the activity is necessary*, do not run the test.

## Lab 01 — Enforce your training scope

This lab validates an IP address without sending any traffic. In the lab ZIP, open a terminal in the `labs/` folder:

```bash
python3 01_scope_guard.py 127.0.0.1
python3 01_scope_guard.py 8.8.8.8
```

The first prints `IN SCOPE`. The second prints `OUT OF SCOPE` and exits with code 2. The code accepts only literal IP addresses; it deliberately does not resolve hostnames or allow a broader private network. To inspect the return code after the second command, run `echo $?` immediately.

**Explain the result:** An allowlist is useful only when it is explicit, enforced, and matched to written permission. This script is a classroom guardrail, not a general engagement authorization system.

## Expert habit

For each action, record **hypothesis → permitted test → expected telemetry → actual evidence → limitation → recommendation**. A good operator can identify alternative explanations and knows when a conclusion is unsupported.

**Checkpoint:** Can you distinguish reconnaissance from exploitation; explain why a private IP address is not automatically in scope; and describe exactly when you must stop?

---

# Module 02 — Computer, binary, and operating-system essentials {#m02}

**Level:** Beginner · **Time:** 3–4 hours · **Outcome:** Understand what software actually executes and where security boundaries are enforced.

## The mental model

The **CPU** executes machine instructions. **Registers** hold immediate execution state. **RAM** stores working data. **Storage** keeps ordinary data across shutdowns. An **operating system** schedules programs, maps memory, exposes files and devices, and checks access rights. A process has its own virtual address space; threads within that process generally share memory but maintain distinct execution states.

![OS boundary](diagrams/os.svg){width=100%}

*Figure 2. Application actions cross the operating-system boundary through defined interfaces.*

### Bits, bytes, and the meaning of data

Eight bits form one byte. `10101101₂` equals decimal 173, or `0xAD`. Every four binary digits correspond to a hexadecimal digit. In an unsigned eight-bit integer, patterns range from 0 through 255; in signed two's complement, from −128 through 127. The *same bits* have different meanings under different interpretations.

UTF-8 is a variable-length encoding. An ASCII `A` uses byte `41`; non-ASCII characters may require multiple bytes. Do not confuse *characters*, *Unicode code points*, and *byte lengths*. For a 32-bit value `0x12345678`, big-endian bytes are `12 34 56 78`; little-endian bytes are `78 56 34 12`.

**Virtual memory** gives processes isolated address spaces with access rules implemented through page tables and hardware. Memory-map permissions such as `r-x` and `rw-` do not equate to filesystem permissions. The stack holds execution-related temporary state; the heap supports dynamic allocations. Poor bounds checks or use-after-free bugs become important later because they can violate expected memory behavior.

## Worked example — From Python to a file

When Python opens a file, the interpreter ultimately asks the kernel to perform operations through system calls. The kernel checks the relevant process credentials, pathname traversal, file permissions, and other policies. The filesystem and underlying storage are then involved. A successful `open()` does not mean Python owns the disk or bypassed the kernel.

Observe only your own environment:

```bash
uname -m                     # CPU architecture reported to software
lscpu | head -n 18          # processor information
free -h                     # RAM and swap
getconf PAGE_SIZE           # configured memory page size
python3 --version
```

Common architectures include x86-64 and AArch64. Different architectures use different instruction sets and calling conventions; this matters when examining compiled programs.

## Lab 02 — Decode a byte and UTF-8 text

```bash
python3 02_bytes.py 173 --text 'سلام'
python3 - <<'PY'
value = 0x12345678
print(value.to_bytes(4, 'little').hex(' '))
print(value.to_bytes(4, 'big').hex(' '))
PY
```

Expected: decimal `173`, binary `10101101`, hex `AD`; the Urdu/Arabic-script text has four code points and eight UTF-8 bytes; little-endian bytes are `78 56 34 12`. The lab requires no elevated rights.

**Troubleshooting:** A printed Unicode glyph may depend on terminal fonts, but the encoded hex bytes are still meaningful. A byte-order difference does not imply corruption; you must know the format specification.

## You are ready when

You can explain: why compiled x86-64 instructions differ from Python source code, why RAM and disk are not interchangeable, what a system call is, and why an integer's signedness must be specified. These facts underpin reverse engineering, file-format parsing, and exploit-mitigation analysis.

---

# Module 03 — Linux and the command line {#m03}

**Level:** Beginner → Operator · **Time:** 4–6 hours · **Outcome:** Navigate and inspect Kali Linux safely without relying on a GUI.

## Know the hierarchy

Linux paths begin at `/`. Home directories are commonly under `/home`; `/etc` stores system configuration; `/var/log` holds many logs; `/usr` contains applications and libraries; `/proc` and `/sys` expose dynamic kernel-related interfaces; `/dev` contains device nodes. The current directory is `.`, and its parent is `..`. A leading `/` means an absolute path.

Kali often uses Zsh interactively. Bash examples below should be run with `bash` when you need Bash-specific behavior. `$SHELL` typically refers to the configured login shell, not necessarily the exact current interpreter.

### Ten commands to internalize

| Need | Command | What to notice |
|---|---|---|
| Where am I? | `pwd` | Current working directory |
| What is here? | `ls -lah` | Owner, mode, sizes, hidden entries |
| Navigate | `cd ~/rte-field-guide` | Quotes when a path has spaces |
| Search filenames | `find . -type f -name '*.txt'` | The shell must not expand the quoted glob first |
| Search content | `grep -R -n -F 'ERROR' logs/` | Literal text search, not threat detection |
| View safely | `less file.txt` | Exit with `q` |
| File kind | `file sample.bin` | Signature-based inference, not trust |
| Metadata | `stat file.txt` | Mode, inode, timestamps |
| Hash | `sha256sum file.txt` | Integrity fingerprint |
| Processes | `ps -p $$ -o pid,ppid,comm` | Parent and active shell |

### Standard streams and pipelines

`stdin` (FD 0) supplies input, `stdout` (FD 1) carries ordinary output, and `stderr` (FD 2) carries diagnostics. `>` overwrites output; `>>` appends; `2>` redirects errors. A pipe connects one program's stdout to the next one's stdin.

```bash
printf 'red\nblue\nred\n' | sort | uniq -c
```

Output: two occurrences of `red`, one of `blue`. `uniq` only combines *adjacent* equal lines; sorting first matters.

### Permissions are not just numbers

In `rwxr-x---`, owner permissions are `7`, group permissions `5`, and others `0`: octal `750`. On a file, `x` means executable; on a directory, `x` means searchable/traversable. ACLs, mount options, and mandatory policies may still affect access. Never casually apply recursive `chmod` to real system directories.

## Lab 03 — Make a file inventory

```bash
bash setup.sh
mkdir -p "$HOME/rte-field-guide/data"
printf 'safe example\n' > "$HOME/rte-field-guide/data/note.txt"
python3 03_file_inventory.py "$HOME/rte-field-guide/data"
```

The program displays the relative filename, size, and SHA-256 hash for each regular file; it skips symbolic links. Change the file and rerun. The hash changes. This is evidence of a content difference, **not** proof of malware or file authenticity.

To inspect an executable on your own system, use `file /bin/ls` and `readelf -h /bin/ls` (if installed); do not change anything in `/bin`, `/usr/bin`, or `/etc` for this lab.

**Checkpoint:** Explain how `pwd`, a pathname, the current user, directory traversal permission, and a file hash work together during an investigation.

---

# Module 04 — Networks, ports, DNS, and HTTP {#m04}

**Level:** Beginner → Operator · **Time:** 4–5 hours · **Outcome:** Explain what a network request does and inspect only your own traffic.

## The model that matters

An IP address identifies a network interface in a routing context. A port identifies a transport-layer endpoint. TCP provides an ordered byte stream; UDP sends datagrams without TCP's delivery guarantees. DNS translates names into records; TLS can authenticate a server and protect transport data when correctly configured. HTTP defines requests, responses, methods, headers, and status codes.

| Concept | What an analyst should ask |
|---|---|
| IP and CIDR | Which network does this address belong to? |
| TCP | Did a connection establish? What application protocol followed? |
| UDP | What application protocol uses the datagram? |
| DNS | Which record type, resolver, and TTL were observed? |
| HTTP | Which method, path, identity, and status were involved? |
| TLS | Was the certificate and hostname validated? |
| Firewall | Which source, destination, port, and direction are allowed? |

### Worked subnet example

A `/24` IPv4 prefix means 24 network bits and eight host bits. `192.0.2.37/24` belongs to `192.0.2.0/24`; the last address is `192.0.2.255`. `192.0.2.0/24` is reserved for documentation; it is not an invitation to probe external devices. The CIDR length alone does not tell you whether traffic is authorized.

### Inspect your own host

```bash
ip -br addr
ip route
ss -ltn
python3 -m http.server 8000 --bind 127.0.0.1
```

The last command starts a deliberately simple local web server in the working directory. Use it **only in a directory containing harmless lab files**. In another terminal:

```bash
curl -i http://127.0.0.1:8000/
```

A `200` response means this request succeeded. It does not prove the application is secure. Stop the service with `Ctrl+C`.

## Lab 04 — Explain a request from end to end

Create a two-column timeline: on the left record `client → TCP connection → HTTP GET → response`; on the right record what evidence would verify each stage. Use your local server and `curl -i`. If Wireshark or `tcpdump` is installed, inspect only your loopback traffic and avoid collecting other users' communications.

**Boundary rule:** Never expand this exercise from loopback to an office subnet without an explicit approved scope.

**Checkpoint:** Explain why TCP 443 usually carries HTTPS, why a port number alone does not identify a specific application, and why DNS resolution does not establish trust.

---


# Module 05 — Python, Bash, and repeatable automation {#m05}

**Level:** Operator · **Time:** 4–6 hours · **Outcome:** Turn manual investigation into small, tested, explainable programs.

## The five patterns that matter

1. **Input:** Accept a known file, argument, or local event; validate its format and boundaries.
2. **Parse:** Convert bytes or text into structured data with the correct encoding and type.
3. **Transform:** Count, sort, filter, compare, or join observations without losing context.
4. **Output:** Show exactly what was observed and preserve a reproducible result.
5. **Error handling:** Fail visibly for malformed input instead of silently returning a misleading conclusion.

Python's standard library already supports many security-analysis tasks: `argparse` for CLI arguments, `pathlib` for filesystem paths, `json` and `csv` for records, `hashlib` for integrity, `collections.Counter` for summaries, and `datetime` for timezone-aware timelines. Bash works well for combining known CLI tools but should not be used to parse arbitrarily complex untrusted data.

### A Bash safety baseline

```bash
#!/usr/bin/env bash
set -euo pipefail
umask 077
printf '%s\n' 'My first reliable automation script'
```

`set -e` has exceptions in conditional constructs; `pipefail` influences pipeline status; `-u` flags unset parameters. These improve reliability but do not make a script intrinsically secure. Quote variable expansions, avoid `eval`, and do not interpolate untrusted strings into commands.

### A good minimal CLI

```python
from pathlib import Path
import argparse

p = argparse.ArgumentParser()
p.add_argument('filename', type=Path)
a = p.parse_args()
if not a.filename.is_file():
    p.error('expected an existing file')
print('Bytes:', a.filename.stat().st_size)
```

This is better than embedding a production filepath in the code. It is testable with temporary files and does not require administrator rights.

## Lab 05 — Run a safe inventory script

```bash
python3 03_file_inventory.py "$HOME/rte-field-guide/data"
python3 -m py_compile 03_file_inventory.py
```

Then add a second text file, rerun, and compare the JSON entries. The answer must distinguish *what the script saw* from assumptions about ownership, intent, or who changed the files.

**Extension:** Modify your own copy of the program to count file suffixes and report errors when files are unreadable. A robust production implementation would also mitigate race conditions between checking file metadata and opening files.

## Git in one minute

Inside your personal lab folder, `git init`, `git add`, and `git commit` can record changes to **safe, nonsensitive** notes and scripts. `git diff` explains what changed. Never commit passwords, API keys, private data, or evidence you lack permission to store. A Git repository is not by itself a tamper-proof evidence store.

**Checkpoint:** Can your script run twice with a predictable result? Does it reject malformed input? Can another student reproduce its output from the same fixture?

---

# Module 06 — Build an isolated security laboratory {#m06}

**Level:** Operator · **Time:** 3–5 hours · **Outcome:** Use VMs and local services without unintentionally exposing test systems.

A virtual machine presents guest hardware and usually runs its own kernel. A Linux container shares the host kernel; namespaces and control groups provide resource and process isolation but are not identical to a VM boundary. Neither technology eliminates the need for patching, access control, or correct network configuration.

![Internal network](diagrams/vm.svg){width=100%}

*Figure 3. Isolated multi-VM classroom design. Each additional adapter changes the threat boundary.*

## VirtualBox network modes

| Mode | Reachability | Use in the handbook |
|---|---|---|
| **Internal Network** | Same named internal network among guests | Preferred for intentionally vulnerable multi-VM exercises |
| Host-only | Guest and host can communicate | Controlled host-to-guest lab with verified exposure |
| NAT | Guest often has outbound reachability | Updates for trusted guests only, **not an air gap** |
| Bridged | Guest joins physical LAN | Avoid for vulnerable lab guests |
| Not attached | No active guest link | Standalone exercises |

### Resource budgeting example

A 4 GiB host might allocate 1.5 GiB to a small guest and leave 2.5 GiB nominally unassigned; real overhead and host applications reduce that reserve. A VM with several vCPUs does not receive dedicated physical cores automatically. If the host starts swapping heavily, lower VM allocations or stop other workloads rather than ignoring memory pressure.

### Snapshot is not backup

A snapshot helps revert a VM to a recorded state; it may still rely on the same physical disk as the VM. Keep independent backups of work that matters. Avoid snapshotting production data into a loosely protected training machine.

## Lab 06 — A reproducible isolation checklist

1. Install VirtualBox using trusted Kali documentation and verify `VBoxManage --version`.
2. Create a small Debian guest only if your host has adequate resources. Disable shared folders, clipboard, drag-and-drop, and unnecessary USB passthrough.
3. Set **one** adapter to Internal Network named `rte-int`. Disable adapters 2–4. Do not leave NAT or Bridged enabled.
4. Inspect the powered-off VM configuration with `VBoxManage showvminfo 'RT-Lab' --details` (substitute your actual VM name).
5. Boot the guest, inspect `ip -br addr` and `ip route`, and document its actual reachability. No other router should exist in the internal network for this exercise.
6. Shut down and take a clean-baseline snapshot. Record what you tested and how you restore it.

If VirtualBox isn't available, all Python labs in this book still work on the local host with no guest VM. The only networked service in the lab pack binds to `127.0.0.1`.

**Check:** A screenshot of a selected adapter does not prove isolation. Verify **every** adapter and relevant host integration setting.

---

# Module 07 — Reconnaissance, inventories, and service discovery {#m07}

**Level:** Operator · **Time:** 3–4 hours · **Outcome:** Build an accurate, authorized inventory and prioritize what needs review.

Reconnaissance is not the same as scanning. Passive collection examines already available authorized information; active discovery sends requests to a target. Public availability does not grant unrestricted permission to test. Good inventories include ownership, business purpose, environment, sensitivity, and the evidence supporting every entry.

| Asset field | Why it belongs in your worksheet |
|---|---|
| Asset name / ID | Stable referent for reporting |
| Owner / operator | Person accountable for remediation |
| Exposure | Local, internal, publicly reachable, or unknown |
| Data classification | Potential harm if accessed improperly |
| Services / dependencies | Where trust boundaries exist |
| Evidence source and timestamp | Whether the observation can be verified |
| Authorization | Whether active assessment is permitted |

Do not use unauthenticated scan results as a complete software inventory. A listening port may be a reverse proxy, container binding, shared service, or transient state. Inventory often requires configuration sources and interviews as well as observed traffic.

### Reading Nmap without overinterpreting it

A port marked `open` usually indicates evidence of an accessible listening service under that probe. `filtered` means the probe could not establish a definitive state under its conditions. Service-detection guesses are not guaranteed identification. Scan behavior and timing must remain within written scope; this guide therefore uses synthetic inventory data for the primary exercise.

## Lab 07 — Review a fictional asset register

```bash
python3 06_asset_review.py
```

The output identifies two documented training assets and one record lacking an owner and approval. **This is an inventory governance gap, not proof of an exploitable service.**

Extend the CSV with `last_reviewed`, `data_owner`, `network_zone`, and `evidence_reference`. Create two report sections: confirmed assets and assets requiring owner verification. Avoid assigning attack severity from incomplete inventory alone.

**Professional question:** What evidence would make you confident that a service is owned, in scope, and safe to test? If you cannot answer, return to the authorization step.

---

# Module 08 — Web and API security fundamentals {#m08}

**Level:** Operator → Analyst · **Time:** 5–7 hours · **Outcome:** Understand HTTP identity, session state, and record-level authorization.

A modern web request may move through a browser, TLS terminator, reverse proxy, application, database, and external service. Each hop is a separate trust boundary. HTTP methods describe requested operations; status codes describe responses; headers carry metadata; cookies and tokens may identify a session. **Authentication** determines who the requester is, while **authorization** checks what that identity is allowed to do.

![Web authorization flow](diagrams/web.svg){width=100%}

*Figure 4. A valid user identity does not grant access to every record.*

### The essential security questions

- Does the server enforce permission checks, or does it trust a hidden browser button?
- Does each API endpoint verify record ownership and role? This is central to preventing BOLA/IDOR.
- Are queries parameterized rather than concatenated with user input?
- Are user-controlled HTML outputs encoded in their context?
- Are state-changing actions protected using appropriate authentication and anti-CSRF measures?
- Do file operations validate both filenames and resolved destination paths?
- Are rate limits, monitoring, and meaningful errors designed appropriately?

### HTTP case: two records, two owners

In the training API, Alice owns record 1, and Bob owns record 2. `GET /api/records/1` as Alice should return 200. Alice requesting record 2 should receive 403. Bob requesting record 2 should receive 200. The server must decide based on a verified identity and resource policy, **not merely on whether the object ID exists**.

> **Important demo limitation:** The provided server intentionally uses an `X-Demo-User` header to simulate identity on loopback. Anyone who can set that header could impersonate an identity. It is **not** a production authentication design. Its sole purpose is to isolate authorization logic for learning.

## Lab 08 — Test a local-only authorization boundary

In terminal A, from the `labs/` directory:

```bash
python3 04_local_http.py --port 8765
```

In terminal B:

```bash
python3 05_local_client.py
```

Expected status sequence: `200`, `200`, `403`, `200`. Manually confirm one case:

```bash
curl -i -H 'X-Demo-User: alice' http://127.0.0.1:8765/api/records/2
```

The result should be HTTP 403. Stop the server with `Ctrl+C`. This validates a specific control path in a *toy* application; it does not constitute a real application pentest.

### What to document

Write the test identity, requested object, expected permission, observed status, and evidence filename. Avoid including real session tokens in the report. After a control change, repeat the same cases rather than concluding success from a single happy-path response.

**Checkpoint:** Explain the difference between a missing object (404), denied access (403), and an unauthorized/unauthenticated request (commonly 401) and why real systems may intentionally limit information disclosed in errors.

---


# Module 09 — Vulnerability assessment and risk decisions {#m09}

**Level:** Analyst · **Time:** 3–4 hours · **Outcome:** Distinguish a finding from a hypothesis and rank remediation sensibly.

Security assessments often discover an outdated package, a broad permission, an unexpected service, or a missing control. Those observations are starting points, not automatic proof of exploitable risk. A useful finding identifies **asset → condition → evidence → plausible impact → affected control → recommendation → retest**.

## Five distinctions you must make

| Term | Practical meaning |
|---|---|
| Vulnerability | Weakness that can create a security impact under conditions |
| Exposure | A reachable or accessible interface, not automatically a vulnerability |
| CVE | Identifier for a published vulnerability, not a severity score |
| CWE | Category of weakness, such as improper input validation |
| CVSS | Standardized severity scoring inputs; not complete business risk |

Prioritization should account for asset value, data sensitivity, exploit prerequisites, reachability, existing compensating controls, current evidence, and operational consequences. A technical CVSS score may inform urgency, but it does not replace analysis of the actual environment. Conversely, a service reachable only internally can still represent a serious problem if it holds highly sensitive information.

### Worked example — A world-readable report

An inventory records mode `0644` for a local test report. Before calling this a security issue, determine where the file lives, who owns the directories, whether the data is confidential, which users can traverse the path, and whether ACLs or other policies alter access. If the report contains harmless synthetic test text, the same mode may be acceptable in one context and inappropriate in another.

**A defensible finding:** “The synthetic report was readable by other local users under the tested path and policies. If the equivalent production report contains classified or personal information, restrict directory traversal and file mode, then retest using an authorized second identity.”

## Lab 09 — Check a controlled file mode

```bash
python3 07_permissions.py
```

The program creates a disposable temporary file, changes its mode to `0600`, prints that the group-read bit is absent, and removes the directory. Repeat the concept manually on an owned file with `stat -c '%a %A'`. Never recursively change live server permissions merely to satisfy a checklist.

### Vulnerability report, minimum viable format

```text
Title: [specific control weakness]
Asset / test identity: [authorized target]
Precondition: [what must be true]
Steps: [repeatable benign verification]
Expected: [stated control objective]
Observed: [timestamped evidence]
Impact: [supported, not speculative]
Confidence / limits: [what was not proved]
Recommendation: [concrete least-change fix]
Retest: [same checks after remediation]
```

**Checkpoint:** Explain why a 403 response does not prove that *all* resources enforce authorization and why a publicly listed version does not automatically establish that a particular CVE is exploitable.

---

# Module 10 — Windows, Active Directory, and identity {#m10}

**Level:** Analyst · **Time:** 4–6 hours · **Outcome:** Read Windows security context and reason about enterprise trust without changing production systems.

Windows represents access using security principals, SIDs, access tokens, access-control lists, integrity levels, privileges, and policy. NTFS permissions may be inherited. Windows services often run under specific service identities with differing rights. The Registry contains structured configuration; it is not a simple text file. The Event Log and optional Sysmon telemetry help reconstruct process, authentication, and system activity.

In Active Directory (AD), a **domain** groups identities and systems under a directory-based management boundary. A forest is a broader administrative and trust structure. Domain controllers support authentication and directory operations. Kerberos uses tickets; LDAP supports directory queries; Group Policy distributes many configuration settings. Roles, group nesting, service accounts, and delegation can create significant access paths.

### The central question: where does the identity come from?

A name appearing in an event does not by itself prove the identity of a human operator. Investigators correlate logon type, source system, session, process, account, timestamps, and administrative context. A service-account logon may be expected. Conversely, a valid account can be used improperly.

### Safe Windows inspection commands

Run on a Windows computer you administer, in PowerShell or Command Prompt as indicated:

```powershell
whoami /user
whoami /groups
whoami /priv
Get-LocalUser
Get-Service | Select-Object -First 12 Name,Status,StartType
Get-WinEvent -ListLog * | Select-Object -First 12 LogName
```

Some commands require permissions, or differ across Windows editions and installation configurations. `Get-LocalUser` is not a complete inventory of domain identities. Avoid exporting enterprise user lists or event logs to personal devices without written permission.

### Example: local file access

Use `icacls C:\Users\Public` to **inspect** a common location's access-control entries. Do not assume that a path being under `Public` makes everything writable. When reviewing an ACL, examine inheritance, group membership, applicable deny rules, and whether the process token actually receives the requested access.

## Lab 10 — Build a fictional trust-boundary table

Create three test identities: `alice` (analyst), `bob` (ordinary user), and `svc-report` (service identity). Define three resources: a synthetic report, a training portal, and a local log file. Write a matrix indicating read/write/admin access for each identity, then challenge each grant using least privilege. This is a **paper and JSON design exercise**, not a request to create domain accounts.

| Identity | Report | Portal | Log file |
|---|---|---|---|
| alice | Read | Admin for training | Read |
| bob | Own records only | Use | None |
| svc-report | Read required rows | Service API only | Append |

**Checkpoint:** Explain why Windows local administrator rights, domain administrative rights, and access to a specific application are different privileges.

---

# Module 11 — Cloud, containers, and supply-chain security {#m11}

**Level:** Analyst → Advanced · **Time:** 5–7 hours · **Outcome:** Recognize identity-first cloud risks and evaluate deployment configurations defensively.

Cloud services replace some hardware administration with APIs and provider-managed infrastructure. They do not eliminate the customer's responsibility for application configuration, identity, data, and workload security. The **shared responsibility model** depends on the exact service being used: infrastructure VMs, managed databases, and hosted applications have different boundaries.

## The few concepts worth memorizing

- **IAM principal:** An identity authorized to request actions, often a user, role, or service identity.
- **Policy:** Defines actions, resources, conditions, and effects (allow or deny). Explicit deny often overrides allow, but exact evaluation semantics are provider-specific.
- **Least privilege:** Grant only the actions and resources required, for as long as necessary.
- **Security group / firewall:** Restricts network reachability; it does not substitute for identity authorization.
- **Cloud audit trail:** Records relevant API and management actions, subject to logging configuration.
- **Container image:** Packaged filesystem and metadata for an application; it is not a standalone VM.
- **Kubernetes RBAC:** Controls allowed Kubernetes API operations; network policies and workload identities are separate concerns.
- **CI/CD:** Automated build and deployment process; secrets, dependencies, and permissions are key risk areas.

### Worked IAM case

A fictional policy allows `Action: "*"` and `Resource: "*"`. That is very broad authorization and deserves review. Yet a wildcard on a **resource string inside a restricted path**, such as `arn:aws:s3:::training-bucket/*`, does not have the same meaning as a fully unrestricted resource `*`. Read the entire policy and its conditions before deciding what it permits.

## Lab 11 — Review a synthetic cloud policy

```bash
python3 08_iam_policy.py
```

Expected: the first statement has no full-action/full-resource wildcard alert; the second is flagged for both. The checker is intentionally simple: real cloud authorization decisions involve condition keys, resource policies, organization policies, permission boundaries, sessions, and other factors. It is a training signal, not a comprehensive IAM analyzer.

### Container checklist for an approved environment

Inspect—not modify—an owned workload's configuration: Does it run as root? Is it privileged? Which directories and host sockets are mounted? Are secrets embedded in the image? Are capabilities, network access, resource limits, and update processes appropriate? Do not run unknown images privileged or mount the host Docker socket inside untrusted containers.

### Supply-chain checklist

Pin and verify dependencies where practical, restrict build secrets, separate build and deployment identities, review provenance, and have a rollback plan. A clean dependency scanner result is not proof that the source or build system is trustworthy.

**Checkpoint:** Distinguish application authorization, cloud IAM authorization, network restrictions, and container isolation. Describe a failure in one layer that the others cannot automatically prevent.

---

# Module 12 — Reverse engineering and binary analysis {#m12}

**Level:** Advanced · **Time:** 6–9 hours · **Outcome:** Analyze your own executable from file structure through observed behavior.

Reverse engineering means reconstructing how a program works from its executable behavior or compiled representation. It requires evidence and uncertainty management: decompilation is an approximation, compiler optimizations change instructions, and symbols may be missing. Never assume the first decompiler view is the original source.

![Reverse engineering workflow](diagrams/reverse.svg){width=100%}

*Figure 5. Safe progression for first-principles reverse engineering.*

### Minimum x86-64 register vocabulary

`RIP` is the instruction pointer, `RSP` is the stack pointer, `RAX` commonly carries return values, and general-purpose registers such as `RDI`, `RSI`, `RDX`, `RCX`, `R8`, and `R9` are used for early integer/pointer arguments in the common System V AMD64 calling convention. Windows x64 uses a different convention: the first four integer/pointer arguments are typically passed through `RCX`, `RDX`, `R8`, `R9`. Calling conventions are essential to interpreting arguments and return values.

### Static tools vs dynamic tools

| Tool | Typical question |
|---|---|
| `file` | What executable format is this likely to be? |
| `readelf` | What does an ELF header, section, or symbol table contain? |
| `objdump -d` | Which instructions are present? |
| `strings` | Which printable sequences are embedded? |
| Ghidra | What control flow and approximate high-level behavior can be reconstructed? |
| GDB | What does this self-built program do while executing? |

Never run an unknown sample merely because the file looks like an ELF or PE. Use a purpose-built isolated analysis environment, and begin with static inspection.

## Lab 12 — Compile, inspect, and explain your own program

Create `square.c`:

```c
#include <stdio.h>
int square(int x) { return x * x; }
int main(void) { printf("%d\n", square(7)); return 0; }
```

Compile **your own source** on a Linux lab system:

```bash
gcc -g -O0 -o square square.c
./square
file square
readelf -h square | head -n 25
objdump -d -M intel square | less
python3 09_elf_header.py square
```

Expected runtime output: `49`. The ELF inspector reads bytes from the file without executing it. Find the `square` symbol in the disassembly and identify where multiplication occurs. In GDB, use `break square`, `run`, `info registers`, `disassemble square`, and `quit` to inspect your compiled program. Build flags, architecture, compiler, and calling convention influence what you see.

### Researcher notebook

Record: file hash, exact build command, machine architecture, compiler version, expected input/output, function hypothesis, instruction evidence, GDB observation, and unresolved questions. A reproducible notebook is more important than memorizing one disassembler's interface.

**Checkpoint:** Why might a decompiler show an expression different from the original source, even when its behavior is equivalent? Why is an ELF header not proof of file safety?

---


# Module 13 — Memory safety, fuzzing, and bug triage {#m13}

**Level:** Advanced · **Time:** 5–7 hours · **Outcome:** Find and explain parser failures without turning a crash into an unsupported exploitation claim.

Programs that parse inputs must respect memory and type boundaries. Common bug classes include out-of-bounds reads/writes, use-after-free, integer-overflow mistakes, unsafe length calculations, and missing authorization. A **crash** may reveal a defect, but actual exploitability requires separate assessment of control, reachability, mitigations, environment, and user impact.

## The four-step research loop

1. Define the input format, invariants, and intended behavior. Example: a record begins with magic byte `0x52`, then an 8-bit payload length, then exactly that many bytes.
2. Write positive and negative tests: empty file, truncated header, extra data, maximum allowed length, and incorrect magic.
3. Run bounded randomized tests against *your own parser*, preserving seeds and inputs that cause unexpected behavior.
4. Minimize and explain any surprising failure; fix the root cause, add a regression test, and document limitations.

**Fuzzing** generates or mutates inputs to find unexpected behavior. Random bytes alone rarely exercise deep structured formats; coverage-guided fuzzers and grammars can be more effective. In this short guide, the goal is reproducible test discipline, not exploit payload construction.

### Defensive compilation

Modern C/C++ toolchains can enable stack protection, address randomization compatibility, hardened library checks, undefined-behavior checks, and sanitizers. These tools complement safe programming; they do not make a program immune to every bug. AddressSanitizer is powerful for detecting some memory safety defects in test environments but alters runtime behavior and is not a drop-in production security boundary.

## Lab 13 — Bounded fuzzing of a toy parser

```bash
python3 10_fuzz_frames.py
```

This deterministic script uses a fixed seed to generate 400 short byte strings. The parser accepts only the defined record shape. The expected output includes **zero unexpected exceptions**; most random inputs are rejected. A rejected invalid record is normal behavior, not a vulnerability. Record the seed, iteration count, accepted/rejected totals, and any exception.

### Challenge: meaningful test cases

Add the following three direct tests to your own copy:

```python
assert valid(bytes([0x52, 0]))
assert valid(bytes([0x52, 1, 0x41]))
assert not valid(bytes([0x52, 2, 0x41]))
```

Explain why the last input is invalid: its length byte says two payload bytes, but only one follows. Then change the parser to support up to 32 bytes; update the tests first, and document exactly what changed.

**Checkpoint:** Distinguish an expected parser rejection, a correctness bug, a confirmed memory-safety issue, and an exploitable vulnerability.

---

# Module 14 — Endpoint telemetry, detection, and incident response {#m14}

**Level:** Advanced · **Time:** 5–7 hours · **Outcome:** Turn events into a testable detection hypothesis and an evidence-based incident timeline.

Endpoint telemetry can include process creation, authentication events, file operations, network connections, script execution, and defensive-control status. Windows environments may use Event Logs and Sysmon; Linux can use the systemd journal, audit facilities, and approved observability tooling. Each source has coverage gaps, retention limits, permissions, and collection costs.

![Telemetry pipeline](diagrams/detect.svg){width=100%}

*Figure 6. Detection creates a signal for investigation; it does not prove adversary intent.*

## The useful detection pattern

A detection hypothesis should specify: **behavior → data fields → rule → threshold/window → expected false positives → validation → response**.

Example: “Three failed sign-ins for one identity within five minutes should create a review signal.” That is a useful classroom rule, but real systems also consider unique source addresses, account importance, shared-service behavior, preceding successful logons, and background authentication failures. Tuning must balance false positives and missed activity.

| Term | Meaning |
|---|---|
| Event | A recorded observation |
| Log | Persisted event representation |
| Detection | Rule or model identifies a pattern |
| Alert | Signal that a condition was met |
| Incident | Investigated event or series requiring response |
| False positive | Benign activity incorrectly flagged as harmful |
| False negative | Relevant activity not signaled by the chosen detection |

### Time and correlation

Timestamps must include timezone context. Events at `10:00+05:00` and `05:00Z` can represent the same instant. Sorting alone does not prove that one event caused another or that all observations share an actor. During incident response, preserve original data, document clock skew, limit access, and avoid contaminating evidence.

## Lab 14 — Detect and reconstruct a synthetic sequence

```bash
python3 11_detect_events.py
python3 12_timeline.py
```

The first script counts failed logins and flags Alice's three failures for review; Bob has only one. The second prints the fictional chronology. The example also includes a later successful sign-in for Alice. **You cannot conclude compromise:** this could represent a legitimate user mistyping a password before signing in. Correlate other sources before assigning intent.

### Incident response in six decisions

1. **Triage:** Is the alert accurate and within the response team's scope?
2. **Preserve:** Which volatile and persistent evidence matters, and how can it be collected lawfully?
3. **Scope:** What identities, devices, applications, and time intervals may be involved?
4. **Contain:** What is the least disruptive action that reduces immediate harm?
5. **Recover:** How is normal service restored and root cause addressed?
6. **Learn:** What detection, configuration, documentation, or process should change?

**Checkpoint:** State why a log is an observation, an alert is an interpretation, and an incident classification requires investigation.

---

# Module 15 — Threat-informed red and purple teaming {#m15}

**Level:** Advanced → Expert practice · **Time:** 4–6 hours · **Outcome:** Design a limited exercise with measurable defensive outcomes.

A mature red-team engagement begins with business risk, not an unrestricted tool list. It selects a relevant objective, models permitted adversary behaviors, obtains authorization, documents controls and stop conditions, and coordinates with people able to prevent harm. ATT&CK tactics explain the objective of an activity; techniques classify behavior; procedures describe observed implementations. The matrix is a **knowledge base**, not an ordered attack recipe.

### Mini scenario — Protect a reporting system

A fictional organization wants confidence that ordinary users cannot retrieve someone else's sensitive report, that attempted unauthorized access creates usable telemetry, and that defenders know what to do when repeated denials appear.

**Objective:** Validate record-level authorization and response workflow using synthetic records.

**Plan:**

| Part | Exercise specification |
|---|---|
| Scope | Localhost API and synthetic event files |
| Test | Alice requests Bob's record in the toy service |
| Expected control | Access denied with an appropriate status |
| Expected telemetry | Request identity, object ID, timestamp, outcome |
| Blue-team action | Investigate context and document classification |
| Stop condition | Any non-local endpoint or sensitive data appears |
| Success criterion | Control works, relevant event visible, report reproducible |

### Purple-team cycle

The red-side tester supplies a hypothesis and the observable behavior; the blue-side analyst checks whether it was seen and correctly interpreted. They agree on improvements, then **retest with the same conditions**. This is more meaningful than counting the number of tools executed or the number of alerts generated.

## Lab 15 — Three-layer validation

1. Run the local HTTP service and demonstrate 200 and 403 results.
2. Run the synthetic detection rule and explain why it signals review rather than compromise.
3. Produce a small report mapping the intended control to evidence and limitations.

Optional ATT&CK mapping should state precisely which observable behavior is simulated and why; do not assign a technique solely because its description sounds similar. If mapping is uncertain, mark it as a hypothesis.

### Measures that actually improve security

Control effectiveness, detection visibility, detection delay, evidence completeness, response decision quality, false-positive burden, and successful remediation retests. “100% ATT&CK coverage” is rarely a defensible standalone claim because coverage depends on specific sub-techniques, data sources, environments, and test depth.

**Checkpoint:** Why is an objective-led experiment better than running every available tool? What would prove that a detection improved after a purple-team session?

---

# Module 16 — Expert capstone, reporting, and next steps {#m16}

**Level:** Expert practice · **Time:** 8–12 hours · **Outcome:** Complete an evidence-based security study combining several disciplines.

Becoming an expert is not the same as finishing a reading list. The essential progression is **understand → reproduce → explain → improve → verify → teach**. A concise handbook can provide the route; expertise develops through repeated original analysis, review, and careful work in increasingly realistic environments.

## Capstone: The synthetic reporting application

You are responsible for evaluating a fictional reporting application and its operational controls, using only the included lab files and your local host. Work through the following sequence and preserve artifacts in a dedicated folder.

**Task A — Scope:** Write the Rules of Engagement: owner, allowed addresses, data, test window, stop conditions, storage, and cleanup. Run `01_scope_guard.py` as a sanity check.

**Task B — System evidence:** Record OS architecture and Python version. Inventory your own synthetic working directory and capture a SHA-256 manifest.

**Task C — API control:** Run `04_local_http.py` and `05_local_client.py`. Prove the intended 200/403 boundary without testing external systems. Explain why the `X-Demo-User` header is not true authentication.

**Task D — Identity and cloud:** Read `iam_policy.json` with `08_iam_policy.py`; write a least-privilege recommendation. Interpret the Windows identity/AD example from Module 10 at a design level.

**Task E — Analysis:** Compile and inspect your own `square.c`, and run the bounded parser fuzzer. Record actual evidence, not assumed exploitation.

**Task F — Detection:** Run the synthetic alert and timeline tools. Decide whether the evidence supports an incident classification or only a review signal.

**Task G — Report and retest:** Write a concise report with clear limitations, preventive and detective improvements, and a retest plan. Verify cleanup.

## Suggested final report structure

| Section | Include |
|---|---|
| Executive summary | Objective, systems, high-confidence outcomes, recommended next action |
| Authorization | Scope, dates, owner, permitted methods, safety boundaries |
| Environment | Host OS, tool versions, synthetic fixtures, network architecture |
| Tests | Hypothesis, commands, expected result, observed result |
| Findings | Supported condition, impact, evidence and confidence |
| Gaps | Missing telemetry, unsupported assumptions, untested paths |
| Recommendations | Owner, priority, least-change remedy, dependencies |
| Retest | Reproducible criteria and what success would look like |
| Cleanup | Services stopped, test assets removed, evidence retained appropriately |

### Portfolio scoring

Use `python3 13_report_score.py` to score five 20-point dimensions. The included JSON is a teaching example; update the `complete` fields only after you finish each task. Aim for at least 80/100, with no missed safety or authorization requirement. A passing score should not be treated as a professional accreditation.

## Learning sequence: first 12 weeks

| Weeks | Focus | Tangible outcome |
|---|---|---|
| 1–2 | Modules 1–3 | Scope file, command notebook, file manifest |
| 3–4 | Modules 4–6 | Local HTTP capture, Python helper, isolated lab design |
| 5–6 | Modules 7–9 | Asset worksheet, authorization tests, first finding report |
| 7–8 | Modules 10–11 | Windows identity matrix and synthetic IAM review |
| 9–10 | Modules 12–13 | Self-built binary analysis and reproducible parser tests |
| 11–12 | Modules 14–16 | Event investigation, purple-team retest, capstone portfolio |

For a deeper specialization, return to the original 120-chapter book. Reverse engineering: Modules 27–28. Enterprise identity: Modules 15–17. Web/API security: Modules 10–12. Red-team planning: Modules 23–25. Detection and reporting: Modules 26 and 29–30.

## Final self-check

Can you **demonstrate** a skill, explain its limits, describe relevant security controls, produce reproducible evidence, and communicate a responsible recommendation? If yes, you have built a sound professional foundation. If not, redo the lab rather than memorizing more commands.

---


# Essential Cheat Sheets {#sheets}

The following references are intended to be useful **during** lab work. Read the relevant module first; commands without context can be misleading. Unless noted otherwise, use them on your own host and your own synthetic files. Every externally addressed activity requires separate written authorization.

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

# Compact knowledge checks and answers {#review}

**1. What is the difference between authorization and authentication?** Authentication identifies the requester; authorization checks whether the identified requester may perform the action on the specific resource.

**2. Why does `127.0.0.1` matter?** It is the IPv4 loopback address; a service bound only to it is intended to accept local-host connections. Do not assume this makes all host data safe or that a service can't contain bugs.

**3. What does a SHA-256 hash prove?** Under suitable assumptions it strongly supports that compared bytes are equal; it does not establish trusted origin or absence of malware.

**4. Why is a VM snapshot not a full backup?** It can depend on the same disk, hypervisor, and files as the original VM.

**5. Why can a service on port 443 still be unsafe?** A port number does not guarantee the application, certificate validation, authorization, or safe handling of requests.

**6. Why is a 403 useful in the local API lab?** It demonstrates a denied access decision for that synthetic identity, record, and program path; broader coverage still requires more tests.

**7. What is a cloud wildcard-policy risk?** Broadly allowed actions/resources can exceed least privilege; actual effective permissions depend on policy evaluation and context.

**8. What is the first reverse-engineering step for an unknown executable?** Preserve identity and hash, inspect the format and architecture statically, and do not execute the file on an ordinary workstation.

**9. What is a reproducible fuzzing finding?** One with the exact input/seed, environment, observed unexpected behavior, and confirmed reproduction steps.

**10. Why isn't an alert always an incident?** A rule identifies a pattern; the analyst must investigate context, reliability, alternative explanations, and impact.

**11. What proves a retest improved a control?** Defined pre/post behavior measured with comparable test conditions, supported by relevant evidence.

**12. What is the point of the entire learning path?** To make technically sound, authorized decisions and communicate verifiable improvements—not simply to run more tools.

---

# References and further study {#refs}

These are starting points, not endorsements of any particular testing activity. Refer to current official documentation when implementing a technique or following legal requirements.

- **MITRE ATT&CK:** <https://attack.mitre.org/> — adversary behavior vocabulary and mapping.
- **OWASP Web Security Testing Guide:** <https://owasp.org/www-project-web-security-testing-guide/> — structured web security testing.
- **OWASP API Security Top 10:** <https://owasp.org/API-Security/> — API-specific risks.
- **NIST SP 800-115:** <https://csrc.nist.gov/pubs/sp/800/115/final> — technical security assessment planning.
- **NIST SP 800-61:** <https://csrc.nist.gov/pubs/sp/800/61/r3/final> — incident response guidance (verify current publication).
- **Linux manuals:** `man bash`, `man 2 open`, `man 5 proc`, `man 7 capabilities`.
- **Ghidra:** <https://ghidra-sre.org/> — reverse-engineering platform and training materials.
- **VirtualBox documentation:** <https://www.virtualbox.org/wiki/Documentation> — networking and virtual machine controls.
- **Kali Linux documentation:** <https://www.kali.org/docs/> — installation and system guidance.

**End of field guide.** Keep the complete 120-chapter volume for deep technical references, specialist research exercises, and advanced topics beyond this high-value learning route.
