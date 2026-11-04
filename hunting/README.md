# OpenSOC · Threat hunting

> **For your own lab only.** The emulation scenarios execute real attack
> techniques (LSASS dumping, persistence, log clearing...). Use them
> only on hosts that belong to you and are isolated. By default everything runs in
> dry-run mode, and real execution is only allowed against the hosts declared in
> `OPENSOC_LAB_TARGETS`.

This directory brings together three pieces that support each other:

| Piece | What it does | Command |
|---|---|---|
| [Emulation](#1-emulation-with-atomic-red-team) | 10 Atomic Red Team scenarios; it launches them and checks in the Wazuh Indexer whether the detection fired | `opensoc-emulate` |
| [Hypotheses](#2-threat-hunting-hypotheses) | 15 documented hypotheses, each with its question, the data required, the DQL + Query DSL query and how to interpret the result | `opensoc-hunt` |
| [IOCs](#3-iocs-stix-21--csv--misp) | Imports and exports IOCs as STIX 2.1 and CSV against MISP, and generates the sweep query for Wazuh | `opensoc-ioc` |

```
hunting/
├── emulation/scenarios.yaml      # catalog of the 10 scenarios
├── hypotheses/H01-…H15-*.md      # 15 hypotheses (Markdown + YAML front matter)
├── examples/                     # sample IOCs (CSV and STIX 2.1)
├── opensoc_hunting/              # Python code
│   ├── emulation/                #   runner, Invoke-AtomicTest executor, alert checking
│   ├── ioc/                      #   IOC model, CSV, STIX 2.1, MISP client, CLI
│   ├── hunts.py                  #   hypothesis reader and runner
│   └── opensearch.py             #   minimal Wazuh Indexer client
└── tests/                        # pytest; MISP, the indexer and PowerShell are simulated with mocks
```

## Installation

Python 3.10 or later is required.

```bash
cd hunting
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env    # edit the lab URLs and credentials
set -a; . ./.env; set +a
```

To run the scenarios (not for the tests), the host you launch the
emulation from also needs:

- **PowerShell 7** (`pwsh`), or Windows PowerShell 5.1 with `--shell powershell.exe`.
- **Invoke-AtomicRedTeam** and the `atomics/` folder
  (`Install-Module invoke-atomicredteam` + `Install-AtomicRedTeam -getAtomics`). If you
  install them in a non-standard path, use `--module <path>/Invoke-AtomicRedTeam.psd1` and
  `--atomics-path <path>/atomics`.
- To run on another host: PowerShell remoting over SSH (`--session-host`,
  `--session-user`, key authentication) or WinRM (`--transport winrm`).

| Variable | Use |
|---|---|
| `WAZUH_INDEXER_URL`, `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASSWORD` | Access to the Wazuh Indexer (OpenSearch) |
| `WAZUH_INDEXER_CA` / `WAZUH_INDEXER_INSECURE=1` | Lab CA / disable TLS verification (lab only) |
| `WAZUH_INDEXER_INDEX`, `WAZUH_INDEXER_TIME_FIELD` | Default `wazuh-alerts-*` and `timestamp` |
| `OPENSOC_LAB_TARGETS` | List of `agent.name` values on which `--execute` is allowed |
| `MISP_URL`, `MISP_KEY` | MISP. The key is **only** read from the environment, never as an argument |
| `MISP_CA_BUNDLE` / `MISP_INSECURE=1` | MISP TLS |

---

## 1. Emulation with Atomic Red Team

### Scenarios

Tests are selected by GUID (Atomic Red Team `auto_generated_guid`), which
stays the same even if ART renumbers the tests. Every GUID and name has been checked
against the current `redcanaryco/atomic-red-team` repository.

| ID | OS | Technique | Atomic Red Team test | GUID | Hypothesis |
|---|---|---|---|---|---|
| EMU-01 | Windows | T1059.001 PowerShell | PowerShell Command Execution | `a538de64-1c74-46ed-aa60-b995ed302598` | H01 |
| EMU-02 | Windows | T1003.001 LSASS Memory | Dump LSASS.exe Memory using comsvcs.dll | `2536dee2-12fb-459a-8c37-971844fa73be` | H02 |
| EMU-03 | Windows | T1053.005 Scheduled Task | Scheduled Task Startup Script | `fec27f65-db86-4c2d-b66c-61945aee87c2` | H04 |
| EMU-04 | Windows | T1547.001 Registry Run Keys | Reg Key Run | `e55be3fd-3521-4610-9d1a-e210e42dcf05` | H03 |
| EMU-05 | Windows | T1685.005 Clear Windows Event Logs (formerly T1070.001) | Clear Logs ⚠ irreversible | `e6abb60e-26b8-41da-8aae-0c35174b0967` | H07 |
| EMU-06 | Windows | T1105 Ingress Tool Transfer | certutil download (urlcache) | `dd3b61dd-7bbc-48cd-ab51-49ad1a776df0` | H06 |
| EMU-07 | Linux | T1136.001 Local Account | Create a user account on a Linux system | `40d8eabd-e394-46f6-8785-b9bfa1d011d2` | H12 |
| EMU-08 | Linux | T1053.003 Cron | Cron - Add script to /etc/cron.d folder | `078e69eb-d9fb-450e-b9d0-2e118217c846` | H13 |
| EMU-09 | Linux | T1098.004 SSH Authorized Keys | Modify SSH Authorized Keys | `342cc723-127c-4d3a-8292-9c0c6b4ecadc` | H13 |
| EMU-10 | Linux | T1543.002 Systemd Service | Create Systemd Service | `d9e4f24f-aa67-4c6e-bcbf-85622b697a7c` | H13 |

In `emulation/scenarios.yaml` each scenario also lists the telemetry it generates and
the lab requirements (Sysmon EID 10 for lsass, real-time FIM for cron and
systemd, etc.).

> **ATT&CK renumbered.** The current version of ATT&CK (and of Atomic Red Team) moved
> *Clear Windows Event Logs* from T1070.001 to **T1685.005**, under the new
> *defense-impairment* tactic. The Wazuh ruleset and many custom rules still use the old
> ID, so the scenario declares `technique_aliases: [T1070.001]` and the check
> looks for both.

### How the detection check works

For each scenario, `opensoc-emulate run --execute`:

1. (Optional, `--prereqs`) runs `Invoke-AtomicTest … -GetPrereqs`.
2. Records the start time minus a 30 s margin in case the clocks are
   skewed (`--clock-skew`).
3. Runs `Invoke-AtomicTest <technique> -TestGuids <guid> [-InputArgs …] [-Session $s]`.
4. Queries `wazuh-alerts-*` every 15 s, for at most `detection.timeout`
   seconds (180 by default and 300 in the scenarios that depend on FIM;
   `--detection-timeout` changes it for all of them), looking for
   alerts of the target agent (`agent.name`/`agent.id`) within the window with
   `rule.level ≥ 3` and with
   - `rule.mitre.id` equal to the technique or to one of its aliases, **or**
   - `rule.id` equal to one of the `/detections` rules for that technique, or to one of
     the scenario `detection.rule_ids`.
5. Runs `Invoke-AtomicTest … -Cleanup`, also when the check has failed.
6. Writes a JSON + Markdown report into `reports/`, which is in `.gitignore`.

| Result | Meaning |
|---|---|
| `DETECTED` | At least one alert that meets the criteria arrived. With `--strict`, it has to be a `/detections` rule (or one of `rule_ids`) |
| `MISSED` | No alert arrived before the timeout |
| `EXEC_ERROR` | Invoke-AtomicTest failed and no alert arrived (if one arrives, the result is `DETECTED`) |
| `CHECK_ERROR` | The indexer could not be queried |
| `SKIPPED` | The scenario is irreversible and `--allow-irreversible` was not passed |
| `DRY_RUN` | Dry-run mode: the scripts are only displayed |

The exit code is 1 if any scenario ends in `MISSED`, `EXEC_ERROR` or
`CHECK_ERROR`, so you can use it in a detection regression pipeline.

### Relationship with `/detections`

When `/detections` does not exist, the check relies on the `rule.mitre.id` set by the
Wazuh ruleset, and the scenarios are mapped by ATT&CK technique ID. As soon as it exists,
it is used automatically:

- **Wazuh XML** rules (`<rule id="…">` with `<mitre><id>T…</id></mitre>`),
  **Sigma** rules (`tags: attack.tXXXX`) and any `.yml/.yaml/.json/.toml/.xml`
  that mentions technique IDs are recognized. `.md` files are ignored, so that a README with a list of
  techniques does not count as coverage. A rule mapped to the parent technique (T1053) covers
  the sub-technique (T1053.003).
- The `rule.id` values of the Wazuh rules it finds are added to the query.
  `--strict` requires one of them to fire, not a generic rule.
- `opensoc-emulate coverage [--fail-on-gap]` shows which scenarios do or do not have a
  rule in `/detections`.
- The `test_each_scenario_has_a_detection_in_detections` test is enabled as soon as
  `/detections` appears and fails if any scenario is left without a rule.

### Usage

```bash
opensoc-emulate list                       # scenarios, techniques and GUIDs
opensoc-emulate coverage                   # cross-check with /detections
opensoc-emulate run --target win10-lab --platform windows --all      # dry run: only prints the scripts
```

```bash
# Real local execution (the control host is the target itself)
export OPENSOC_LAB_TARGETS=win10-lab,ubuntu-lab
opensoc-emulate run --target win10-lab -s EMU-01 -s EMU-04 --execute
```

```bash
# Remote execution over SSH against a lab Linux host, with prerequisites
opensoc-emulate run --target ubuntu-lab --platform linux --all --execute --prereqs \
  --session-host ubuntu-lab.lab.local --session-user purple
```

```bash
# Lab without Internet: change the EMU-06 download URL
opensoc-emulate run --target win10-lab -s EMU-06 --execute \
  --input-arg EMU-06.remote_file=http://server.lab.local:8000/file.txt
```

```bash
# Irreversible scenario (clears the System log) and strict check against /detections
opensoc-emulate run --target win10-lab -s EMU-05 --execute --allow-irreversible --strict
```

```bash
# Check only, if the test was launched by hand
opensoc-emulate check --target win10-lab -s EMU-02 --since 2026-11-04T10:15:00Z
```

**Safeguards:** without `--execute` nothing runs. `--execute` refuses to run if the
target is not in `OPENSOC_LAB_TARGETS`, or if the variable is empty. Scenarios
without cleanup are skipped unless `--allow-irreversible` is given. Cleanup always runs,
unless `--no-cleanup` is given.

---

## 2. Threat hunting hypotheses

| ID | Hypothesis | Techniques | Index | Scenario |
|---|---|---|---|---|
| [H01](hypotheses/H01-encoded-powershell.md) | Encoded or obfuscated PowerShell | T1059.001, T1027 | archives | EMU-01 |
| [H02](hypotheses/H02-lsass-memory-access.md) | LSASS memory access | T1003.001 | archives | EMU-02 |
| [H03](hypotheses/H03-run-key-persistence.md) | Persistence in Run/RunOnce and Winlogon | T1547.001 | archives | EMU-04 |
| [H04](hypotheses/H04-scheduled-tasks.md) | Suspicious scheduled tasks | T1053.005 | archives | EMU-03 |
| [H05](hypotheses/H05-new-services.md) | New services with binaries in writable paths | T1543.003 | archives | — |
| [H06](hypotheses/H06-lolbin-downloads.md) | LOLBins downloading files | T1105 | archives | EMU-06 |
| [H07](hypotheses/H07-event-log-clearing.md) | Event log clearing | T1685.005 (T1070.001) | archives | EMU-05 |
| [H08](hypotheses/H08-brute-force-spraying.md) | Brute force and password spraying | T1110.001, T1110.003 | alerts | — |
| [H09](hypotheses/H09-lateral-movement.md) | Lateral movement over RDP/SMB | T1021.001, T1021.002 | archives | — |
| [H10](hypotheses/H10-office-spawning-shells.md) | Office spawning shells or LOLBins | T1204.002, T1566.001 | archives | — |
| [H11](hypotheses/H11-c2-beaconing.md) | C2 beaconing at regular intervals | T1071.001 | archives | — |
| [H12](hypotheses/H12-new-local-accounts.md) | New or privileged local accounts | T1136.001, T1098 | archives | EMU-07 |
| [H13](hypotheses/H13-linux-persistence-fim.md) | Linux persistence seen by FIM | T1053.003, T1543.002, T1098.004, T1574.006 | alerts | EMU-08/09/10 |
| [H14](hypotheses/H14-execution-from-tmp.md) | Execution from /tmp, /dev/shm, /var/tmp | T1059.004 | archives | — |
| [H15](hypotheses/H15-misp-ioc-sweep.md) | Retrospective sweep of MISP IOCs | T1071.001, T1105 | archives | — |

Each document has the sections **Hypothesis**, **Question**, **Data required**,
**Query** (a `dql` block for Discover and a `json` block with Query DSL) and
**Interpretation** (what is suspicious, common false positives, next steps and
how to validate it with the matching emulation scenario).

```bash
opensoc-hunt list
opensoc-hunt show H11                     # DQL + Query DSL
opensoc-hunt run H08                      # runs against the indexer and summarizes hits and aggregations
opensoc-hunt run H09 --from now-14d --to now-7d   # changes the time window (replaces the "timestamp" range)
opensoc-hunt run H01 --index wazuh-alerts-*       # if you have no archives index
opensoc-hunt validate                     # checks the format and JSON of all 15
```

Notes for reading the queries:

- **`wazuh-archives-*` versus `wazuh-alerts-*`.** `wazuh-alerts-*` only holds the
  events that fired a rule. To hunt over the full telemetry (Sysmon,
  auditd...) you need to enable `<logall_json>yes</logall_json>` on the manager and the archives
  index in Filebeat. The hypotheses based on alerts (H08, authentication
  failures; H13, FIM) use `wazuh-alerts-*`.
- The `data.win.eventdata.*`, `data.audit.*` and `syscheck.*` fields are `keyword`. The
  JSON queries use `wildcard` with `case_insensitive: true`, whereas in DQL
  wildcards **are case-sensitive**. In `wildcard` values the backslash is
  written twice (`*\\\\lsass.exe` in JSON). A test checks that escaping.
- If a very long field (e.g. `scriptBlockText`) exceeds the `ignore_above` of the
  template, it is not indexed as a keyword. In that case search in `full_log`.

---

## 3. IOCs: STIX 2.1 + CSV ⇄ MISP

```bash
opensoc-ioc ping                                                      # connection and API key
opensoc-ioc export --tag tlp:amber --last 30d --to-ids-only -o iocs.json   # MISP -> STIX 2.1
opensoc-ioc export --event-id 42 -f csv --defang -o iocs.csv          # MISP -> CSV (hxxp, [.])
opensoc-ioc import iocs.csv --event-info "Purple team exercise 2026-11" --tlp amber --dry-run
opensoc-ioc import report.stix.json --event-id 42                     # adds to an existing event, without duplicates
opensoc-ioc convert examples/iocs-example.csv iocs.json               # CSV <-> STIX without touching MISP
opensoc-ioc validate iocs.csv
opensoc-ioc hunt-query iocs.csv --since now-30d > h15.json            # sweep query for hypothesis H15
```

**Export** queries `/attributes/restSearch` with pagination (filters `--event-id`,
`--tag`, `--type`, `--last`, `--to-ids-only`, `--published-only`). Composite
types (`domain|ip`, `filename|sha256`, `ip-dst|port`...) are split into their parts,
unsupported types are counted and reported, and duplicates are merged.

**Import** creates an event (`/events/add`, with distribution 0 = your
organization only by default) or adds attributes to an existing event
(`/attributes/add/{id}`). Before adding, it queries the attributes the event already
has, and treats the 403 *"A similar attribute already
exists"* response as a duplicate. If any row is invalid nothing is imported, unless `--skip-invalid` is given.
`--publish` publishes the event at the end. Always use `--dry-run` the first time.

### CSV format

```
type,value,description,tags,tlp,confidence,first_seen,source,to_ids
ipv4,203.0.113.45,C2 of the exercise,lab;c2,amber,80,2026-11-01T09:00:00Z,OpenSOC exercise,true
```

- Only `value` is required. Without `type`, the type is inferred from the value (IP, hash by
  length, URL, email, domain or file name). When it is ambiguous, fill in `type`: for
  example, `update.zip` is taken as a file name even though `.zip` is also a TLD.
- *Defanged* values (`hxxp`, `[.]`, `[@]`) are normalized on import.
- Tags separated by `;`. `tlp` accepts `clear` (or `white`), `green`, `amber`,
  `amber+strict` and `red`.
- On CSV export formula injection is neutralized (cells that start with
  `= + - @` get a leading `'`), and it is removed on import, so the round trip does not
  lose anything.

### Type mapping

| Type | STIX 2.1 pattern | MISP attribute (category) |
|---|---|---|
| ipv4 / ipv6 (or CIDR) | `[ipv4-addr:value = '…']` / `[ipv6-addr:value = '…']` | `ip-dst` (or `--ip-type ip-src`) · Network activity |
| domain / hostname | `[domain-name:value = '…']` | `domain` / `hostname` · Network activity |
| url | `[url:value = '…']` | `url` · Network activity |
| email | `[email-addr:value = '…']` | `email-src` · Payload delivery |
| md5 / sha1 / sha256 | `[file:hashes.MD5 = '…']`, `'SHA-1'`, `'SHA-256'` | `md5` / `sha1` / `sha256` · Payload delivery |
| filename | `[file:name = '…']` | `filename` · Payload delivery |

STIX 2.1 details:

- Every bundle carries an `identity` (`--producer`) and the TLP `marking-definition` objects
  predefined by the specification. TLP 2.0 `amber+strict` has no predefined
  marking, so it is marked as TLP:AMBER and the `tlp:amber+strict` label
  is kept.
- IOCs with `to_ids=true` are exported as `indicator`, with a UUIDv5 ID of
  (type, value): the same IOC always has the same ID. IOCs with `to_ids=false`
  are exported as `observed-data` + SCO, as MISP does, and their description goes in a
  `note`.
- On import, compound patterns are accepted (`OR`/`AND`, from which each
  observable is extracted), as well as `network-traffic:dst_ref.value`, `observed-data`, standalone SCOs and TLP 2.0
  by name. Revoked indicators are discarded, expired ones (`valid_until`) are
  imported with `to_ids=false`, and operators other than `=` (`LIKE`, `MATCHES`...) are
  ignored with a warning.
- The CSV → STIX → CSV round trip does not lose data (a test checks it), except that
  `hostname` comes back as `domain` and that an IOC without a source gets the bundle
  producer as its source. `confidence` is not sent to MISP, because MISP attributes
  do not have that field.
- The tests validate the generated bundles with the official OASIS `stix2` library
  (`stix2.parse(..., allow_custom=False)`), including the pattern syntax.

---

## Tests

```bash
cd hunting
pip install -e ".[dev]"
pytest            # 162 tests; MISP, the Wazuh Indexer and pwsh are simulated
ruff check .      # optional
```

They cover:

- **Catalog**: the 10 scenarios, valid GUIDs and techniques, the scenario ⇄ hypothesis
  cross-reference in both directions and the `/detections` coverage (the latter
  is skipped while `/detections` does not exist).
- **Executor**: the generated PowerShell script, including quote escaping against
  injection in `InputArgs`, `-EncodedCommand` and SSH/WinRM sessions.
- **Runner**: detected, not detected, timeout, execution failure, indexer error,
  `--strict`, irreversible scenarios, blocking of hosts outside the lab, cleanup and
  reports. It uses a fake clock, so there are no real waits.
- **Hypotheses**: document structure, valid JSON, `wildcard` escaping,
  replacement of the time window and that H15 matches the output of
  `hunt-query` exactly.
- **IOCs**: normalization, CSV, STIX 2.1 (validated with `stix2`) and the MISP client against a
  simulated API (pagination, composite types, duplicates, 403/500 errors, dry-run),
  plus the CLIs.

## Limitations and assumptions

- The field names are those of the Windows decoder (`data.win.*`) and of the Wazuh 4.x auditd/FIM
  decoders. If your lab uses other decoders (or Suricata/Zeek with other names),
  adjust the queries.
- The `rule.mitre.id` used as a criterion depends on the rules (those of the ruleset
  or of `/detections`) carrying the `<mitre>` block. If a custom rule does not carry it,
  add its ID to `detection.rule_ids` in the scenario.
- Atomic Red Team evolves. If a GUID no longer exists in your copy of `atomics/`,
  `Invoke-AtomicTest` runs nothing and the scenario ends in `EXEC_ERROR`/`MISSED`.
  Update `atomics/` or the catalog.
- The MISP client uses the REST API directly (without PyMISP). It has been tested with mocks and
  against a simulated server, not against a real MISP instance.
