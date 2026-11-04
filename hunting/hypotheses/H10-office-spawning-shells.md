---
id: H10
title: Office applications launching interpreters or LOLBins
techniques: [T1204.002, T1566.001]
tactics: [execution, initial-access]
platforms: [windows]
data_sources:
  - Sysmon EID 1 (process creation, with parent process)
index: wazuh-archives-*
emulation: []
---

# H10 · Office spawning shells or LOLBins

## Hypothesis

A user opens a malicious attachment (macro, OLE, remote template) and the Office
application creates a child process it normally never creates: `cmd`, `powershell`,
`wscript`, `mshta`, `rundll32`, `regsvr32`, `certutil`...

## Question

Which child processes have `WINWORD.EXE`, `EXCEL.EXE`, `POWERPNT.EXE`,
`OUTLOOK.EXE`, `MSACCESS.EXE`, `ONENOTE.EXE` or `MSPUB.EXE` created in the last 30 days that
are interpreters or execution proxy binaries?

## Data required

- **Sysmon EID 1**: `data.win.eventdata.parentImage`, `image`, `commandLine`,
  `parentCommandLine` (name of the opened document), `user`.
- `wazuh-archives-*` index.

## Query

### DQL (Wazuh Dashboard → Discover)

```dql
data.win.system.eventID:1 and data.win.eventdata.parentImage:(*WINWORD.EXE or *EXCEL.EXE or *POWERPNT.EXE or *OUTLOOK.EXE or *MSACCESS.EXE or *ONENOTE.EXE or *MSPUB.EXE) and data.win.eventdata.image:(*cmd.exe or *powershell.exe or *pwsh.exe or *wscript.exe or *cscript.exe or *mshta.exe or *rundll32.exe or *regsvr32.exe or *certutil.exe or *bitsadmin.exe)
```

### OpenSearch Query DSL

```json
{
  "size": 200,
  "sort": [{"timestamp": {"order": "desc"}}],
  "_source": ["timestamp", "agent.name", "data.win.eventdata.user", "data.win.eventdata.parentImage", "data.win.eventdata.parentCommandLine", "data.win.eventdata.image", "data.win.eventdata.commandLine"],
  "query": {
    "bool": {
      "filter": [
        {"range": {"timestamp": {"gte": "now-30d"}}},
        {"term": {"data.win.system.channel": "Microsoft-Windows-Sysmon/Operational"}},
        {"term": {"data.win.system.eventID": "1"}},
        {"bool": {"should": [
          {"wildcard": {"data.win.eventdata.parentImage": {"value": "*\\\\winword.exe", "case_insensitive": true}}},
          {"wildcard": {"data.win.eventdata.parentImage": {"value": "*\\\\excel.exe", "case_insensitive": true}}},
          {"wildcard": {"data.win.eventdata.parentImage": {"value": "*\\\\powerpnt.exe", "case_insensitive": true}}},
          {"wildcard": {"data.win.eventdata.parentImage": {"value": "*\\\\outlook.exe", "case_insensitive": true}}},
          {"wildcard": {"data.win.eventdata.parentImage": {"value": "*\\\\msaccess.exe", "case_insensitive": true}}},
          {"wildcard": {"data.win.eventdata.parentImage": {"value": "*\\\\onenote.exe", "case_insensitive": true}}},
          {"wildcard": {"data.win.eventdata.parentImage": {"value": "*\\\\mspub.exe", "case_insensitive": true}}}
        ], "minimum_should_match": 1}},
        {"bool": {"should": [
          {"wildcard": {"data.win.eventdata.image": {"value": "*\\\\cmd.exe", "case_insensitive": true}}},
          {"wildcard": {"data.win.eventdata.image": {"value": "*\\\\powershell.exe", "case_insensitive": true}}},
          {"wildcard": {"data.win.eventdata.image": {"value": "*\\\\pwsh.exe", "case_insensitive": true}}},
          {"wildcard": {"data.win.eventdata.image": {"value": "*\\\\wscript.exe", "case_insensitive": true}}},
          {"wildcard": {"data.win.eventdata.image": {"value": "*\\\\cscript.exe", "case_insensitive": true}}},
          {"wildcard": {"data.win.eventdata.image": {"value": "*\\\\mshta.exe", "case_insensitive": true}}},
          {"wildcard": {"data.win.eventdata.image": {"value": "*\\\\rundll32.exe", "case_insensitive": true}}},
          {"wildcard": {"data.win.eventdata.image": {"value": "*\\\\regsvr32.exe", "case_insensitive": true}}},
          {"wildcard": {"data.win.eventdata.image": {"value": "*\\\\certutil.exe", "case_insensitive": true}}},
          {"wildcard": {"data.win.eventdata.image": {"value": "*\\\\bitsadmin.exe", "case_insensitive": true}}},
          {"wildcard": {"data.win.eventdata.image": {"value": "*\\\\msbuild.exe", "case_insensitive": true}}}
        ], "minimum_should_match": 1}}
      ]
    }
  },
  "aggs": {
    "parent_child_pairs": {
      "terms": {"field": "data.win.eventdata.parentImage", "size": 10},
      "aggs": {"children": {"terms": {"field": "data.win.eventdata.image", "size": 10}}}
    }
  }
}
```

## Interpretation

- **What is suspicious**: almost everything. Office launching `powershell`, `mshta`, `wscript`,
  `regsvr32` or `rundll32` is one of the initial access indicators with the fewest false
  positives. Look at `parentCommandLine` to know which document caused it and at the
  `commandLine` of the child (downloads, H06; Base64, H01).
- **Common false positives**: corporate add-ins (email signatures, CRM,
  finance macros) that launch `cmd.exe` with fixed commands; Outlook opening
  links with `rundll32 url.dll`. The `parent_child_pairs` aggregations show the
  frequent pairs, which are usually the legitimate ones.
- **Next steps**: locate the document (attachment in the mailbox, `parentCommandLine`
  path), compute its hash and upload it to MISP; look for the same sender or
  attachment for other users; review the connections of the child (Sysmon EID 3) and the files
  it created (EID 11).
- **Validation**: there is no automatic scenario; with Office installed in the
  lab you can use the Atomic Red Team T1204.002 tests that launch macros.
