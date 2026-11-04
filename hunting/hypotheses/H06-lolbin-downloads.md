---
id: H06
title: System binaries (LOLBins) used to download tools
techniques: [T1105]
tactics: [command-and-control]
platforms: [windows]
data_sources:
  - Sysmon EID 1 (process creation)
  - Sysmon EID 3 (network connections)
index: wazuh-archives-*
emulation: [EMU-06]
---

# H06 · LOLBins downloading files

## Hypothesis

An attacker uses signed Windows binaries (`certutil`, `bitsadmin`, PowerShell,
`curl.exe`, `regsvr32`, `mshta`) to download their next stage without bringing
their own tools.

## Question

Which executions of `certutil -urlcache/-verifyctl`, `bitsadmin /transfer`,
`Invoke-WebRequest`, `DownloadFile`, `Start-BitsTransfer`, `curl/wget` or
`regsvr32 /i:http` have there been in the last 7 days, and to which URL or IP?

## Data required

- **Sysmon EID 1**: `image`, `commandLine`, `parentImage`, `user`.
- **Sysmon EID 3**: `destinationIp`, `destinationHostname`, `destinationPort` to
  confirm the connection of the LOLBin.
- `wazuh-archives-*` index.

## Query

### DQL (Wazuh Dashboard → Discover)

```dql
data.win.system.eventID:1 and ((data.win.eventdata.image:*\\certutil.exe and data.win.eventdata.commandLine:(*urlcache* or *verifyctl*)) or (data.win.eventdata.image:*\\bitsadmin.exe and data.win.eventdata.commandLine:*transfer*) or data.win.eventdata.commandLine:(*Invoke-WebRequest* or *DownloadFile* or *Start-BitsTransfer* or *Net.WebClient*))
```

### OpenSearch Query DSL

```json
{
  "size": 200,
  "sort": [{"timestamp": {"order": "desc"}}],
  "_source": ["timestamp", "agent.name", "data.win.system.eventID", "data.win.eventdata.user", "data.win.eventdata.parentImage", "data.win.eventdata.image", "data.win.eventdata.commandLine", "data.win.eventdata.destinationIp", "data.win.eventdata.destinationHostname", "data.win.eventdata.destinationPort"],
  "query": {
    "bool": {
      "filter": [
        {"range": {"timestamp": {"gte": "now-7d"}}},
        {"term": {"data.win.system.channel": "Microsoft-Windows-Sysmon/Operational"}}
      ],
      "should": [
        {"bool": {"filter": [
          {"term": {"data.win.system.eventID": "1"}},
          {"bool": {"should": [
            {"bool": {"filter": [
              {"wildcard": {"data.win.eventdata.image": {"value": "*\\\\certutil.exe", "case_insensitive": true}}},
              {"bool": {"should": [
                {"wildcard": {"data.win.eventdata.commandLine": {"value": "*urlcache*", "case_insensitive": true}}},
                {"wildcard": {"data.win.eventdata.commandLine": {"value": "*verifyctl*", "case_insensitive": true}}}
              ], "minimum_should_match": 1}}
            ]}},
            {"bool": {"filter": [
              {"wildcard": {"data.win.eventdata.image": {"value": "*\\\\bitsadmin.exe", "case_insensitive": true}}},
              {"wildcard": {"data.win.eventdata.commandLine": {"value": "*/transfer*", "case_insensitive": true}}}
            ]}},
            {"wildcard": {"data.win.eventdata.commandLine": {"value": "*invoke-webrequest*", "case_insensitive": true}}},
            {"wildcard": {"data.win.eventdata.commandLine": {"value": "*iwr *http*", "case_insensitive": true}}},
            {"wildcard": {"data.win.eventdata.commandLine": {"value": "*downloadfile*", "case_insensitive": true}}},
            {"wildcard": {"data.win.eventdata.commandLine": {"value": "*start-bitstransfer*", "case_insensitive": true}}},
            {"wildcard": {"data.win.eventdata.commandLine": {"value": "*net.webclient*", "case_insensitive": true}}},
            {"wildcard": {"data.win.eventdata.commandLine": {"value": "*regsvr32*/i:http*", "case_insensitive": true}}},
            {"bool": {"filter": [
              {"bool": {"should": [
                {"wildcard": {"data.win.eventdata.image": {"value": "*\\\\curl.exe", "case_insensitive": true}}},
                {"wildcard": {"data.win.eventdata.image": {"value": "*\\\\wget.exe", "case_insensitive": true}}}
              ], "minimum_should_match": 1}},
              {"wildcard": {"data.win.eventdata.commandLine": {"value": "*http*", "case_insensitive": true}}}
            ]}}
          ], "minimum_should_match": 1}}
        ]}},
        {"bool": {"filter": [
          {"term": {"data.win.system.eventID": "3"}},
          {"bool": {"should": [
            {"wildcard": {"data.win.eventdata.image": {"value": "*\\\\certutil.exe", "case_insensitive": true}}},
            {"wildcard": {"data.win.eventdata.image": {"value": "*\\\\bitsadmin.exe", "case_insensitive": true}}},
            {"wildcard": {"data.win.eventdata.image": {"value": "*\\\\regsvr32.exe", "case_insensitive": true}}},
            {"wildcard": {"data.win.eventdata.image": {"value": "*\\\\mshta.exe", "case_insensitive": true}}}
          ], "minimum_should_match": 1}}
        ]}}
      ],
      "minimum_should_match": 1
    }
  }
}
```

## Interpretation

- **What is suspicious**: any `certutil -urlcache` (it is almost never legitimate on
  user workstations); downloads to `%TEMP%`, `%APPDATA%` or `C:\Users\Public`; URLs to IPs
  without a domain, to paste services (pastebin, transfer.sh) or to newly
  registered domains; the LOLBin launched by Office, `wscript`, `mshta` or a service.
- **Common false positives**: deployment scripts that use
  `Invoke-WebRequest`/`curl.exe` against internal repositories; `bitsadmin` from
  old updaters. Group by destination domain and document the internal ones.
- **Next steps**: extract the URL and the destination file, look for its creation
  (Sysmon EID 11) and its later execution (EID 1); add the URL/IP/hash to MISP with
  `opensoc-ioc import` and sweep the rest of the fleet (H15).
- **If nothing shows up**: run EMU-06 (in an isolated lab point `remote_file`
  to an internal HTTP server with `--input-arg`).
