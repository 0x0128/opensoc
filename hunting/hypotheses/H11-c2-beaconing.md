---
id: H11
title: C2 beaconing over HTTP/HTTPS at regular intervals
techniques: [T1071.001]
tactics: [command-and-control]
platforms: [windows]
data_sources:
  - Sysmon EID 3 (outbound network connections)
  - Optionally, Suricata/Zeek integrated into Wazuh
index: wazuh-archives-*
emulation: []
---

# H11 · C2 beaconing

## Hypothesis

An implant (Cobalt Strike, Sliver, Mythic...) contacts its C2 server at
almost constant intervals (with little *jitter*), always from the same process and to the
same external destination, for hours or days.

## Question

In the last 24 hours, which (external destination IP, process) pairs have
connections spread regularly across most hours, on few hosts?

## Data required

- **Sysmon EID 3** with `Initiated=true`: `data.win.eventdata.destinationIp`,
  `destinationPort`, `destinationHostname`, `image`, `agent.name`. Sysmon
  configurations often filter EID 3 because of noise: make sure it does not exclude the
  processes you want to watch.
- Optional: Suricata (`data.dest_ip`, `data.tls.sni`) or Zeek for the same analysis
  on the network.
- `wazuh-archives-*` index.

## Query

### DQL (Wazuh Dashboard → Discover)

```dql
data.win.system.eventID:3 and data.win.eventdata.initiated:true and not data.win.eventdata.destinationIp:(10.* or 192.168.* or 127.* or 169.254.*)
```

### OpenSearch Query DSL

```json
{
  "size": 0,
  "query": {
    "bool": {
      "filter": [
        {"range": {"timestamp": {"gte": "now-24h"}}},
        {"term": {"data.win.system.channel": "Microsoft-Windows-Sysmon/Operational"}},
        {"term": {"data.win.system.eventID": "3"}},
        {"term": {"data.win.eventdata.initiated": "true"}}
      ],
      "must_not": [
        {"prefix": {"data.win.eventdata.destinationIp": "10."}},
        {"prefix": {"data.win.eventdata.destinationIp": "192.168."}},
        {"prefix": {"data.win.eventdata.destinationIp": "127."}},
        {"prefix": {"data.win.eventdata.destinationIp": "169.254."}},
        {"regexp": {"data.win.eventdata.destinationIp": "172\\.(1[6-9]|2[0-9]|3[01])\\..*"}},
        {"prefix": {"data.win.eventdata.destinationIp": "fe80:"}},
        {"term": {"data.win.eventdata.destinationIp": "::1"}}
      ]
    }
  },
  "aggs": {
    "destinations": {
      "terms": {"field": "data.win.eventdata.destinationIp", "size": 30, "min_doc_count": 12},
      "aggs": {
        "processes": {
          "terms": {"field": "data.win.eventdata.image", "size": 3},
          "aggs": {
            "by_hour": {"date_histogram": {"field": "timestamp", "fixed_interval": "1h", "min_doc_count": 0}},
            "regularity": {"extended_stats_bucket": {"buckets_path": "by_hour>_count"}},
            "hosts": {"cardinality": {"field": "agent.name"}},
            "ports": {"terms": {"field": "data.win.eventdata.destinationPort", "size": 3}},
            "names": {"terms": {"field": "data.win.eventdata.destinationHostname", "size": 3}}
          }
        }
      }
    }
  }
}
```

## Interpretation

- **How to read it**: for each destination and process, `regularity` gives statistics of the
  number of connections per hour:
  - `count` ≈ number of hours with activity (up to 24): a beacon is active almost
    every hour, even at night.
  - **Coefficient of variation** = `std_deviation / avg`. Below ~0.5 the
    connections per hour are very steady → beacon candidate. A user
    browsing produces peaks (high CV) and gaps at night.
  - `hosts` = 1-2 → something specific to those hosts; a legitimate service usually
    appears across the whole fleet.
- **What is suspicious**: processes that should not talk to the Internet (`rundll32`,
  `regsvr32`, `powershell`, binaries in `%APPDATA%`/`%TEMP%`), destinations without a name
  (empty `names`) or in VPS ASNs, non-standard ports.
- **Common false positives**: updaters, telemetry, sync
  clients (OneDrive, Teams), EDR agents and NTP. Build an allow list
  by signed `image` + domain.
- **Next steps**: for the candidate, pull the full series of connections and
  compute the interval between them (the implant *sleep*); look for the binary
  (Sysmon EID 1/11), the persistence (H03/H04/H05) and share the IP/domain in MISP.
- **Limitations**: with high *jitter* or a *sleep* of hours this method is not enough; widen
  the window (`--from now-7d`) and the histogram interval to 6 h.
