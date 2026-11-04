---
id: H15
title: Retrospective sweep of MISP IOCs over the Wazuh telemetry
techniques: [T1071.001, T1105]
tactics: [command-and-control]
platforms: [windows, linux]
data_sources:
  - Sysmon EID 3 and 22 (connections and DNS queries)
  - Suricata (dest_ip, dns.rrname, tls.sni, http.hostname)
  - Wazuh FIM (file hashes) and Sysmon EID 1 (Hashes)
  - IOCs exported from MISP with opensoc-ioc
index: wazuh-archives-*
emulation: []
---

# H15 · Retrospective sweep of MISP IOCs

## Hypothesis

Some IOCs that are in MISP today (from feeds, from our own incidents or from the
lab exercises) already showed up on the network **before** they were known. If they are
searched for backwards in the telemetry, the hosts that contacted that
infrastructure or ran those files show up.

## Question

Has any host resolved, connected to or executed, in the last 30 days, any IP,
domain, URL or hash flagged as `to_ids` in MISP? Which hosts, and when was the
first time?

## Data required

- MISP IOCs exported with the tool in this directory:
  ```
  opensoc-ioc export --tag tlp:amber --last 30d --to-ids-only -o iocs.csv
  opensoc-ioc hunt-query iocs.csv --since now-30d > h15.json
  ```
  `hunt-query` generates a query like the one below with the real IOCs, spread
  across the fields where each type appears.
- Fields used: IPs in `data.srcip`, `data.dstip`, `data.src_ip`, `data.dest_ip`,
  `data.win.eventdata.destinationIp`/`sourceIp`/`ipAddress`; domains in
  `data.win.eventdata.queryName` (Sysmon EID 22), `destinationHostname`,
  `data.dns.rrname`, `data.http.hostname`, `data.tls.sni`; hashes in
  `syscheck.*_after` and `data.win.eventdata.hashes` (Sysmon stores
  `SHA256=...,MD5=...` in a single field, which is why it uses `wildcard`).
- `wazuh-archives-*` index.

## Query

### DQL (Wazuh Dashboard → Discover)

```dql
data.win.eventdata.destinationIp:"203.0.113.45" or data.dest_ip:"203.0.113.45" or data.win.eventdata.queryName:"update-checker.example" or data.dns.rrname:"update-checker.example" or syscheck.sha256_after:"4f0c0fbb3a1e0b8b1e3a0c6c1a4e5d1d9a1f4b8f2e7f5b6c1d0a9e8f7a6b5c4d"
```

### OpenSearch Query DSL

It is the output of `opensoc-ioc hunt-query examples/iocs-example.csv --since now-30d`
(IOCs with `to_ids=false`, emails and file names are left out by
default; see `--all` and `--include-filenames`). For real use, generate the JSON
with `opensoc-ioc hunt-query` and run it with
`curl -s -u "$WAZUH_INDEXER_USER" -H 'Content-Type: application/json' "$WAZUH_INDEXER_URL/wazuh-archives-*/_search" -d @h15.json`.

```json
{
  "size": 200,
  "sort": [{"timestamp": {"order": "desc"}}],
  "_source": ["timestamp", "agent.name", "rule.id", "rule.description", "location", "data", "syscheck.path"],
  "query": {
    "bool": {
      "filter": [{"range": {"timestamp": {"gte": "now-30d"}}}],
      "should": [
        {"terms": {"data.srcip": ["203.0.113.45"]}},
        {"terms": {"data.dstip": ["203.0.113.45"]}},
        {"terms": {"data.src_ip": ["203.0.113.45"]}},
        {"terms": {"data.dest_ip": ["203.0.113.45"]}},
        {"terms": {"data.win.eventdata.destinationIp": ["203.0.113.45"]}},
        {"terms": {"data.win.eventdata.sourceIp": ["203.0.113.45"]}},
        {"terms": {"data.win.eventdata.ipAddress": ["203.0.113.45"]}},
        {"terms": {"data.win.eventdata.queryName": ["update-checker.example"]}},
        {"terms": {"data.win.eventdata.destinationHostname": ["update-checker.example"]}},
        {"terms": {"data.dns.rrname": ["update-checker.example"]}},
        {"terms": {"data.http.hostname": ["update-checker.example"]}},
        {"terms": {"data.tls.sni": ["update-checker.example"]}},
        {"terms": {"data.url": ["http://198.51.100.7:8000/stage2.ps1"]}},
        {"terms": {"data.http.url": ["http://198.51.100.7:8000/stage2.ps1"]}},
        {"terms": {"syscheck.sha256_after": ["4f0c0fbb3a1e0b8b1e3a0c6c1a4e5d1d9a1f4b8f2e7f5b6c1d0a9e8f7a6b5c4d"]}},
        {"wildcard": {"data.win.eventdata.hashes": {"value": "*4f0c0fbb3a1e0b8b1e3a0c6c1a4e5d1d9a1f4b8f2e7f5b6c1d0a9e8f7a6b5c4d*", "case_insensitive": true}}}
      ],
      "minimum_should_match": 1
    }
  },
  "aggs": {"by_agent": {"terms": {"field": "agent.name", "size": 50}}}
}
```

## Interpretation

- **How to read it**: each hit is a host that touched an IOC. `by_agent` gives
  the scope; sort by ascending `timestamp` to find the **first host**
  (possible patient zero) and the real start date of the incident.
- **IOC quality**: before escalating, look at the context of the attribute in MISP
  (source, date, `to_ids`, decay). CDN or shared hosting IPs and very generic
  domains produce false positives; a hash is much more reliable than an IP.
- **Common false positives**: expired IOCs (reassigned IPs), sinkholes,
  DNS resolvers that resolve the domain on behalf of the clients (look at the
  host that made the query, not the resolver), internal security scanners.
- **Next steps**: for each host with a hit, open a timeline of
  ±1 h around the event (processes, H01/H06; persistence, H03/H04/H13). Go back to
  MISP with what you find (`opensoc-ioc import --event-id <id>`), flagging
  `to_ids` only on what is reliable.
- **Continuous detection**: if an IOC is good, turn it into a detection (a Wazuh CDB
  list or a rule in `/detections`) instead of repeating the sweep.
- **Volume**: more than a few hundred `wildcard` clauses (hashes against Sysmon)
  make the query slow; `hunt-query` warns about it and it is better to split the list.
