#!/usr/bin/env bash
# OpenSOC verification: checks that every service responds and that the
# integrations work end to end.
#
#   sudo ./verify.sh           all checks (services + end-to-end integrations)
#   sudo ./verify.sh --quick   service checks only
#
# Exit code 0 when every check passes, 1 otherwise.
set -Eeuo pipefail

INFRA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=lib/common.sh
source "$INFRA_DIR/lib/common.sh"

QUICK=0
E2E_TIMEOUT="${OPENSOC_E2E_TIMEOUT:-240}"
# Documentation addresses (RFC 5737): the probes never reach a real host.
SELFTEST_IOC_IP="198.51.100.77"
SELFTEST_CLEAN_IP="198.51.100.78"
SELFTEST_PORT=40001
SELFTEST_EVENT_INFO="OpenSOC self-test IOC (verify.sh)"
SHUFFLE_WORKFLOW_NAME="OpenSOC - MISP IOC triage"

PASSED=0
FAILED=0
FAILED_NAMES=()

usage() {
    sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
}

# check "<description>" <command...>: runs the command, prints OK/FAIL and details.
check() {
    local description="$1" output; shift
    if output=$("$@" 2>&1); then
        PASSED=$((PASSED + 1))
        ok "$description${output:+ — ${output%%$'\n'*}}"
    else
        FAILED=$((FAILED + 1))
        FAILED_NAMES+=("$description")
        error "$description${output:+ — ${output//$'\n'/ | }}"
    fi
}

url_of() { printf 'https://localhost:%s' "$1"; }

# ------------------------------------------------------------------ containers
check_containers() {
    local services svc state bad=()
    mapfile -t services < <(compose config --services)
    for svc in "${services[@]}"; do
        state=$(service_state "$svc")
        [[ "$state" == healthy ]] || bad+=("$svc=$state")
    done
    if (( ${#bad[@]} )); then echo "${bad[*]}"; return 1; fi
    echo "${#services[@]} healthy containers"
}

# ------------------------------------------------------------------ Wazuh
check_indexer() {
    local body
    body=$(api GET "https://localhost:$WAZUH_INDEXER_PORT/_cluster/health" -u "admin:$WAZUH_INDEXER_PASSWORD" --resolve "wazuh.indexer:$WAZUH_INDEXER_PORT:127.0.0.1" )
    [[ "$(http_code)" == 200 ]] || { echo "HTTP $(http_code)"; return 1; }
    local status; status=$(jq -r .status <<<"$body")
    [[ "$status" == green || "$status" == yellow ]] || { echo "cluster $status"; return 1; }
    local count
    count=$(api GET "https://localhost:$WAZUH_INDEXER_PORT/wazuh-alerts-*/_count" -u "admin:$WAZUH_INDEXER_PASSWORD" | jq -r '.count // 0')
    echo "cluster $status, $count alerts indexed"
}

WAZUH_TOKEN=""
wazuh_token() {
    [[ -n "$WAZUH_TOKEN" ]] && { printf '%s' "$WAZUH_TOKEN"; return; }
    WAZUH_TOKEN=$(curl -sk --noproxy "*" --max-time 30 -u "wazuh-wui:$WAZUH_API_PASSWORD" -X POST \
        "https://localhost:$WAZUH_API_PORT/security/user/authenticate?raw=true")
    printf '%s' "$WAZUH_TOKEN"
}
wazuh_api() {
    # The Wazuh API uses its own self-signed certificate (-k).
    curl -sk --noproxy "*" --max-time 30 -H "Authorization: Bearer $(wazuh_token)" -H 'Content-Type: application/json' -X "$1" \
        "https://localhost:$WAZUH_API_PORT$2" "${@:3}"
}

check_wazuh_api() {
    local status stopped
    status=$(wazuh_api GET /manager/status)
    stopped=$(jq -r '.data.affected_items[0] | to_entries[] | select(.key | test("analysisd|remoted|logcollector|integratord|authd|apid|db")) | select(.value != "running") | .key' <<<"$status" 2>/dev/null) \
        || { echo "invalid response: ${status:0:200}"; return 1; }
    [[ -z "$stopped" ]] || { echo "stopped daemons: $stopped"; return 1; }
    echo "analysisd, remoted, authd, integratord and API running"
}

check_wazuh_dashboard() {
    api GET "https://wazuh.dashboard:$WAZUH_DASHBOARD_PORT/app/login" --resolve "wazuh.dashboard:$WAZUH_DASHBOARD_PORT:127.0.0.1" -o /dev/null >/dev/null
    [[ "$(http_code)" == 200 ]] || { echo "HTTP $(http_code)"; return 1; }
    local code
    code=$(curl -s --noproxy "*" -o /dev/null -w '%{http_code}' --cacert "$CA_CERT" --resolve "wazuh.dashboard:$WAZUH_DASHBOARD_PORT:127.0.0.1" \
        -u "admin:$WAZUH_INDEXER_PASSWORD" "https://wazuh.dashboard:$WAZUH_DASHBOARD_PORT/api/status")
    [[ "$code" == 200 ]] || { echo "login admin: HTTP $code"; return 1; }
    echo "login and status API OK (TLS validated against the OpenSOC CA)"
}

check_enrollment_port() {
    timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/1515' 2>/dev/null || { echo "1515/tcp closed"; return 1; }
    timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/1514' 2>/dev/null || { echo "1514/tcp closed"; return 1; }
    echo "1514/tcp and 1515/tcp open"
}

# ------------------------------------------------------------------ Suricata
check_suricata() {
    local uptime rules
    uptime=$(compose exec -T suricata suricatasc -c uptime 2>/dev/null | jq -r 'select(.return == "OK") | .message') \
        || { echo "suricatasc is not responding"; return 1; }
    [[ -n "$uptime" ]] || { echo "suricatasc is not responding"; return 1; }
    rules=$(compose exec -T suricata suricatasc -c ruleset-stats 2>/dev/null | jq -r '.message[0].rules_loaded // 0')
    echo "up for ${uptime}s on $SURICATA_INTERFACE, $rules rules loaded"
}

# ------------------------------------------------------------------ TheHive / Cortex
thehive() { api "$1" "$(url_of "$THEHIVE_PORT")$2" -H "Authorization: Bearer $THEHIVE_INTEGRATION_API_KEY" -H 'Content-Type: application/json' -H "X-Organisation: $THEHIVE_ORG" "${@:3}"; }

check_thehive() {
    local status version
    status=$(api GET "$(url_of "$THEHIVE_PORT")/api/status")
    [[ "$(http_code)" == 200 ]] || { echo "HTTP $(http_code)"; return 1; }
    version=$(jq -r '.versions.TheHive // .versions.Thehive // "?"' <<<"$status")
    local login
    login=$(thehive GET /api/v1/user/current | jq -r '.login // empty')
    [[ "$login" == "integrations@opensoc.local" ]] || { echo "the integration key is not valid (HTTP $(http_code))"; return 1; }
    echo "TheHive $version, integration key is valid"
}

check_cortex() {
    local status
    status=$(api GET "$(url_of "$CORTEX_PORT")/api/status")
    [[ "$(http_code)" == 200 ]] || { echo "HTTP $(http_code)"; return 1; }
    api GET "$(url_of "$CORTEX_PORT")/api/user/current" -H "Authorization: Bearer $CORTEX_API_KEY" >/dev/null
    [[ "$(http_code)" == 200 ]] || { echo "TheHive API key rejected (HTTP $(http_code))"; return 1; }
    echo "Cortex $(jq -r '.versions.Cortex // "?"' <<<"$status"), API key is valid"
}

check_thehive_cortex() {
    local status connector
    status=$(api GET "$(url_of "$THEHIVE_PORT")/api/v1/admin/config/cortex" -u "admin@thehive.local:$THEHIVE_ADMIN_PASSWORD" -H 'X-Organisation: admin')
    [[ "$(http_code)" == 200 ]] || { echo "HTTP $(http_code)"; return 1; }
    jq -e '.servers[]? | select(.url == "http://cortex:9001")' <<<"$status" >/dev/null || { echo "Cortex not registered"; return 1; }
    connector=$(thehive GET /api/v1/status | jq -r '.connectors.cortex.status // "?"')
    [[ "$connector" == OK ]] || { echo "connector status: $connector"; return 1; }
    echo "Cortex connector in TheHive: $connector"
}

# ------------------------------------------------------------------ MISP
misp() { api "$2" "$(url_of "$MISP_PORT")$3" -H "Authorization: $1" -H 'Accept: application/json' -H 'Content-Type: application/json' "${@:4}"; }

check_misp() {
    local version
    version=$(misp "$MISP_ADMIN_KEY" GET /servers/getVersion | jq -r '.version // empty')
    [[ -n "$version" ]] || { echo "API unavailable or invalid admin key (HTTP $(http_code))"; return 1; }
    misp "$MISP_AUTOMATION_KEY" GET /users/view/me.json >/dev/null
    [[ "$(http_code)" == 200 ]] || { echo "invalid automation key (HTTP $(http_code))"; return 1; }
    local modules
    modules=$(misp "$MISP_ADMIN_KEY" GET /servers/serverSettings/diagnostics.json | jq -r '.moduleStatus.Enrichment // empty' 2>/dev/null || true)
    echo "MISP $version${modules:+, misp-modules: $modules}"
}

check_misp_sync() {
    compose exec -T misp-ioc-sync python /app/misp_to_wazuh.py --healthcheck
}

# ------------------------------------------------------------------ Shuffle
shuffle() { api "$1" "$(url_of "$SHUFFLE_PORT")$2" -H "Authorization: Bearer $SHUFFLE_API_KEY" -H 'Content-Type: application/json' "${@:3}"; }

SHUFFLE_WORKFLOW_ID=""
check_shuffle() {
    api GET "$(url_of "$SHUFFLE_PORT")/" -o /dev/null >/dev/null
    [[ "$(http_code)" == 200 ]] || { echo "frontend HTTP $(http_code)"; return 1; }
    shuffle GET /api/v1/getinfo >/dev/null
    [[ "$(http_code)" == 200 ]] || { echo "API: key rejected (HTTP $(http_code))"; return 1; }
    SHUFFLE_WORKFLOW_ID=$(shuffle GET /api/v1/workflows | jq -r --arg n "$SHUFFLE_WORKFLOW_NAME" '[.[]? | select(.name == $n)][0].id // empty')
    [[ -n "$SHUFFLE_WORKFLOW_ID" ]] || { echo "playbook '$SHUFFLE_WORKFLOW_NAME' not found"; return 1; }
    echo "frontend and API OK, playbook '$SHUFFLE_WORKFLOW_NAME' present"
}

# ------------------------------------------------------------------ Grafana
check_grafana() {
    local health ds
    health=$(api GET "$(url_of "$GRAFANA_PORT")/api/health")
    [[ "$(http_code)" == 200 ]] || { echo "HTTP $(http_code)"; return 1; }
    ds=$(api GET "$(url_of "$GRAFANA_PORT")/api/datasources/uid/opensoc-wazuh-alerts/health" -u "admin:$GRAFANA_ADMIN_PASSWORD")
    [[ "$(jq -r .status <<<"$ds")" == OK ]] || { echo "datasource Wazuh: ${ds:0:200}"; return 1; }
    echo "Grafana $(jq -r .version <<<"$health"), datasource 'Wazuh alerts' OK"
}

# ------------------------------------------------------------------ end-to-end
# Wazuh alerts are looked up in alerts.json on the manager (fast) and then in the indexer.
find_alert() {
    # find_alert <jq filter on the alert> -> prints the most recent matching alert (JSON)
    compose exec -T wazuh.manager tail -n 5000 /var/ossec/logs/alerts/alerts.json 2>/dev/null \
        | jq -c "select($1)" 2>/dev/null | tail -n 1
}

wait_alert() {
    local filter="$1" deadline=$(( $(date +%s) + E2E_TIMEOUT )) alert
    while (( $(date +%s) < deadline )); do
        alert=$(find_alert "$filter")
        [[ -n "$alert" ]] && { printf '%s' "$alert"; return 0; }
        sleep 3
    done
    return 1
}

thehive_find_alert() {
    # thehive_find_alert <sourceRef> -> TheHive alert JSON (with caseId when promoted)
    thehive POST /api/v1/query -d "$(jq -nc --arg r "$1" '{query: [{_name: "listAlert"}, {_name: "filter", _field: "sourceRef", _value: $r}]}')" \
        | jq -c '.[0] // empty' 2>/dev/null
}

wait_thehive_alert() {
    local ref="$1" need_case="$2" deadline=$(( $(date +%s) + E2E_TIMEOUT )) alert
    while (( $(date +%s) < deadline )); do
        alert=$(thehive_find_alert "$ref")
        if [[ -n "$alert" ]] && { [[ "$need_case" != yes ]] || [[ "$(jq -r '.caseId // empty' <<<"$alert")" != "" ]]; }; then
            printf '%s' "$alert"; return 0
        fi
        sleep 3
    done
    [[ -n "$alert" ]] && printf '%s' "$alert"
    return 1
}

indexed() {
    # indexed <wazuh alert id>: wait until the alert is searchable in the indexer
    local id="$1" deadline=$(( $(date +%s) + E2E_TIMEOUT )) count
    while (( $(date +%s) < deadline )); do
        count=$(api POST "https://localhost:$WAZUH_INDEXER_PORT/wazuh-alerts-*/_count" -u "admin:$WAZUH_INDEXER_PASSWORD" \
            -H 'Content-Type: application/json' -d "$(jq -nc --arg id "$id" '{query: {term: {id: $id}}}')" | jq -r '.count // 0')
        (( count > 0 )) && return 0
        sleep 5
    done
    return 1
}

send_probe() {
    # UDP datagram sent from the host network namespace: Suricata sees it on SURICATA_INTERFACE.
    local ip="$1" marker="$2"
    compose exec -T suricata bash -c "printf '%s' 'OPENSOC-IDS-TEST $marker' > /dev/udp/$ip/$SELFTEST_PORT"
}

e2e_wazuh_thehive() {
    # Synthetic level-12 event ingested through the Wazuh API (rule 100299).
    local nonce alert alert_id th
    nonce="selftest-$(date +%s)-$RANDOM"
    wazuh_api POST /events -d "$(jq -nc --arg n "$nonce" '{events: [({opensoc: {selftest: $n, source: "verify.sh"}} | tojson)]}')" \
        | jq -e '.data.total_affected_items == 1' >/dev/null || { echo "the Wazuh API did not accept the event"; return 1; }
    alert=$(wait_alert ".rule.id == \"100299\" and .data.opensoc.selftest == \"$nonce\"") || { echo "Wazuh did not raise alert 100299"; return 1; }
    alert_id=$(jq -r .id <<<"$alert")
    th=$(wait_thehive_alert "$alert_id" yes) || { echo "alert $alert_id not found in TheHive (or without a case): ${th:0:200}"; return 1; }
    indexed "$alert_id" || { echo "alert $alert_id did not reach the indexer"; return 1; }
    echo "Wazuh alert $alert_id (level 12) -> indexer + TheHive alert $(jq -r ._id <<<"$th") -> case $(jq -r .caseId <<<"$th")"
}

e2e_suricata() {
    local marker alert alert_id th
    marker="$(date +%s)-$RANDOM"
    send_probe "$SELFTEST_CLEAN_IP" "$marker" || { echo "could not send the UDP probe"; return 1; }
    alert=$(wait_alert ".rule.id == \"100200\" and .data.dest_ip == \"$SELFTEST_CLEAN_IP\" and ((.data.payload_printable // \"\") | contains(\"$marker\"))") \
        || { echo "Wazuh did not receive the Suricata alert (sid 9000001) within ${E2E_TIMEOUT}s"; return 1; }
    alert_id=$(jq -r .id <<<"$alert")
    th=$(wait_thehive_alert "$alert_id" no) || { echo "alert $alert_id not found in TheHive"; return 1; }
    echo "UDP probe -> Suricata sid 9000001 -> Wazuh rule 100200 ($alert_id) -> TheHive $(jq -r ._id <<<"$th")"
}

ensure_misp_selftest_ioc() {
    local found event
    found=$(misp "$MISP_ADMIN_KEY" POST /attributes/restSearch -d "$(jq -nc --arg v "$SELFTEST_IOC_IP" '{returnFormat: "json", value: $v, type: "ip-dst", to_ids: true}')" \
        | jq -r '.response.Attribute | length' 2>/dev/null || echo 0)
    (( found > 0 )) && return 0
    event=$(misp "$MISP_ADMIN_KEY" POST /events/add -d "$(jq -nc --arg info "$SELFTEST_EVENT_INFO" --arg ip "$SELFTEST_IOC_IP" '{
        info: $info, distribution: 0, threat_level_id: 4, analysis: 2, published: true,
        Attribute: [{type: "ip-dst", category: "Network activity", value: $ip, to_ids: true,
                     comment: "Documentation address (RFC 5737) used by infra/verify.sh"}]}')")
    [[ "$(http_code)" == 200 ]] || { echo "could not create the test event in MISP (HTTP $(http_code)): ${event:0:200}"; return 1; }
    misp "$MISP_ADMIN_KEY" POST "/events/publish/$(jq -r .Event.id <<<"$event")" -d '{}' >/dev/null
}

e2e_misp_wazuh() {
    ensure_misp_selftest_ioc || return 1
    compose exec -T misp-ioc-sync python /app/misp_to_wazuh.py --once >/dev/null || { echo "the MISP -> Wazuh synchronization failed"; return 1; }
    compose exec -T wazuh.manager grep -q "^$SELFTEST_IOC_IP:" /var/ossec/etc/lists/malicious-ioc/malicious-ip \
        || { echo "$SELFTEST_IOC_IP is not in etc/lists/malicious-ioc/malicious-ip"; return 1; }
    local entries; entries=$(compose exec -T wazuh.manager sh -c 'cat /var/ossec/etc/lists/malicious-ioc/* | wc -l' | tr -d '[:space:]')
    echo "test IOC $SELFTEST_IOC_IP exported to the Wazuh CDB list ($entries IOCs in total)"
}

e2e_shuffle() {
    local marker alert alert_id th
    sleep 5  # leave analysisd time to finish the ruleset reload triggered by the sync
    marker="$(date +%s)-$RANDOM"
    send_probe "$SELFTEST_IOC_IP" "$marker" || { echo "could not send the UDP probe"; return 1; }
    alert=$(wait_alert ".rule.id == \"100101\" and .data.dest_ip == \"$SELFTEST_IOC_IP\" and ((.data.payload_printable // \"\") | contains(\"$marker\"))") \
        || { echo "Wazuh did not raise IOC alert 100101 for $SELFTEST_IOC_IP"; return 1; }
    alert_id=$(jq -r .id <<<"$alert")
    th=$(wait_thehive_alert "wazuh-$alert_id" yes) || { echo "the playbook did not create the alert/case in TheHive for $alert_id: ${th:0:200}"; return 1; }
    local info attr_id sighted
    info=$(jq -r '.description' <<<"$th" | grep -o 'MISP event: #[0-9]*' | head -n 1)
    attr_id=$(misp "$MISP_ADMIN_KEY" POST /attributes/restSearch -d "$(jq -nc --arg v "$SELFTEST_IOC_IP" '{returnFormat: "json", value: $v, type: "ip-dst"}')" \
        | jq -r '.response.Attribute[0].id // empty')
    sighted=$(misp "$MISP_ADMIN_KEY" POST /sightings/restSearch/attribute -d "$(jq -nc --argjson id "${attr_id:-0}" '{id: $id}')" \
        | jq -r --arg a "$alert_id" '[.response[]?.Sighting | select(.source | contains($a))] | length' 2>/dev/null || echo 0)
    (( sighted > 0 )) || { echo "TheHive OK but there is no MISP sighting for alert $alert_id"; return 1; }
    echo "IOC $SELFTEST_IOC_IP -> Wazuh 100101 ($alert_id) -> Shuffle -> MISP sighting + TheHive alert $(jq -r ._id <<<"$th") -> case $(jq -r .caseId <<<"$th") (${info:-no MISP context})"
}

main() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --quick) QUICK=1 ;;
            -h|--help) usage; exit 0 ;;
            *) usage; die "unknown option: $1" ;;
        esac
        shift
    done
    cd "$INFRA_DIR"
    load_env
    for cmd in docker curl jq; do command -v "$cmd" >/dev/null || die "missing command $cmd"; done

    title "Services"
    check "Containers (docker compose)" check_containers
    check "Wazuh indexer" check_indexer
    check "Wazuh manager (API)" check_wazuh_api
    check "Wazuh dashboard" check_wazuh_dashboard
    check "Wazuh: agent ports" check_enrollment_port
    check "Suricata" check_suricata
    check "TheHive" check_thehive
    check "Cortex" check_cortex
    check "TheHive -> Cortex" check_thehive_cortex
    check "MISP" check_misp
    check "MISP -> Wazuh (synchronization service)" check_misp_sync
    check "Shuffle" check_shuffle
    check "Grafana" check_grafana

    if (( ! QUICK )); then
        title "Integrations (end to end)"
        check "Wazuh -> TheHive (alert and case)" e2e_wazuh_thehive
        check "Suricata -> Wazuh -> TheHive" e2e_suricata
        check "MISP -> Wazuh (IOCs)" e2e_misp_wazuh
        check "Wazuh -> Shuffle -> MISP/TheHive (playbook)" e2e_shuffle
    fi

    title "Result"
    if (( FAILED )); then
        error "$FAILED checks failed, $PASSED passed: ${FAILED_NAMES[*]}"
        exit 1
    fi
    ok "$PASSED checks passed"
}

main "$@"
