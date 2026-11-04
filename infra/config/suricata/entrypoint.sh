#!/bin/bash
# OpenSOC - Suricata launcher.
#  * copies the default configuration on first start and appends the OpenSOC include,
#  * downloads rules with suricata-update (ET Open); failures are not fatal (offline
#    hosts still get the local rules in /etc/suricata-opensoc/rules),
#  * runs a background loop that refreshes the rules every SURICATA_UPDATE_INTERVAL
#    seconds and rotates eve.json once it grows over SURICATA_EVE_MAX_MB,
#  * starts Suricata in AF_PACKET mode on SURICATA_INTERFACE.
set -euo pipefail

IFACE="${SURICATA_INTERFACE:?SURICATA_INTERFACE is not set}"
UPDATE_INTERVAL="${SURICATA_UPDATE_INTERVAL:-86400}"
EVE_MAX_MB="${SURICATA_EVE_MAX_MB:-512}"
CONF=/etc/suricata/suricata.yaml
INCLUDE=/etc/suricata-opensoc/opensoc.yaml
RULES_DIR=/var/lib/suricata/rules
LOG_DIR=/var/log/suricata

log() { echo "[opensoc-suricata] $*"; }

for src in /etc/suricata.dist/*; do
    dst="/etc/suricata/$(basename "$src")"
    [ -e "$dst" ] || cp -a "$src" "$dst"
done

if ! grep -q "^include: ${INCLUDE}" "$CONF"; then
    printf '\n# Added by OpenSOC\ninclude: %s\n' "$INCLUDE" >> "$CONF"
fi

if [ ! -e "/sys/class/net/${IFACE}" ]; then
    log "ERROR: interface ${IFACE} not found. Available: $(cd /sys/class/net && echo *)"
    exit 1
fi

update_rules() {
    local out
    # suricata-update exits 0 even when a source cannot be downloaded: check its output.
    if out=$(suricata-update --no-test --no-reload 2>&1) && ! grep -q "Failed to fetch" <<<"$out"; then
        log "rules updated"
        return 0
    fi
    grep -E "Error|Failed" <<<"$out" | head -n 3 || true
    log "WARNING: suricata-update failed (no Internet access?); keeping the current rule set"
    return 1
}

mkdir -p "$RULES_DIR"
[ -s "$RULES_DIR/suricata.rules" ] || update_rules || true
[ -e "$RULES_DIR/suricata.rules" ] || : > "$RULES_DIR/suricata.rules"

maintenance() {
    local last_update elapsed size
    last_update=$(date +%s)
    while sleep 60; do
        size=$(stat -c %s "$LOG_DIR/eve.json" 2>/dev/null || echo 0)
        if [ "$size" -gt $((EVE_MAX_MB * 1024 * 1024)) ]; then
            mv -f "$LOG_DIR/eve.json" "$LOG_DIR/eve.json.1"
            suricatasc -c reopen-log-files >/dev/null 2>&1 || true
            log "rotated eve.json (${size} bytes)"
        fi
        elapsed=$(( $(date +%s) - last_update ))
        if [ "$elapsed" -ge "$UPDATE_INTERVAL" ]; then
            last_update=$(date +%s)
            if update_rules; then
                suricatasc -c reload-rules >/dev/null 2>&1 || true
            fi
        fi
    done
}
maintenance &

log "starting Suricata on ${IFACE}"
exec /docker-entrypoint.sh --af-packet="${IFACE}" -s /etc/suricata-opensoc/rules/opensoc.rules "$@"
