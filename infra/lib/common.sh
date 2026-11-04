#!/usr/bin/env bash
# OpenSOC - helpers shared by install.sh and verify.sh. Source it, do not execute it.
# shellcheck disable=SC2034  # variables are used by the sourcing scripts

INFRA_DIR="${INFRA_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
ENV_FILE="${ENV_FILE:-$INFRA_DIR/.env}"
ENV_EXAMPLE="$INFRA_DIR/.env.example"
COMPOSE_FILE="$INFRA_DIR/docker-compose.yml"
GENERATED_DIR="$INFRA_DIR/generated"
CERTS_DIR="$GENERATED_DIR/certs"
DATA_DIR="$INFRA_DIR/data"
CA_CERT="$CERTS_DIR/root-ca.pem"

# Images used outside docker-compose.yml (keep in sync with it).
WAZUH_INDEXER_IMAGE="wazuh/wazuh-indexer:4.14.9"
WAZUH_CERTS_IMAGE="wazuh/wazuh-certs-generator:0.0.4"

# ------------------------------------------------------------------ output
if [[ -t 1 ]]; then
    C_RED=$'\e[31m' C_GREEN=$'\e[32m' C_YELLOW=$'\e[33m' C_BLUE=$'\e[34m' C_BOLD=$'\e[1m' C_RESET=$'\e[0m'
else
    C_RED="" C_GREEN="" C_YELLOW="" C_BLUE="" C_BOLD="" C_RESET=""
fi

info()  { printf '%s==>%s %s\n' "$C_BLUE" "$C_RESET" "$*"; }
ok()    { printf '%s[ OK ]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn()  { printf '%s[WARN]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
error() { printf '%s[FAIL]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
die()   { error "$*"; exit 1; }
title() { printf '\n%s%s%s\n' "$C_BOLD" "$*" "$C_RESET"; }

# ------------------------------------------------------------------ random values
# All generators read /dev/urandom through openssl; output is URL/YAML/shell safe.
gen_alnum() {
    local length="$1" out=""
    while [[ ${#out} -lt $length ]]; do
        out+=$(openssl rand -base64 96 | tr -dc 'A-Za-z0-9')
    done
    printf '%s' "${out:0:$length}"
}

gen_hex() { openssl rand -hex "$(( ($1 + 1) / 2 ))" | cut -c "1-$1"; }

gen_uuid() {
    if [[ -r /proc/sys/kernel/random/uuid ]]; then
        cat /proc/sys/kernel/random/uuid
    else
        local h; h=$(openssl rand -hex 16)
        printf '%s-%s-4%s-a%s-%s\n' "${h:0:8}" "${h:8:4}" "${h:13:3}" "${h:17:3}" "${h:20:12}"
    fi
}

# Strong password accepted by every component (Wazuh requires upper, lower, digit and
# a symbol): 24 random alphanumerics split by '.' and '-'.
gen_password() {
    local p
    while :; do
        p=$(gen_alnum 24)
        [[ $p =~ [A-Z] && $p =~ [a-z] && $p =~ [0-9] ]] && break
    done
    printf '%s.%s-%s' "${p:0:8}" "${p:8:8}" "${p:16:8}"
}

# Expand a __GENERATE:<kind><length>__ marker from .env.example.
gen_value() {
    local spec="$1"
    case "$spec" in
        password) gen_password ;;
        uuid) gen_uuid ;;
        alnum*) gen_alnum "${spec#alnum}" ;;
        hex*) gen_hex "${spec#hex}" ;;
        *) die "unknown generator '$spec' in .env.example" ;;
    esac
}

# ------------------------------------------------------------------ .env handling
# .env is parsed, never sourced: values are taken literally.
env_get() {
    local key="$1" file="${2:-$ENV_FILE}"
    [[ -f "$file" ]] || return 0
    awk -v k="$key" 'index($0, k "=") == 1 { v = substr($0, length(k) + 2) } END { if (v != "") print v }' "$file"
}

env_has() { [[ -f "${2:-$ENV_FILE}" ]] && grep -q "^$1=" "${2:-$ENV_FILE}"; }

# Set KEY=VALUE in .env in place (keeps the file inode, permissions and ordering).
env_set() {
    local key="$1" value="$2" tmp
    [[ "$value" != *$'\n'* ]] || die "env_set: multi-line value for $key"
    if env_has "$key"; then
        tmp=$(awk -v k="$key" -v v="$value" 'index($0, k "=") == 1 { print k "=" v; next } { print }' "$ENV_FILE")
        printf '%s\n' "$tmp" > "$ENV_FILE"
    else
        printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
    fi
}

# Export every KEY=VALUE of .env into the environment of the current shell.
load_env() {
    [[ -f "$ENV_FILE" ]] || die "$ENV_FILE does not exist: run ./install.sh first"
    local line key value
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] || continue
        key="${line%%=*}"
        value="${line#*=}"
        export "$key=$value"
    done < "$ENV_FILE"
}

# ------------------------------------------------------------------ docker helpers
compose() {
    docker compose --project-directory "$INFRA_DIR" -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"
}

# Health of a compose service: healthy | unhealthy | starting | running | exited | missing
service_state() {
    local id state health
    id=$(compose ps -q "$1" 2>/dev/null | head -n 1)
    [[ -n "$id" ]] || { echo missing; return; }
    state=$(docker inspect -f '{{.State.Status}}' "$id" 2>/dev/null || echo missing)
    health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$id" 2>/dev/null || true)
    if [[ "$state" == running && -n "$health" ]]; then echo "$health"; else echo "$state"; fi
}

# Wait until every given service is healthy (or running when it has no healthcheck).
wait_for_services() {
    local timeout="$1"; shift
    local deadline=$(( $(date +%s) + timeout )) pending state svc last_report=0
    while :; do
        pending=()
        for svc in "$@"; do
            state=$(service_state "$svc")
            case "$state" in
                healthy) ;;
                running) [[ -z $(docker inspect -f '{{if .State.Health}}x{{end}}' "$(compose ps -q "$svc")") ]] || pending+=("$svc($state)") ;;
                exited|dead) error "service $svc has stopped:"; compose logs --tail 30 "$svc" >&2 || true; return 1 ;;
                *) pending+=("$svc($state)") ;;
            esac
        done
        [[ ${#pending[@]} -eq 0 ]] && return 0
        if (( $(date +%s) >= deadline )); then
            error "timed out waiting for: ${pending[*]}"
            return 1
        fi
        if (( $(date +%s) - last_report >= 30 )); then
            info "waiting for: ${pending[*]}"
            last_report=$(date +%s)
        fi
        sleep 5
    done
}

# ------------------------------------------------------------------ HTTP helpers
# curl against the published OpenSOC endpoints, validated with the OpenSOC root CA.
# Usage: api <method> <url> [curl args...]   -> prints the body.
# The status code is stored in a file because api usually runs in a subshell
# (body=$(api ...)); read it with http_code.
HTTP_CODE_FILE=$(mktemp)
trap 'rm -f "$HTTP_CODE_FILE"' EXIT
api() {
    local method="$1" url="$2" out code; shift 2
    if out=$(curl -sS --noproxy "*" --cacert "$CA_CERT" --connect-timeout 10 --max-time 60 -X "$method" \
        -w $'\n%{http_code}' "$@" "$url" 2>/dev/null); then
        code="${out##*$'\n'}"; out="${out%$'\n'*}"
    else
        code=000; out=""
    fi
    printf '%s' "$code" > "$HTTP_CODE_FILE"
    printf '%s' "$out"
}
http_code() { cat "$HTTP_CODE_FILE"; }

retry_until() {
    # retry_until <timeout_s> <interval_s> <command...>
    local timeout="$1" interval="$2"; shift 2
    local deadline=$(( $(date +%s) + timeout ))
    until "$@"; do
        (( $(date +%s) >= deadline )) && return 1
        sleep "$interval"
    done
}
