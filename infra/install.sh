#!/usr/bin/env bash
# OpenSOC installer: deploys the whole SOC on a single Linux host with one command.
#
#   sudo ./install.sh            check requirements, generate secrets/PKI, start, configure
#   sudo ./install.sh --help
#
# Idempotent: re-running it keeps the existing secrets (.env), certificates and data,
# starts whatever is missing and re-applies the integration configuration.
set -Eeuo pipefail

INFRA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=lib/common.sh
source "$INFRA_DIR/lib/common.sh"

MIN_RAM_GB=14          # 16 GB hosts report ~15.5 GiB
REC_RAM_GB=15
MIN_CPUS=4
MIN_DISK_GB=40         # images (~15 GB) + data
MIN_DATA_DISK_GB=10
TCP_PORTS_KEYS=(WAZUH_DASHBOARD_PORT WAZUH_API_PORT THEHIVE_PORT CORTEX_PORT MISP_PORT SHUFFLE_PORT GRAFANA_PORT)
TCP_PORTS_FIXED=(1514 1515)
START_TIMEOUT="${OPENSOC_START_TIMEOUT:-1500}"
SKIP_CHECKS=0
SKIP_PULL=0

THEHIVE_ADMIN_LOGIN="admin@thehive.local"
THEHIVE_ANALYST_LOGIN="analyst@opensoc.local"
THEHIVE_INTEGRATION_LOGIN="integrations@opensoc.local"
CORTEX_ADMIN_LOGIN="admin"
CORTEX_THEHIVE_LOGIN="thehive"
MISP_DEFAULT_ADMIN="admin@admin.test"
MISP_AUTOMATION_EMAIL="automation@opensoc.local"
SHUFFLE_WORKFLOW_NAME="OpenSOC - MISP IOC triage"

usage() {
    cat <<EOF
Usage: sudo ./install.sh [options]

Deploys OpenSOC (Wazuh, Suricata, TheHive, Cortex, MISP, Shuffle and Grafana) on this host.

Options:
  --skip-checks   do not abort when the RAM/CPU/disk requirements are not met
  --no-pull       do not pull images (use the ones already available locally)
  -h, --help      show this help

Environment variables:
  OPENSOC_START_TIMEOUT   seconds to wait for the services to become healthy (default 1500)
EOF
}

# ================================================================== 1. requirements
port_in_use() {
    # Linux: look for a LISTEN socket (state 0A) on the port in /proc/net/tcp{,6}.
    local hex; hex=$(printf '%04X' "$1")
    awk -v p=":$hex" '$4 == "0A" && substr($2, length($2) - 4) == p { found = 1 } END { exit !found }' \
        /proc/net/tcp /proc/net/tcp6 2>/dev/null
}

version_ge() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" == "$2" ]]; }

check_requirements() {
    title "1/7 Checking requirements"
    local failed=0 cmd

    [[ "$(uname -s)" == Linux ]] || die "OpenSOC requires Linux"
    [[ $EUID -eq 0 ]] || die "run the installer as root: sudo ./install.sh"

    for cmd in docker curl openssl jq awk sed sort; do
        command -v "$cmd" >/dev/null 2>&1 || { error "missing command '$cmd'"; failed=1; }
    done
    (( failed == 0 )) || die "install the missing dependencies (e.g. apt install curl openssl jq)"

    docker info >/dev/null 2>&1 || die "cannot connect to the Docker daemon (is it running?)"
    local docker_version compose_version
    docker_version=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo 0)
    version_ge "$docker_version" 24.0 || die "Docker Engine >= 24.0 is required (found $docker_version)"
    compose_version=$(docker compose version --short 2>/dev/null | sed 's/^v//' || true)
    [[ -n "$compose_version" ]] || die "the Docker Compose v2 plugin (docker compose) is required"
    version_ge "$compose_version" 2.24 || die "Docker Compose >= 2.24 is required (found $compose_version)"
    ok "Docker $docker_version, Compose $compose_version"

    local ram_kb ram_gb cpus disk_gb docker_root
    ram_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
    ram_gb=$(( ram_kb / 1024 / 1024 ))
    cpus=$(nproc)
    docker_root=$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || echo /var/lib/docker)
    disk_gb=$(df -Pk "$docker_root" | awk 'NR == 2 { print int($4 / 1024 / 1024) }')

    if (( ram_gb < MIN_RAM_GB )); then
        error "RAM: ${ram_gb} GiB (minimum ${MIN_RAM_GB} GiB, 16 GB recommended)"; failed=1
    elif (( ram_gb < REC_RAM_GB )); then
        warn "RAM: ${ram_gb} GiB (16 GB recommended)"
    else
        ok "RAM: ${ram_gb} GiB"
    fi
    if (( cpus < MIN_CPUS )); then warn "CPU: ${cpus} cores (recommended >= ${MIN_CPUS})"; else ok "CPU: ${cpus} cores"; fi
    # Images take ~15 GB; once they are all present only room for data is needed.
    local env_for_images="$ENV_FILE" image missing=0 min_disk
    [[ -f "$env_for_images" ]] || env_for_images="$ENV_EXAMPLE"
    while read -r image; do
        docker image inspect "$image" >/dev/null 2>&1 || missing=$((missing + 1))
    done < <(docker compose -f "$COMPOSE_FILE" --env-file "$env_for_images" config --images 2>/dev/null)
    min_disk=$(( missing > 0 ? MIN_DISK_GB : MIN_DATA_DISK_GB ))
    if (( disk_gb < min_disk )); then
        error "free disk in $docker_root: ${disk_gb} GB (minimum ${min_disk} GB; $missing images still to pull)"; failed=1
    else
        ok "free disk in $docker_root: ${disk_gb} GB (images still to pull: $missing)"
    fi

    # OpenSearch / Elasticsearch need vm.max_map_count >= 262144.
    local map_count; map_count=$(sysctl -n vm.max_map_count)
    if (( map_count < 262144 )); then
        sysctl -q -w vm.max_map_count=262144
        echo "vm.max_map_count=262144" > /etc/sysctl.d/99-opensoc.conf
        ok "vm.max_map_count set to 262144 (persisted in /etc/sysctl.d/99-opensoc.conf)"
    else
        ok "vm.max_map_count=$map_count"
    fi

    # Published TCP ports must be free unless OpenSOC itself already uses them.
    local port key ports=()
    if [[ $(compose ps -q 2>/dev/null | wc -l) -eq 0 ]]; then
        for key in "${TCP_PORTS_KEYS[@]}"; do
            port=$(env_get "$key"); [[ -n "$port" ]] || port=$(env_get "$key" "$ENV_EXAMPLE")
            ports+=("$port")
        done
        ports+=("${TCP_PORTS_FIXED[@]}")
        for port in "${ports[@]}"; do
            if port_in_use "$port"; then error "TCP port $port is already in use"; failed=1; fi
        done
        (( failed == 0 )) && ok "free ports: ${ports[*]}"
    else
        ok "OpenSOC is already running: skipping the port check"
    fi

    if (( failed )); then
        if (( SKIP_CHECKS )); then warn "continuing despite the failures (--skip-checks)"; else die "requirements not met (use --skip-checks to force)"; fi
    fi
}

# ================================================================== 2. secrets (.env)
default_interface() {
    awk '$2 == "00000000" && $8 == "00000000" { print $1; exit }' /proc/net/route
}

interface_ipv4() {
    local iface="$1" ip=""
    if command -v ip >/dev/null 2>&1; then
        ip=$(ip -4 -o addr show dev "$iface" 2>/dev/null | awk '{ split($4, a, "/"); print a[1]; exit }')
    fi
    if [[ -z "$ip" ]] && command -v hostname >/dev/null 2>&1; then
        ip=$(hostname -I 2>/dev/null | awk '{ print $1 }')
    fi
    printf '%s' "$ip"
}

# Value for a key when .env is created: generated secret, detected host value or default.
initial_value() {
    local key="$1" default="$2"
    case "$key" in
        OPENSOC_HOSTNAME)
            local iface ip; iface=$(default_interface); ip=$(interface_ipv4 "${iface:-lo}")
            printf '%s' "${ip:-$(hostname -f 2>/dev/null || hostname)}" ;;
        SURICATA_INTERFACE)
            local iface; iface=$(default_interface)
            [[ -n "$iface" ]] || die "could not detect the network interface (set SURICATA_INTERFACE in .env)"
            printf '%s' "$iface" ;;
        DOCKER_GID) stat -c %g /var/run/docker.sock ;;
        CORTEX_JOB_DIR) printf '%s' "$DATA_DIR/cortex-jobs" ;;
        *)
            if [[ "$default" =~ ^__GENERATE:([a-z]+[0-9]*)__$ ]]; then
                gen_value "${BASH_REMATCH[1]}"
            else
                printf '%s' "$default"
            fi ;;
    esac
}

init_env() {
    title "2/7 Secrets and configuration (.env)"
    local created=0 added=() line key default
    if [[ ! -f "$ENV_FILE" ]]; then
        (umask 077; printf '# OpenSOC - generated by install.sh on %s. Do NOT commit it to the repository.\n' "$(date -u +%FT%TZ)" > "$ENV_FILE")
        created=1
    fi
    chmod 600 "$ENV_FILE"
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]] || continue
        key="${BASH_REMATCH[1]}"; default="${BASH_REMATCH[2]}"
        env_has "$key" && continue
        env_set "$key" "$(initial_value "$key" "$default")"
        added+=("$key")
    done < "$ENV_EXAMPLE"
    if (( created )); then
        ok "created $ENV_FILE with ${#added[@]} values (random secrets, mode 600)"
    elif (( ${#added[@]} > 8 )); then
        ok "added ${#added[@]} new keys to .env (random secrets, mode 600)"
    elif (( ${#added[@]} )); then
        ok "new keys added to .env: ${added[*]}"
    else
        ok "$ENV_FILE already exists: keeping the secrets"
    fi
    grep -q '__GENERATE:' "$ENV_FILE" && die "unresolved __GENERATE__ placeholders remain in .env"
    load_env
    ok "host: $OPENSOC_HOSTNAME  ·  Suricata interface: $SURICATA_INTERFACE"
}

# ================================================================== 3. PKI
issue_cert() {
    # issue_cert <name> <CN> <subjectAltName> <extendedKeyUsage>
    local name="$1" cn="$2" san="$3" eku="$4" ext
    ext=$(mktemp)
    printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=%s\nsubjectAltName=%s\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n' "$eku" "$san" > "$ext"
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$CERTS_DIR/$name-key.pem" 2>/dev/null
    openssl req -new -key "$CERTS_DIR/$name-key.pem" -subj "/O=OpenSOC/OU=SOC/CN=$cn" -out "$CERTS_DIR/$name.csr"
    openssl x509 -req -in "$CERTS_DIR/$name.csr" -CA "$CA_CERT" -CAkey "$CERTS_DIR/root-ca.key" -CAcreateserial \
        -days 825 -sha256 -extfile "$ext" -out "$CERTS_DIR/$name.pem" 2>/dev/null
    rm -f "$CERTS_DIR/$name.csr" "$ext"
}

host_sans() {
    local san="DNS:localhost,IP:127.0.0.1" h
    for h in "$OPENSOC_HOSTNAME" "$(hostname 2>/dev/null || true)" "$(hostname -f 2>/dev/null || true)"; do
        [[ -n "$h" && "$san" != *":$h,"* && "$san" != *":$h" ]] || continue
        if [[ "$h" =~ ^[0-9.]+$ ]]; then san+=",IP:$h"; else san+=",DNS:$h"; fi
    done
    printf '%s' "$san"
}

generate_pki() {
    title "3/7 TLS certificates (OpenSOC CA)"
    mkdir -p "$CERTS_DIR"; chmod 700 "$GENERATED_DIR" "$CERTS_DIR" 2>/dev/null || true
    if [[ ! -f "$CA_CERT" || ! -f "$CERTS_DIR/root-ca.key" ]]; then
        openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$CERTS_DIR/root-ca.key" 2>/dev/null
        openssl req -x509 -new -key "$CERTS_DIR/root-ca.key" -sha256 -days 3650 \
            -subj "/O=OpenSOC/OU=SOC/CN=OpenSOC Root CA" \
            -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
            -out "$CA_CERT"
        ok "root CA created: $CA_CERT"
    else
        ok "existing root CA: $CA_CERT"
    fi
    local sans; sans=$(host_sans)
    [[ -f "$CERTS_DIR/admin.pem" ]] || issue_cert admin admin "DNS:admin" "clientAuth"
    [[ -f "$CERTS_DIR/wazuh.indexer.pem" ]] || issue_cert wazuh.indexer wazuh.indexer "DNS:wazuh.indexer,$sans" "serverAuth,clientAuth"
    [[ -f "$CERTS_DIR/wazuh.manager.pem" ]] || issue_cert wazuh.manager wazuh.manager "DNS:wazuh.manager" "serverAuth,clientAuth"
    # Web UIs: re-issue when OPENSOC_HOSTNAME is not in the certificate anymore.
    local name
    for name in wazuh.dashboard opensoc-proxy; do
        if [[ ! -f "$CERTS_DIR/$name.pem" ]] || ! openssl x509 -in "$CERTS_DIR/$name.pem" -noout -ext subjectAltName 2>/dev/null | grep -q "$OPENSOC_HOSTNAME"; then
            issue_cert "$name" "$name" "DNS:$name,$sans" "serverAuth"
        fi
    done
    # Bind-mounted files are read by several container users; the directory stays 0700.
    chmod 644 "$CERTS_DIR"/*.pem
    chmod 600 "$CERTS_DIR/root-ca.key"
    ok "certificates for wazuh.indexer, wazuh.manager, wazuh.dashboard, admin and proxy ready"
}

# ================================================================== 4. rendered configs
# Replace ${VAR} placeholders of a template with values from the environment.
render_template() {
    local src="$1" dst="$2" content var
    content=$(<"$src")
    shopt -u patsub_replacement 2>/dev/null || true
    # shellcheck disable=SC2016  # literal ${VAR} placeholders
    for var in $(grep -o '\${[A-Z_][A-Z0-9_]*}' "$src" | sort -u | tr -d '${}'); do
        content="${content//\$\{$var\}/${!var-}}"
    done
    # Write in place: bind mounts keep pointing at the same inode.
    printf '%s\n' "$content" > "$dst"
}

bcrypt_hashes() {
    # Prints one bcrypt hash per password given as environment variable names.
    local args=() v
    for v in "$@"; do args+=(-e "$v"); done
    docker run --rm "${args[@]}" --entrypoint /bin/bash "$WAZUH_INDEXER_IMAGE" -c '
        export JAVA_HOME=/usr/share/wazuh-indexer/jdk
        tool=/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh
        for v in '"$*"'; do "$tool" -env "$v" 2>/dev/null | grep -E "^\\\$2[aby]\\\$" | tail -n 1; done'
}

INTERNAL_USERS_CHANGED=0
render_configs() {
    title "4/7 Generated configuration"
    mkdir -p "$GENERATED_DIR/wazuh"

    local users_file="$GENERATED_DIR/wazuh/internal_users.yml" sum_file="$GENERATED_DIR/wazuh/.internal_users.sum" sum
    sum=$(printf '%s\n%s\n%s\n' "$WAZUH_INDEXER_PASSWORD" "$WAZUH_DASHBOARD_PASSWORD" "$GRAFANA_INDEXER_PASSWORD" | sha256sum | cut -d' ' -f1)
    if [[ ! -s "$users_file" || "$(cat "$sum_file" 2>/dev/null)" != "$sum" ]]; then
        if ! docker image inspect "$WAZUH_INDEXER_IMAGE" >/dev/null 2>&1; then
            docker pull -q "$WAZUH_INDEXER_IMAGE" >/dev/null
        fi
        local hashes
        mapfile -t hashes < <(bcrypt_hashes WAZUH_INDEXER_PASSWORD WAZUH_DASHBOARD_PASSWORD GRAFANA_INDEXER_PASSWORD)
        [[ ${#hashes[@]} -eq 3 ]] || die "could not compute the bcrypt hashes of the indexer users"
        local content
        content=$(<"$INFRA_DIR/config/wazuh/internal_users.yml.tpl")
        content="${content//__ADMIN_HASH__/${hashes[0]}}"
        content="${content//__KIBANASERVER_HASH__/${hashes[1]}}"
        content="${content//__GRAFANA_HASH__/${hashes[2]}}"
        [[ -s "$users_file" ]] && INTERNAL_USERS_CHANGED=1
        printf '%s\n' "$content" > "$users_file"
        printf '%s\n' "$sum" > "$sum_file"
        chmod 644 "$users_file"
        ok "Wazuh indexer users generated (admin, kibanaserver, grafana)"
    else
        ok "Wazuh indexer users unchanged"
    fi

    render_ossec_conf || true   # returns 1 when unchanged
    printf '%s\n' "$WAZUH_ENROLLMENT_PASSWORD" > "$GENERATED_DIR/wazuh/authd.pass"
    chmod 600 "$GENERATED_DIR/wazuh/authd.pass"
    ok "ossec.conf and authd.pass generated"
}

render_ossec_conf() {
    local dst="$GENERATED_DIR/wazuh/ossec.conf" before=""
    [[ -f "$dst" ]] && before=$(sha256sum "$dst" | cut -d' ' -f1)
    [[ -f "$dst" ]] || : > "$dst"
    render_template "$INFRA_DIR/config/wazuh/ossec.conf.tpl" "$dst"
    chmod 644 "$dst"
    [[ "$(sha256sum "$dst" | cut -d' ' -f1)" != "$before" ]]
}

prepare_data_dirs() {
    mkdir -p "$DATA_DIR"/{wazuh-ioc-lists,cortex-jobs,shuffle-apps,shuffle-files}
    local list
    for list in malicious-ip malicious-domains malware-hashes; do
        [[ -e "$DATA_DIR/wazuh-ioc-lists/$list" ]] || : > "$DATA_DIR/wazuh-ioc-lists/$list"
    done
    chmod 775 "$DATA_DIR/wazuh-ioc-lists"; chmod 664 "$DATA_DIR/wazuh-ioc-lists"/*
    [[ "$CORTEX_JOB_DIR" == /* ]] || die "CORTEX_JOB_DIR must be an absolute path"
    mkdir -p "$CORTEX_JOB_DIR" && chown 1001:1001 "$CORTEX_JOB_DIR"

    # Shuffle downloads its apps from GitHub on first start. Pre-fetching the two apps
    # used by the example playbook makes it work on hosts where only the host (not the
    # containers) can reach GitHub. Failures are not fatal.
    if [[ ! -d "$DATA_DIR/shuffle-apps/http" ]] && command -v git >/dev/null 2>&1; then
        local tmp; tmp=$(mktemp -d)
        if timeout 180 git clone -q --depth 1 --filter=blob:none --sparse https://github.com/Shuffle/python-apps.git "$tmp/apps" 2>/dev/null \
            && git -C "$tmp/apps" sparse-checkout set http shuffle-tools 2>/dev/null; then
            cp -r "$tmp/apps/http" "$tmp/apps/shuffle-tools" "$DATA_DIR/shuffle-apps/"
            ok "Shuffle apps (http, shuffle-tools) downloaded"
        else
            warn "could not download the Shuffle apps; the backend will try on its own"
        fi
        rm -rf "$tmp"
    fi
}

# ================================================================== 5. start
start_stack() {
    title "5/7 Starting containers"
    prepare_data_dirs
    if (( ! SKIP_PULL )); then
        local attempt
        for attempt in 1 2 3; do
            compose pull --quiet --ignore-buildable && break
            (( attempt == 3 )) && die "could not pull the images"
            warn "image pull failed, retry $attempt/3 in 20 s"; sleep 20
        done
        ok "images pulled"
    fi
    compose up -d --remove-orphans
    info "waiting for the services to become healthy (the first start can take 5-15 min)"
    # misp-ioc-sync only becomes healthy after its MISP key is provisioned (step 6).
    local services; mapfile -t services < <(compose config --services | grep -vx misp-ioc-sync)
    wait_for_services "$START_TIMEOUT" "${services[@]}" || die "some services did not start (docker compose logs <service>)"
    ok "all services are healthy"

    if (( INTERNAL_USERS_CHANGED )); then
        info "applying the new indexer passwords (securityadmin)"
        compose exec -T wazuh.indexer bash -c 'export JAVA_HOME=/usr/share/wazuh-indexer/jdk; \
            /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
            -f /usr/share/wazuh-indexer/config/opensearch-security/internal_users.yml -t internalusers \
            -icl -nhnv -h localhost -cacert config/certs/root-ca.pem -cert config/certs/admin.pem -key config/certs/admin-key.pem' >/dev/null
        compose restart wazuh.manager wazuh.dashboard grafana >/dev/null
        wait_for_services 600 wazuh.manager wazuh.dashboard grafana
        ok "indexer passwords updated"
    fi
}

# ================================================================== 6. bootstrap / integrations
url_of() { printf 'https://localhost:%s' "$1"; }

# ---- Wazuh indexer: least-privilege role for the Grafana datasource
configure_indexer_roles() {
    local base="https://localhost:$WAZUH_INDEXER_PORT/_plugins/_security/api" role mapping
    role=$(jq -nc '{
        description: "OpenSOC - read-only access to Wazuh alerts for Grafana",
        cluster_permissions: ["cluster:monitor/main", "cluster:monitor/health", "cluster_composite_ops_ro"],
        index_permissions: [{index_patterns: ["wazuh-alerts-*", "wazuh-archives-*"],
                             allowed_actions: ["read", "indices:admin/mappings/get", "indices:monitor/settings/get"]}]}')
    mapping=$(jq -nc '{users: ["grafana"], description: "OpenSOC Grafana datasource"}')
    api PUT "$base/roles/opensoc_grafana" -u "admin:$WAZUH_INDEXER_PASSWORD" -H 'Content-Type: application/json' -d "$role" >/dev/null
    [[ "$(http_code)" =~ ^20[01]$ ]] || die "Wazuh indexer: could not create the opensoc_grafana role (HTTP $(http_code))"
    api PUT "$base/rolesmapping/opensoc_grafana" -u "admin:$WAZUH_INDEXER_PASSWORD" -H 'Content-Type: application/json' -d "$mapping" >/dev/null
    [[ "$(http_code)" =~ ^20[01]$ ]] || die "Wazuh indexer: could not map the opensoc_grafana role (HTTP $(http_code))"
    ok "Wazuh indexer: read-only opensoc_grafana role mapped to the grafana user"
}

# ---- Cortex: superadmin, organisation and API key used by TheHive
CORTEX_JAR=""
cortex_call() {
    # cortex_call <method> <path> [json]  (session cookie + CSRF token of the admin login)
    local method="$1" path="$2" data="${3:-}" token args=()
    token=$(awk '$6 == "CORTEX-XSRF-TOKEN" { print $7 }' "$CORTEX_JAR" 2>/dev/null | tail -n 1)
    [[ -n "$token" ]] && args+=(-H "X-CORTEX-XSRF-TOKEN: $token")
    [[ -n "$data" ]] && args+=(-H 'Content-Type: application/json' -d "$data")
    api "$method" "$(url_of "$CORTEX_PORT")$path" -b "$CORTEX_JAR" -c "$CORTEX_JAR" "${args[@]}"
}

bootstrap_cortex() {
    local base; base=$(url_of "$CORTEX_PORT")
    retry_until 300 5 bash -c "curl -fs --noproxy '*' --cacert '$CA_CERT' '$base/api/status' >/dev/null" || die "Cortex is not responding at $base"

    if [[ -n "${CORTEX_API_KEY:-}" ]]; then
        api GET "$base/api/user/current" -H "Authorization: Bearer $CORTEX_API_KEY" >/dev/null
        if [[ "$(http_code)" == 200 ]]; then ok "Cortex: TheHive API key is valid"; return; fi
    fi

    api POST "$base/api/maintenance/migrate" -H 'Content-Type: application/json' -d '{}' >/dev/null
    local body
    body=$(jq -nc --arg p "$CORTEX_ADMIN_PASSWORD" --arg l "$CORTEX_ADMIN_LOGIN" \
        '{login: $l, name: "OpenSOC admin", roles: ["superadmin"], preferences: "{}", password: $p, organization: "cortex"}')
    api POST "$base/api/user" -H 'Content-Type: application/json' -d "$body" >/dev/null
    [[ "$(http_code)" == 201 ]] && ok "Cortex: superadmin '$CORTEX_ADMIN_LOGIN' created"

    CORTEX_JAR=$(mktemp)
    # shellcheck disable=SC2064
    trap "rm -f '$CORTEX_JAR'" RETURN
    cortex_call POST /api/login "$(jq -nc --arg u "$CORTEX_ADMIN_LOGIN" --arg p "$CORTEX_ADMIN_PASSWORD" '{user: $u, password: $p}')" >/dev/null
    [[ "$(http_code)" == 200 ]] || die "Cortex: could not log in as '$CORTEX_ADMIN_LOGIN' (HTTP $(http_code))"
    cortex_call GET /api/user/current >/dev/null   # sets the CORTEX-XSRF-TOKEN cookie

    cortex_call POST /api/organization "$(jq -nc --arg o "$THEHIVE_ORG" '{name: $o, description: "OpenSOC", status: "Active"}')" >/dev/null
    [[ "$(http_code)" =~ ^(201|400)$ ]] || die "Cortex: could not create the organization (HTTP $(http_code))"
    cortex_call POST /api/user "$(jq -nc --arg o "$THEHIVE_ORG" --arg l "$CORTEX_THEHIVE_LOGIN" \
        '{login: $l, name: "TheHive", roles: ["read", "analyze", "orgadmin"], organization: $o}')" >/dev/null
    [[ "$(http_code)" =~ ^(201|400)$ ]] || die "Cortex: could not create the TheHive user (HTTP $(http_code))"
    local key
    key=$(cortex_call POST "/api/user/$CORTEX_THEHIVE_LOGIN/key/renew")
    [[ "$(http_code)" == 200 && -n "$key" ]] || die "Cortex: could not generate the API key (HTTP $(http_code))"
    env_set CORTEX_API_KEY "$key"; export CORTEX_API_KEY="$key"
    ok "Cortex: organization '$THEHIVE_ORG' and API key for TheHive created"
}

# ---- TheHive: admin password, organisation, users, integration key, Cortex connector
thehive_admin() { api "$1" "$(url_of "$THEHIVE_PORT")$2" -u "$THEHIVE_ADMIN_LOGIN:$THEHIVE_ADMIN_PASSWORD" -H 'Content-Type: application/json' "${@:3}"; }

bootstrap_thehive() {
    local base; base=$(url_of "$THEHIVE_PORT")
    retry_until 300 5 bash -c "curl -fs --noproxy '*' --cacert '$CA_CERT' '$base/api/status' >/dev/null" || die "TheHive is not responding at $base"

    thehive_admin GET /api/v1/user/current >/dev/null
    if [[ "$(http_code)" != 200 ]]; then
        api POST "$base/api/v1/user/$THEHIVE_ADMIN_LOGIN/password/change" -u "$THEHIVE_ADMIN_LOGIN:secret" \
            -H 'Content-Type: application/json' \
            -d "$(jq -nc --arg p "$THEHIVE_ADMIN_PASSWORD" '{currentPassword: "secret", password: $p}')" >/dev/null
        [[ "$(http_code)" == 204 ]] || die "TheHive: could not change the default password of $THEHIVE_ADMIN_LOGIN (HTTP $(http_code))"
        ok "TheHive: password of $THEHIVE_ADMIN_LOGIN changed"
    fi

    thehive_admin GET "/api/v1/organisation/$THEHIVE_ORG" >/dev/null
    if [[ "$(http_code)" != 200 ]]; then
        thehive_admin POST /api/v1/organisation -d "$(jq -nc --arg o "$THEHIVE_ORG" '{name: $o, description: "OpenSOC security operations"}')" >/dev/null
        [[ "$(http_code)" == 201 ]] || die "TheHive: could not create the organization (HTTP $(http_code))"
        ok "TheHive: organization '$THEHIVE_ORG' created"
    fi

    local login profile name password
    for login in "$THEHIVE_ANALYST_LOGIN" "$THEHIVE_INTEGRATION_LOGIN"; do
        thehive_admin GET "/api/v1/user/$login" >/dev/null
        [[ "$(http_code)" == 200 ]] && continue
        if [[ "$login" == "$THEHIVE_ANALYST_LOGIN" ]]; then
            profile=org-admin; name="SOC analyst"; password="$THEHIVE_ANALYST_PASSWORD"
        else
            profile=analyst; name="OpenSOC integrations (Wazuh, Shuffle)"; password=""
        fi
        thehive_admin POST /api/v1/user -d "$(jq -nc --arg l "$login" --arg n "$name" --arg o "$THEHIVE_ORG" --arg p "$profile" --arg pw "$password" \
            '{login: $l, name: $n, organisation: $o, profile: $p} + (if $pw == "" then {} else {password: $pw} end)')" >/dev/null
        [[ "$(http_code)" == 201 ]] || die "TheHive: could not create the user $login (HTTP $(http_code))"
        ok "TheHive: user $login created ($profile)"
    done

    if [[ -n "${THEHIVE_INTEGRATION_API_KEY:-}" ]]; then
        api GET "$base/api/v1/user/current" -H "Authorization: Bearer $THEHIVE_INTEGRATION_API_KEY" >/dev/null
    else
        printf 401 > "$HTTP_CODE_FILE"
    fi
    if [[ "$(http_code)" != 200 ]]; then
        local key
        key=$(thehive_admin POST "/api/v1/user/$THEHIVE_INTEGRATION_LOGIN/key/renew")
        [[ "$(http_code)" == 200 && -n "$key" ]] || die "TheHive: could not generate the integration API key (HTTP $(http_code))"
        env_set THEHIVE_INTEGRATION_API_KEY "$key"; export THEHIVE_INTEGRATION_API_KEY="$key"
        ok "TheHive: integration API key generated"
    else
        ok "TheHive: integration API key is valid"
    fi

    local cortex_conf
    cortex_conf=$(jq -nc --arg k "$CORTEX_API_KEY" '{
        statusCheckInterval: "1 minute", refreshDelay: "5 seconds", maxRetryOnError: 3, jobTimeout: "3 hours",
        servers: [{name: "Cortex", url: "http://cortex:9001", auth: {type: "bearer", key: $k}, wsConfig: {},
                   includedTheHiveOrganisations: ["*"], excludedTheHiveOrganisations: []}]}')
    thehive_admin PUT /api/v1/admin/config/cortex -H 'X-Organisation: admin' -d "$cortex_conf" >/dev/null
    [[ "$(http_code)" =~ ^20[04]$ ]] || die "TheHive: could not register Cortex (HTTP $(http_code))"
    ok "TheHive: Cortex connector configured"
}

# ---- MISP: admin credentials, automation user, default feeds
misp_cake() { compose exec -T misp su-exec apache /var/www/MISP/app/Console/cake "$@"; }
misp_api() { local key="$1" method="$2" path="$3"; shift 3; api "$method" "$(url_of "$MISP_PORT")$path" -H "Authorization: $key" -H 'Accept: application/json' -H 'Content-Type: application/json' "$@"; }

bootstrap_misp() {
    retry_until 600 10 bash -c "curl -fs --noproxy '*' --cacert '$CA_CERT' -o /dev/null '$(url_of "$MISP_PORT")/users/login'" || die "MISP is not responding"

    misp_api "$MISP_ADMIN_KEY" GET /users/view/me.json >/dev/null
    if [[ "$(http_code)" != 200 ]]; then
        misp_cake user change_authkey "$MISP_DEFAULT_ADMIN" "$MISP_ADMIN_KEY" >/dev/null \
            || misp_cake user change_authkey "$MISP_ADMIN_EMAIL" "$MISP_ADMIN_KEY" >/dev/null \
            || die "MISP: could not set the administrator API key"
        misp_api "$MISP_ADMIN_KEY" GET /users/view/me.json >/dev/null
        [[ "$(http_code)" == 200 ]] || die "MISP: the administrator API key does not work (HTTP $(http_code))"
        ok "MISP: administrator API key configured"
    fi

    local me admin_id admin_email
    me=$(misp_api "$MISP_ADMIN_KEY" GET /users/view/me.json)
    admin_id=$(jq -r '.User.id' <<<"$me"); admin_email=$(jq -r '.User.email' <<<"$me")
    if [[ "$admin_email" != "$MISP_ADMIN_EMAIL" ]]; then
        misp_api "$MISP_ADMIN_KEY" POST "/admin/users/edit/$admin_id" -d "$(jq -nc --arg e "$MISP_ADMIN_EMAIL" '{email: $e}')" >/dev/null
        [[ "$(http_code)" == 200 ]] || warn "MISP: could not change the administrator email (HTTP $(http_code))"
        misp_cake user change_pw "$admin_id" "$MISP_ADMIN_PASSWORD" --no_password_change >/dev/null \
            || die "MISP: could not set the administrator password"
        ok "MISP: administrator $MISP_ADMIN_EMAIL configured"
    fi

    misp_api "$MISP_AUTOMATION_KEY" GET /users/view/me.json >/dev/null
    if [[ "$(http_code)" != 200 ]]; then
        local exists
        exists=$(misp_api "$MISP_ADMIN_KEY" GET /admin/users/index.json | jq -r --arg e "$MISP_AUTOMATION_EMAIL" '[.[] | select(.User.email == $e)] | length')
        if [[ "$exists" == 0 ]]; then
            misp_api "$MISP_ADMIN_KEY" POST /admin/users/add -d "$(jq -nc --arg e "$MISP_AUTOMATION_EMAIL" --arg p "$(gen_password)" \
                '{email: $e, org_id: 1, role_id: 3, password: $p, change_pw: false, termsaccepted: true, notify: false}')" >/dev/null
            [[ "$(http_code)" == 200 ]] || die "MISP: could not create $MISP_AUTOMATION_EMAIL (HTTP $(http_code))"
        fi
        misp_cake user change_authkey "$MISP_AUTOMATION_EMAIL" "$MISP_AUTOMATION_KEY" >/dev/null || die "MISP: could not set the key of $MISP_AUTOMATION_EMAIL"
        misp_api "$MISP_AUTOMATION_KEY" GET /users/view/me.json >/dev/null
        [[ "$(http_code)" == 200 ]] || die "MISP: the key of $MISP_AUTOMATION_EMAIL does not work (HTTP $(http_code))"
        ok "MISP: automation user $MISP_AUTOMATION_EMAIL configured"
    else
        ok "MISP: administration and automation credentials are valid"
    fi

    # Enable the free CIRCL OSINT and Botvrij.eu feeds (fetched daily by MISP when
    # the host has Internet access). Not fatal.
    local feeds id
    feeds=$(misp_api "$MISP_ADMIN_KEY" GET /feeds/index.json)
    for id in $(jq -r '.[] | select((.Feed.name | test("CIRCL OSINT|Botvrij"; "i")) and (.Feed.enabled != true)) | .Feed.id' <<<"$feeds" 2>/dev/null); do
        misp_api "$MISP_ADMIN_KEY" POST "/feeds/enable/$id" -d '{}' >/dev/null
        [[ "$(http_code)" == 200 ]] && ok "MISP: feed $id enabled"
    done
}

# ---- Shuffle: apps, example playbook and its webhook
shuffle_api() { local method="$1" path="$2"; shift 2; api "$method" "$(url_of "$SHUFFLE_PORT")$path" -H "Authorization: Bearer $SHUFFLE_API_KEY" -H 'Content-Type: application/json' "$@"; }

shuffle_http_app() {
    shuffle_api GET /api/v1/apps | jq -c '[.[]? | select(.name == "http")] | sort_by(.app_version) | last // empty' 2>/dev/null
}

bootstrap_shuffle() {
    retry_until 300 5 bash -c "curl -fs --noproxy '*' --cacert '$CA_CERT' -o /dev/null -H 'Authorization: Bearer $SHUFFLE_API_KEY' '$(url_of "$SHUFFLE_PORT")/api/v1/getinfo'" \
        || die "Shuffle: the API rejects the key of $SHUFFLE_ADMIN_USER"

    local app
    app=$(shuffle_http_app)
    if [[ -z "$app" ]]; then
        info "Shuffle: loading apps (hotload)"
        shuffle_api GET /api/v1/apps/run_hotload >/dev/null
        retry_until 300 10 bash -c "[[ -n \"\$(curl -fsS --noproxy '*' --cacert '$CA_CERT' -H 'Authorization: Bearer $SHUFFLE_API_KEY' '$(url_of "$SHUFFLE_PORT")/api/v1/apps' | jq -c '.[]? | select(.name == \"http\")' 2>/dev/null)\" ]]" \
            || die "Shuffle: the 'http' app is not available (no GitHub access?). Copy Shuffle/python-apps/http into $DATA_DIR/shuffle-apps and try again."
        app=$(shuffle_http_app)
    fi
    local app_id app_version
    app_id=$(jq -r '.id' <<<"$app"); app_version=$(jq -r '.app_version' <<<"$app")

    local workflow
    workflow=$(sed -e "s|__WEBHOOK_ID__|$SHUFFLE_WEBHOOK_ID|g" -e "s|__HTTP_APP_ID__|$app_id|g" -e "s|__HTTP_APP_VERSION__|$app_version|g" \
        -e "s|__MISP_API_KEY__|$MISP_AUTOMATION_KEY|g" -e "s|__THEHIVE_API_KEY__|$THEHIVE_INTEGRATION_API_KEY|g" \
        -e "s|__THEHIVE_ORG__|$THEHIVE_ORG|g" "$INFRA_DIR/config/shuffle/workflows/misp-ioc-triage.json")

    local workflow_id
    workflow_id=$(shuffle_api GET /api/v1/workflows | jq -r --arg n "$SHUFFLE_WORKFLOW_NAME" '[.[]? | select(.name == $n)][0].id // empty')
    if [[ -z "$workflow_id" ]]; then
        workflow_id=$(shuffle_api POST /api/v1/workflows -d "$workflow" | jq -r '.id // empty')
        [[ -n "$workflow_id" ]] || die "Shuffle: could not create the playbook (HTTP $(http_code))"
        ok "Shuffle: playbook '$SHUFFLE_WORKFLOW_NAME' imported"
    fi
    shuffle_api PUT "/api/v1/workflows/$workflow_id" -d "$(jq -c --arg id "$workflow_id" '. + {id: $id, previously_saved: true}' <<<"$workflow")" >/dev/null
    [[ "$(http_code)" == 200 ]] || die "Shuffle: could not save the playbook (HTTP $(http_code))"

    local start hook
    start=$(jq -r '.start' <<<"$workflow")
    hook=$(jq -nc --arg id "$SHUFFLE_WEBHOOK_ID" --arg wf "$workflow_id" --arg start "$start" \
        '{name: "Wazuh alert", type: "webhook", id: $id, workflow: $wf, start: $start, environment: "Shuffle", auth: "", custom_response: "", version: ""}')
    local out; out=$(shuffle_api POST /api/v1/hooks/new -d "$hook")
    if [[ "$(http_code)" == 200 ]] || grep -qi 'exist' <<<"$out"; then
        ok "Shuffle: playbook webhook active (Wazuh -> /api/v1/hooks/webhook_<id>)"
    else
        die "Shuffle: could not enable the webhook (HTTP $(http_code)): ${out:0:200}"
    fi
}

configure_integrations() {
    title "6/7 Configuring integrations"
    configure_indexer_roles
    bootstrap_cortex
    bootstrap_thehive
    bootstrap_misp
    bootstrap_shuffle
    load_env
    render_ossec_conf || true
    # Recreate the manager when any file under /wazuh-config-mount (ossec.conf, rules,
    # integration scripts) differs from the copy in use.
    # shellcheck disable=SC2016  # expanded inside the container
    if ! compose exec -T wazuh.manager sh -c 'cd /wazuh-config-mount && find . -type f | while read -r f; do [ "$(md5sum < "$f")" = "$(md5sum < "/var/ossec/$f")" ] || exit 1; done'; then
        # The manager image copies /wazuh-config-mount only when the container is created.
        info "applying the Wazuh integration configuration (recreating wazuh.manager)"
        compose up -d --force-recreate --no-deps wazuh.manager >/dev/null 2>&1
        wait_for_services 600 wazuh.manager || die "wazuh.manager did not come back up"
    fi
    # Upstream init aborts on restart when this permanent-data directory is empty.
    compose exec -T wazuh.manager touch /var/ossec/var/multigroups/.keep
    ok "Wazuh -> TheHive, MISP -> Wazuh and Wazuh -> Shuffle configured"
    # First IOC export right away (the service then runs every MISP_SYNC_INTERVAL s).
    if compose exec -T misp-ioc-sync python /app/misp_to_wazuh.py --once >/dev/null; then
        ok "MISP -> Wazuh: first IOC synchronization completed"
        wait_for_services 180 misp-ioc-sync || warn "misp-ioc-sync is not healthy yet"
    else
        warn "MISP -> Wazuh: the first synchronization failed (it will be retried automatically)"
    fi
}

# ================================================================== 7. summary
summary() {
    title "7/7 OpenSOC is ready"
    local h="$OPENSOC_HOSTNAME"
    printf '\n  %-16s %-34s %s\n' "Service" "URL" "User"
    printf '  %-16s %-34s %s\n' "----------------" "----------------------------------" "------------------------------"
    printf '  %-16s %-34s %s\n' \
        "Wazuh dashboard" "https://$h:$WAZUH_DASHBOARD_PORT" "admin" \
        "TheHive" "https://$h:$THEHIVE_PORT" "$THEHIVE_ANALYST_LOGIN / $THEHIVE_ADMIN_LOGIN" \
        "Cortex" "https://$h:$CORTEX_PORT" "$CORTEX_ADMIN_LOGIN" \
        "MISP" "https://$h:$MISP_PORT" "$MISP_ADMIN_EMAIL" \
        "Shuffle" "https://$h:$SHUFFLE_PORT" "$SHUFFLE_ADMIN_USER" \
        "Grafana" "https://$h:$GRAFANA_PORT" "admin" \
        "Wazuh API" "https://$h:$WAZUH_API_PORT" "wazuh-wui"
    cat <<EOF

  Passwords:       $ENV_FILE  (e.g. grep PASSWORD $ENV_FILE)
  Root CA (TLS):   $CA_CERT  (import it into your browser to avoid warnings)
  Wazuh agents:    ports 1514/1515, WAZUH_REGISTRATION_PASSWORD=<WAZUH_ENROLLMENT_PASSWORD from .env>
  Verification:    sudo $INFRA_DIR/verify.sh

EOF
}

main() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --skip-checks) SKIP_CHECKS=1 ;;
            --no-pull) SKIP_PULL=1 ;;
            -h|--help) usage; exit 0 ;;
            *) usage; die "unknown option: $1" ;;
        esac
        shift
    done
    cd "$INFRA_DIR"
    check_requirements
    init_env
    generate_pki
    render_configs
    start_stack
    configure_integrations
    summary
}

main "$@"
