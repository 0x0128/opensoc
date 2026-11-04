---
# Rendered by install.sh into generated/wazuh/internal_users.yml.
# Hashes are bcrypt hashes of the passwords stored in infra/.env.
# The demo users shipped with the Wazuh indexer (kibanaro, logstash, readall,
# snapshotrestore) are intentionally removed.

_meta:
  type: "internalusers"
  config_version: 2

admin:
  hash: "__ADMIN_HASH__"
  reserved: true
  backend_roles:
    - "admin"
  description: "OpenSOC indexer administrator (Wazuh manager/filebeat and dashboard)"

kibanaserver:
  hash: "__KIBANASERVER_HASH__"
  reserved: true
  description: "Wazuh dashboard server user"

grafana:
  hash: "__GRAFANA_HASH__"
  reserved: false
  description: "Grafana datasource (role opensoc_grafana, created by install.sh)"
