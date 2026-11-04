"""sigma-cli plugin entry: exposes the OpenSOC Wazuh backend as `-t opensoc_wazuh`.

    sigma convert -t opensoc_wazuh rules/            # Wazuh XML on stdout
"""

from opensoc_detections.wazuh.backend import WazuhBackend

backends = {"opensoc_wazuh": WazuhBackend}
