"""Stable Sigma rule -> Wazuh rule ID allocation.

Each Sigma rule owns a block of ``BLOCK_SIZE`` consecutive Wazuh IDs. A Sigma rule
whose condition cannot be expressed as a single Wazuh rule (Wazuh only ANDs the
conditions of one rule) is split into several Wazuh rules that use the IDs of its
block. The registry is committed so IDs never change when rules are added/removed.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from opensoc_detections.config import RULE_IDS_FILE

FIRST_ID = 110000  # Wazuh user range is 100000-120000; 100000-109999 is left for local_rules.xml
LAST_ID = 119999
BLOCK_SIZE = 10

HEADER = (
    "# Sigma rule id -> first Wazuh rule ID of its block (block size "
    f"{BLOCK_SIZE}).\n"
    "# Managed by `python -m opensoc_detections convert`: new rules get the next free\n"
    "# block, existing entries never change. OpenSOC range: 110000-119999.\n"
)


class RuleIdRegistry:
    def __init__(self, path: Path = RULE_IDS_FILE):
        self.path = path
        self.ids: dict[str, int] = {}
        if path.exists():
            with open(path, encoding="utf-8") as fh:
                self.ids = {str(k): int(v) for k, v in (yaml.safe_load(fh) or {}).items()}
        self._check()
        self.dirty = False

    def _check(self) -> None:
        seen: dict[int, str] = {}
        for sigma_id, base in self.ids.items():
            if base < FIRST_ID or base + BLOCK_SIZE - 1 > LAST_ID or (base - FIRST_ID) % BLOCK_SIZE:
                raise ValueError(f"{self.path}: invalid Wazuh base id {base} for {sigma_id}")
            if base in seen:
                raise ValueError(f"{self.path}: Wazuh id {base} assigned twice ({seen[base]}, {sigma_id})")
            seen[base] = sigma_id

    def get(self, sigma_id: str) -> int | None:
        return self.ids.get(str(sigma_id))

    def assign(self, sigma_id: str) -> int:
        sigma_id = str(sigma_id)
        if sigma_id in self.ids:
            return self.ids[sigma_id]
        used = set(self.ids.values())
        base = FIRST_ID
        while base in used:
            base += BLOCK_SIZE
        if base + BLOCK_SIZE - 1 > LAST_ID:
            raise ValueError("Wazuh custom rule ID range exhausted")
        self.ids[sigma_id] = base
        self.dirty = True
        return base

    def orphans(self, known_ids: set[str]) -> list[str]:
        return sorted(set(self.ids) - known_ids)

    def save(self) -> None:
        body = yaml.safe_dump(
            dict(sorted(self.ids.items(), key=lambda kv: kv[1])), sort_keys=False, default_flow_style=False
        )
        self.path.write_text(HEADER + body, encoding="utf-8")
        self.dirty = False
