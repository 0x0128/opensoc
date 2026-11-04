"""Loading and validation of the scenario catalog (emulation/scenarios.yaml)."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..mitre import normalize_technique
from ..paths import SCENARIOS_FILE

PLATFORMS = ("windows", "linux", "macos")
GUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
SCENARIO_ID_RE = re.compile(r"^EMU-\d{2,3}$")
HYPOTHESIS_ID_RE = re.compile(r"^H\d{2}$")


class CatalogError(ValueError):
    """The scenario catalog is not valid."""


@dataclass(frozen=True)
class AtomicRef:
    technique: str
    guid: str
    name: str
    elevation_required: bool = False
    input_args: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class DetectionSpec:
    mitre_ids: tuple[str, ...]
    rule_ids: tuple[str, ...] = ()
    min_level: int = 3
    timeout: int = 180


@dataclass(frozen=True)
class Scenario:
    id: str
    name: str
    platform: str
    technique: str
    atomic: AtomicRef
    detection: DetectionSpec
    technique_aliases: tuple[str, ...] = ()
    tactics: tuple[str, ...] = ()
    description: str = ""
    telemetry: tuple[str, ...] = ()
    requirements: tuple[str, ...] = ()
    hypotheses: tuple[str, ...] = ()
    irreversible: bool = False

    @property
    def techniques(self) -> tuple[str, ...]:
        """Main technique + aliases (legacy IDs)."""
        return (self.technique, *self.technique_aliases)


def _as_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, (str, int)):
        return (str(value),)
    return tuple(str(v) for v in value)


def _parse_scenario(raw: Mapping[str, Any], defaults: Mapping[str, Any]) -> Scenario:
    sid = str(raw.get("id", "")).strip()
    if not SCENARIO_ID_RE.match(sid):
        raise CatalogError(f"invalid scenario ID: {sid!r} (format EMU-NN)")

    def fail(msg: str) -> CatalogError:
        return CatalogError(f"{sid}: {msg}")

    for key in ("name", "platform", "technique", "atomic"):
        if not raw.get(key):
            raise fail(f"missing required field '{key}'")

    platform = str(raw["platform"]).lower()
    if platform not in PLATFORMS:
        raise fail(f"unsupported platform {platform!r}; use one of {PLATFORMS}")

    try:
        technique = normalize_technique(str(raw["technique"]))
        aliases = tuple(normalize_technique(a) for a in _as_tuple(raw.get("technique_aliases")))
    except ValueError as exc:
        raise fail(str(exc)) from exc

    atomic_raw = raw["atomic"]
    if not isinstance(atomic_raw, Mapping):
        raise fail("'atomic' must be a mapping")
    guid = str(atomic_raw.get("guid", "")).lower()
    if not GUID_RE.match(guid):
        raise fail(f"invalid Atomic Red Team GUID: {guid!r}")
    try:
        atomic_technique = normalize_technique(str(atomic_raw.get("technique") or technique))
    except ValueError as exc:
        raise fail(str(exc)) from exc
    input_args = atomic_raw.get("input_args") or {}
    if not isinstance(input_args, Mapping):
        raise fail("'atomic.input_args' must be a mapping")
    atomic = AtomicRef(
        technique=atomic_technique,
        guid=guid,
        name=str(atomic_raw.get("name") or ""),
        elevation_required=bool(atomic_raw.get("elevation_required", False)),
        input_args={str(k): str(v) for k, v in input_args.items()},
    )

    det_raw = raw.get("detection") or {}
    if not isinstance(det_raw, Mapping):
        raise fail("'detection' must be a mapping")
    try:
        mitre_ids = tuple(normalize_technique(t) for t in _as_tuple(det_raw.get("mitre_ids"))) or (
            technique,
            *aliases,
        )
    except ValueError as exc:
        raise fail(str(exc)) from exc
    detection = DetectionSpec(
        mitre_ids=mitre_ids,
        rule_ids=_as_tuple(det_raw.get("rule_ids")),
        min_level=int(det_raw.get("min_level", defaults.get("min_level", 3))),
        timeout=int(det_raw.get("timeout", defaults.get("detection_timeout", 180))),
    )
    if detection.timeout <= 0:
        raise fail("detection.timeout must be > 0")

    hypotheses = _as_tuple(raw.get("hypotheses"))
    for hid in hypotheses:
        if not HYPOTHESIS_ID_RE.match(hid):
            raise fail(f"invalid hypothesis reference: {hid!r}")

    return Scenario(
        id=sid,
        name=str(raw["name"]),
        platform=platform,
        technique=technique,
        technique_aliases=aliases,
        tactics=_as_tuple(raw.get("tactics")),
        description=" ".join(str(raw.get("description") or "").split()),
        atomic=atomic,
        detection=detection,
        telemetry=_as_tuple(raw.get("telemetry")),
        requirements=_as_tuple(raw.get("requirements")),
        hypotheses=hypotheses,
        irreversible=bool(raw.get("irreversible", False)),
    )


def parse_catalog(data: Mapping[str, Any]) -> list[Scenario]:
    if not isinstance(data, Mapping) or not isinstance(data.get("scenarios"), list):
        raise CatalogError("the catalog must have a 'scenarios' list")
    defaults = data.get("defaults") or {}
    scenarios = [_parse_scenario(item, defaults) for item in data["scenarios"]]
    seen: set[str] = set()
    for scenario in scenarios:
        if scenario.id in seen:
            raise CatalogError(f"duplicate scenario ID: {scenario.id}")
        seen.add(scenario.id)
    return scenarios


def load_scenarios(path: Path | str = SCENARIOS_FILE) -> list[Scenario]:
    with open(path, encoding="utf-8") as fh:
        return parse_catalog(yaml.safe_load(fh))


def select_scenarios(
    scenarios: Iterable[Scenario],
    ids: Iterable[str] | None = None,
    platform: str | None = None,
) -> list[Scenario]:
    """Filters by IDs (EMU-01, emu-1...) and/or platform. Raises CatalogError if an ID does not exist."""
    scenarios = list(scenarios)
    wanted = [_normalize_id(i) for i in ids or []]
    if wanted:
        by_id = {s.id: s for s in scenarios}
        missing = [i for i in wanted if i not in by_id]
        if missing:
            raise CatalogError(f"unknown scenarios: {', '.join(missing)}")
        scenarios = [by_id[i] for i in wanted]
    if platform:
        scenarios = [s for s in scenarios if s.platform == platform.lower()]
    return scenarios


def _normalize_id(value: str) -> str:
    value = value.strip().upper()
    match = re.match(r"^(?:EMU-?)?(\d{1,3})$", value)
    if match:
        return f"EMU-{int(match.group(1)):02d}"
    return value
