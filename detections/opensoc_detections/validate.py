"""Rule validation: sigma-cli ``sigma check`` plus the OpenSOC detection policy.

Policy enforced on every rule (errors fail CI):

* file name: lower snake case, prefix matching its logsource (config/wazuh_mapping.yml)
* metadata: title, UUID id (unique), status, description, references, author, date,
  level and *documented* false positives ("unknown"/"none" are rejected)
* MITRE ATT&CK: at least one technique and one tactic tag, techniques must exist in
  the bundled ATT&CK release (revoked/deprecated ones are rejected with their
  replacement), every technique must belong to one of the rule's tactics and every
  tactic tag must be justified by a technique
* logsource must have a Wazuh mapping and the rule must convert to Wazuh XML
* a sample file with at least one ``match`` and one ``no_match`` case must exist
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path

from sigma.collection import SigmaCollection

from opensoc_detections import attack
from opensoc_detections.config import RULES_DIR, SIGMA_CHECK_CONFIG, mapping_for
from opensoc_detections.loader import load_rule, load_samples, rule_files, rule_yaml, sample_path

REQUIRED_FIELDS = (
    "title", "id", "status", "description", "references", "author", "date",
    "tags", "logsource", "detection", "falsepositives", "level",
)
ALLOWED_STATUS = {"stable", "test", "experimental"}
ALLOWED_LEVELS = {"informational", "low", "medium", "high", "critical"}
VAGUE_FALSE_POSITIVES = {"unknown", "none", "n/a", "na", "-", "unlikely"}
FILENAME = re.compile(r"^[a-z0-9]+(?:_[a-z0-9]+)*\.yml$")


@dataclass(frozen=True)
class Issue:
    severity: str  # "error" | "warning"
    path: str
    message: str

    def __str__(self) -> str:
        return f"[{self.severity.upper()}] {self.path}: {self.message}"


def _rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(RULES_DIR.resolve().parent))
    except ValueError:
        return str(path)


# --------------------------------------------------------------- sigma-cli
_SIGMA_BOOTSTRAP = (
    "import os, sys\n"
    "stix = os.environ.get('OPENSOC_ATTACK_STIX')\n"
    "if stix:\n"
    "    from sigma.data import mitre_attack\n"
    "    mitre_attack.set_url(stix)\n"
    "from sigma.cli.main import main\n"
    "sys.argv = ['sigma'] + sys.argv[1:]\n"
    "sys.exit(main())\n"
)


def run_sigma_check(paths: list[Path], attack_stix: str | None = None) -> tuple[int, str]:
    """Run ``sigma check`` (sigma-cli) and return (exit code, output).

    ``attack_stix`` (or $OPENSOC_ATTACK_STIX) points pySigma at a local/alternative
    ATT&CK STIX bundle for offline environments; by default pySigma downloads it.
    """
    env = dict(os.environ)
    if attack_stix:
        env["OPENSOC_ATTACK_STIX"] = attack_stix
    cmd = [
        sys.executable, "-c", _SIGMA_BOOTSTRAP, "check",
        "--validation-config", str(SIGMA_CHECK_CONFIG),
        "--fail-on-error", "--fail-on-issues",
        *[str(p) for p in paths],
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, env=env)
    return res.returncode, (res.stdout + res.stderr).strip()


# ------------------------------------------------------------ OpenSOC policy
def _check_attack(path: str, tags: list[str], issues: list[Issue]) -> None:
    data = attack.load()
    techniques, tactics = attack.parse_tags(tags)
    if not techniques:
        issues.append(Issue("error", path, "no ATT&CK technique tag (attack.tXXXX[.YYY])"))
    if not tactics:
        issues.append(Issue("error", path, "no ATT&CK tactic tag (e.g. attack.execution)"))
    tactic_names = set()
    for t in tactics:
        tac = data.tactic_by_tag(t)
        if tac is None:
            issues.append(Issue("error", path, f"unknown ATT&CK tactic tag 'attack.{t}'"))
        elif "_" in t:
            issues.append(Issue("error", path, f"tactic tag 'attack.{t}' must use '-' (attack.{tac.shortname})"))
        else:
            tactic_names.add(tac.shortname)
    used_tactics: set[str] = set()
    for tid in techniques:
        tech = data.technique(tid)
        if tech is None:
            why = data.deprecated.get(tid)
            hint = f" ({why} in ATT&CK v{data.version})" if why else ""
            issues.append(Issue("error", path, f"ATT&CK technique {tid} does not exist{hint}"))
            continue
        overlap = set(tech.tactics) & tactic_names
        if tactic_names and not overlap:
            issues.append(
                Issue("error", path, f"{tid} ({tech.full_name}) belongs to {list(tech.tactics)}, "
                      "none of which is tagged on the rule")
            )
        used_tactics |= set(tech.tactics)
    for tac in sorted(tactic_names - used_tactics):
        if techniques:
            issues.append(Issue("error", path, f"tactic '{tac}' is not justified by any technique tag"))


def check_rule_file(path: Path) -> list[Issue]:
    rel = _rel(path)
    issues: list[Issue] = []
    if not FILENAME.match(path.name):
        issues.append(Issue("error", rel, "file name must be lower snake case and end in .yml"))
    try:
        raw = rule_yaml(path)
    except Exception as exc:
        return issues + [Issue("error", rel, f"invalid YAML: {exc}")]
    if not isinstance(raw, dict):
        return issues + [Issue("error", rel, "rule file must contain a YAML mapping")]
    try:
        rule = load_rule(path)
    except Exception as exc:  # also reported by sigma check
        rule = None
        issues.append(Issue("error", rel, f"cannot be parsed by pySigma: {exc}"))

    for f in REQUIRED_FIELDS:
        if raw.get(f) in (None, "", [], {}):
            issues.append(Issue("error", rel, f"missing required field '{f}'"))
    try:
        if uuid.UUID(str(raw.get("id"))).version != 4:
            issues.append(Issue("warning", rel, "id should be a random UUIDv4"))
    except ValueError:
        issues.append(Issue("error", rel, f"id '{raw.get('id')}' is not a UUID"))
    if raw.get("status") not in ALLOWED_STATUS:
        issues.append(Issue("error", rel, f"status must be one of {sorted(ALLOWED_STATUS)}"))
    if raw.get("level") not in ALLOWED_LEVELS:
        issues.append(Issue("error", rel, f"level must be one of {sorted(ALLOWED_LEVELS)}"))
    if len(str(raw.get("title", ""))) > 110:
        issues.append(Issue("error", rel, "title longer than 110 characters"))
    fps = raw.get("falsepositives") or []
    if not isinstance(fps, list) or not fps:
        issues.append(Issue("error", rel, "falsepositives must be a non-empty list"))
    elif any(str(fp).strip().lower().rstrip(".") in VAGUE_FALSE_POSITIVES for fp in fps):
        issues.append(Issue("error", rel, "document concrete false positives instead of 'Unknown'/'None'"))
    refs = raw.get("references") or []
    if any(not str(r).startswith(("http://", "https://")) for r in refs):
        issues.append(Issue("error", rel, "references must be URLs"))

    _check_attack(rel, [str(t) for t in raw.get("tags") or []], issues)
    if rule is None:
        return issues

    mapping = mapping_for(rule.logsource)
    if mapping is None:
        issues.append(Issue("error", rel, f"logsource {dict(raw.get('logsource', {}))} has no Wazuh mapping"))
    elif mapping.rule_prefix and not path.name.startswith(mapping.rule_prefix):
        issues.append(Issue("error", rel, f"file name must start with '{mapping.rule_prefix}' for this logsource"))

    spath = sample_path(path)
    if not spath.exists():
        issues.append(Issue("error", rel, f"missing test samples {_rel(spath)}"))
    else:
        try:
            samples = load_samples(spath)
        except ValueError as exc:
            issues.append(Issue("error", _rel(spath), str(exc)))
        else:
            if samples.rule_id != str(rule.id):
                issues.append(Issue("error", _rel(spath), f"rule_id {samples.rule_id} != rule id {rule.id}"))
            kinds = {c.expect for c in samples.cases}
            for needed in ("match", "no_match"):
                if needed not in kinds:
                    issues.append(Issue("error", _rel(spath), f"needs at least one '{needed}' case"))
    return issues


def check_collection(paths: list[Path], full_ruleset: bool = True) -> list[Issue]:
    issues: list[Issue] = []
    ids: dict[str, Path] = {}
    titles: dict[str, Path] = {}
    for p in paths:
        try:
            raw = rule_yaml(p)
        except Exception:
            continue
        rid, title = str(raw.get("id")), str(raw.get("title", "")).strip().lower()
        if rid in ids:
            issues.append(Issue("error", _rel(p), f"duplicate id {rid} (also in {_rel(ids[rid])})"))
        ids.setdefault(rid, p)
        if title in titles:
            issues.append(Issue("error", _rel(p), f"duplicate title (also in {_rel(titles[title])})"))
        titles.setdefault(title, p)
    if full_ruleset:  # every sample file must belong to a rule
        from opensoc_detections.config import SAMPLES_DIR

        expected = {sample_path(p).resolve() for p in paths}
        for sample in sorted(SAMPLES_DIR.rglob("*.yml")):
            if sample.resolve() not in expected:
                issues.append(Issue("error", _rel(sample), "sample file without a matching rule"))
    return issues


def check_conversion(paths: list[Path]) -> list[Issue]:
    """Every rule must convert to Wazuh XML (uses a throw-away ID registry)."""
    from opensoc_detections.wazuh.backend import WazuhBackend
    from opensoc_detections.wazuh.ids import RuleIdRegistry

    issues = []
    for p in paths:
        try:
            rule = load_rule(p)
        except Exception:
            continue
        registry = RuleIdRegistry.__new__(RuleIdRegistry)
        registry.path, registry.ids, registry.dirty = Path(os.devnull), {}, False
        try:
            WazuhBackend(id_registry=registry).convert(SigmaCollection([rule]))
        except Exception as exc:
            issues.append(Issue("error", _rel(p), f"Wazuh conversion failed: {exc}"))
    return issues


def validate(paths: list[Path] | None = None, sigma_cli: bool = True, attack_stix: str | None = None):
    """Run all checks. Returns (issues, sigma-cli exit code or None, sigma-cli output)."""
    full_ruleset = paths is None
    paths = paths or rule_files()
    issues: list[Issue] = []
    for p in paths:
        issues.extend(check_rule_file(p))
    issues.extend(check_collection(paths, full_ruleset))
    issues.extend(check_conversion(paths))
    code, output = (None, "")
    if sigma_cli:
        code, output = run_sigma_check([RULES_DIR] if full_ruleset else paths, attack_stix)
        if code != 0:
            issues.append(Issue("error", "sigma check", "sigma-cli reported errors or issues (see output)"))
    return issues, code, output
