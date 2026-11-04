"""Orchestration: run scenario -> wait for alert -> cleanup -> result."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from .checker import DetectionCheck, DetectionChecker, iso_utc, utcnow
from .detections import DetectionIndex
from .executor import AtomicExecutor, ExecResult
from .scenarios import Scenario


class LabGuardError(RuntimeError):
    """Attempt to run outside the hosts declared as lab hosts."""


class Status(str, Enum):
    DETECTED = "DETECTED"
    MISSED = "MISSED"
    EXEC_ERROR = "EXEC_ERROR"
    CHECK_ERROR = "CHECK_ERROR"
    SKIPPED = "SKIPPED"
    DRY_RUN = "DRY_RUN"


@dataclass
class ScenarioResult:
    scenario_id: str
    name: str
    technique: str
    platform: str
    status: Status
    target: str
    started_at: str | None = None
    finished_at: str | None = None
    alerts: list[dict[str, Any]] = field(default_factory=list)
    expected_rule_ids: list[str] = field(default_factory=list)
    detections: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    execution: dict[str, Any] | None = None
    query: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


def parse_lab_targets(raw: str | None) -> set[str]:
    return {t.strip().lower() for t in (raw or "").split(",") if t.strip()}


def ensure_lab_target(target: str, lab_targets: Iterable[str]) -> None:
    """Raises LabGuardError if ``target`` is not declared as a lab host."""
    allowed = {t.lower() for t in lab_targets}
    if not allowed:
        raise LabGuardError(
            "OPENSOC_LAB_TARGETS is empty: declare the lab hosts "
            "(e.g. OPENSOC_LAB_TARGETS=win10-lab,ubuntu-lab) before using --execute."
        )
    if target.lower() not in allowed:
        raise LabGuardError(
            f"'{target}' is not in OPENSOC_LAB_TARGETS ({', '.join(sorted(allowed))}). "
            "Tests only run on hosts of your own lab."
        )


def _tail(text: str, limit: int = 2000) -> str:
    return text if len(text) <= limit else "…" + text[-limit:]


def _exec_summary(result: ExecResult) -> dict[str, Any]:
    return {
        "action": result.action,
        "returncode": result.returncode,
        "duration_s": round(result.duration, 1),
        "stdout_tail": _tail(result.stdout),
        "stderr_tail": _tail(result.stderr),
    }


class EmulationRunner:
    def __init__(
        self,
        executor: AtomicExecutor,
        checker: DetectionChecker | None,
        *,
        target: str,
        lab_targets: Iterable[str],
        execute: bool = False,
        prereqs: bool = False,
        cleanup: bool = True,
        strict: bool = False,
        allow_irreversible: bool = False,
        detection_index: DetectionIndex | None = None,
        input_overrides: Mapping[str, Mapping[str, str]] | None = None,
        clock_skew: float = 30.0,
        detection_timeout: float | None = None,
        now: Callable[[], datetime] = utcnow,
        log: Callable[[str], None] = print,
    ):
        self.executor = executor
        self.checker = checker
        self.target = target
        self.lab_targets = {t.lower() for t in lab_targets}
        self.execute = execute
        self.prereqs = prereqs
        self.cleanup = cleanup
        self.strict = strict
        self.allow_irreversible = allow_irreversible
        self.detection_index = detection_index or DetectionIndex([])
        self.input_overrides = {k.upper(): dict(v) for k, v in (input_overrides or {}).items()}
        self.clock_skew = clock_skew
        self.detection_timeout = detection_timeout
        self._now = now
        self._log = log
        if execute:
            self.ensure_lab_target()
            if checker is None:
                raise ValueError("a DetectionChecker is required to run scenarios")

    def ensure_lab_target(self) -> None:
        ensure_lab_target(self.target, self.lab_targets)

    # ------------------------------------------------------------------ helpers
    def expected_rule_ids(self, scenario: Scenario) -> list[str]:
        ids = list(scenario.detection.rule_ids) + list(self.detection_index.rule_ids_for(scenario))
        return list(dict.fromkeys(ids))

    def _base_result(self, scenario: Scenario, status: Status) -> ScenarioResult:
        return ScenarioResult(
            scenario_id=scenario.id,
            name=scenario.name,
            technique=scenario.technique,
            platform=scenario.platform,
            status=status,
            target=self.target,
            expected_rule_ids=self.expected_rule_ids(scenario),
            detections=[ref.label() for ref in self.detection_index.for_scenario(scenario)],
        )

    def _accept(self, rule_ids: list[str]) -> Callable[[DetectionCheck], bool]:
        if self.strict:
            return lambda check: bool(check.matching(rule_ids))
        return lambda check: bool(check.alerts)

    def _apply_check(self, result: ScenarioResult, scenario: Scenario, check: DetectionCheck) -> None:
        result.query = check.query
        result.alerts = [asdict(a) for a in check.alerts]
        rule_ids = result.expected_rule_ids
        if self.strict:
            hits = check.matching(rule_ids)
            if not rule_ids:
                result.notes.append("--strict without /detections rules or rule_ids for this technique")
        else:
            hits = check.alerts
        result.status = Status.DETECTED if hits else Status.MISSED
        if hits:
            fired = sorted({f"{a.rule_id} ({a.rule_description})" for a in hits})
            result.notes.append("Rules that fired: " + "; ".join(fired))
            if rule_ids and not check.matching(rule_ids):
                result.notes.append(
                    "Generic Wazuh rules fired, but none of the /detections ones: "
                    + ", ".join(rule_ids)
                )
        else:
            result.notes.append(
                f"No alerts with rule.mitre.id in {list(scenario.detection.mitre_ids)}"
                + (f" or rule.id in {rule_ids}" if rule_ids else "")
                + f" for agent '{self.target}'."
            )

    def _query_kwargs(self, scenario: Scenario, rule_ids: list[str]) -> dict[str, Any]:
        return {
            "mitre_ids": scenario.detection.mitre_ids,
            "rule_ids": rule_ids,
            "agent": self.target,
            "min_level": scenario.detection.min_level,
        }

    # -------------------------------------------------------------------- API
    def run(self, scenarios: Iterable[Scenario]) -> list[ScenarioResult]:
        return [self.run_one(s) for s in scenarios]

    def run_one(self, scenario: Scenario) -> ScenarioResult:
        overrides = self.input_overrides.get(scenario.id, {})

        if scenario.irreversible and not self.allow_irreversible:
            result = self._base_result(scenario, Status.SKIPPED)
            result.notes.append("Irreversible scenario (no cleanup): use --allow-irreversible to run it.")
            self._log(f"[{scenario.id}] SKIPPED (irreversible)")
            return result

        if not self.execute:
            result = self._base_result(scenario, Status.DRY_RUN)
            result.execution = {"script": self.executor.build_script(scenario, "run", overrides)}
            if self.cleanup:
                result.execution["cleanup_script"] = self.executor.build_script(scenario, "cleanup", overrides)
            result.notes.append("Dry-run mode: nothing was executed (use --execute).")
            self._log(f"[{scenario.id}] DRY_RUN {scenario.atomic.technique} {scenario.atomic.guid}")
            return result

        self.ensure_lab_target()
        result = self._base_result(scenario, Status.MISSED)
        self._log(f"[{scenario.id}] {scenario.name} ({scenario.technique}) -> {self.target}")

        if self.prereqs:
            pre = self.executor.run(scenario, "prereqs", overrides)
            if not pre.ok:
                result.status = Status.EXEC_ERROR
                result.execution = _exec_summary(pre)
                result.notes.append("-GetPrereqs failed")
                return result

        start = self._now() - timedelta(seconds=self.clock_skew)
        result.started_at = iso_utc(start)
        execution = self.executor.run(scenario, "run", overrides)
        result.execution = _exec_summary(execution)

        if not execution.ok:
            result.status = Status.EXEC_ERROR
            result.notes.append(
                "Invoke-AtomicTest ended with an error; alerts are searched anyway in case the technique did run."
            )

        rule_ids = result.expected_rule_ids
        try:
            assert self.checker is not None
            timeout = self.detection_timeout if self.detection_timeout is not None else scenario.detection.timeout
            deadline = self._now() + timedelta(seconds=timeout)
            check = self.checker.wait_for(
                start=start,
                deadline=deadline,
                accept=self._accept(rule_ids),
                **self._query_kwargs(scenario, rule_ids),
            )
            status_before = result.status
            self._apply_check(result, scenario, check)
            if status_before is Status.EXEC_ERROR and result.status is Status.MISSED:
                result.status = Status.EXEC_ERROR
        except Exception as exc:  # noqa: BLE001 - reported in the result
            result.status = Status.CHECK_ERROR
            result.notes.append(f"Error querying the indexer: {exc}")
        finally:
            if self.cleanup:
                cleanup = self.executor.run(scenario, "cleanup", overrides)
                if not cleanup.ok:
                    result.notes.append(f"Cleanup failed (rc={cleanup.returncode}): {_tail(cleanup.stderr, 300)}")
            else:
                result.notes.append("Cleanup skipped (--no-cleanup): clean the host manually.")
            result.finished_at = iso_utc(self._now())

        self._log(f"[{scenario.id}] {result.status.value}")
        return result

    def check_only(self, scenario: Scenario, since: datetime, until: datetime | None = None) -> ScenarioResult:
        """Check only, for scenarios launched by hand."""
        if self.checker is None:
            raise ValueError("a DetectionChecker is required")
        result = self._base_result(scenario, Status.MISSED)
        until = until or self._now()
        result.started_at, result.finished_at = iso_utc(since), iso_utc(until)
        rule_ids = result.expected_rule_ids
        try:
            check = self.checker.check_once(start=since, end=until, **self._query_kwargs(scenario, rule_ids))
            self._apply_check(result, scenario, check)
        except Exception as exc:  # noqa: BLE001
            result.status = Status.CHECK_ERROR
            result.notes.append(f"Error querying the indexer: {exc}")
        return result


# ---------------------------------------------------------------------- reports
def render_markdown(results: list[ScenarioResult]) -> str:
    lines = [
        "# OpenSOC emulation report",
        "",
        f"Generated: {iso_utc(datetime.now(timezone.utc))}",
        "",
        "| Scenario | Technique | Target | Result | Rules that fired |",
        "|---|---|---|---|---|",
    ]
    for r in results:
        fired = ", ".join(sorted({a["rule_id"] for a in r.alerts})) or "—"
        lines.append(f"| {r.scenario_id} {r.name} | {r.technique} | {r.target} | **{r.status.value}** | {fired} |")
    counts: dict[str, int] = {}
    for r in results:
        counts[r.status.value] = counts.get(r.status.value, 0) + 1
    lines += ["", "Summary: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())), ""]
    for r in results:
        if r.notes:
            lines.append(f"- **{r.scenario_id}**: " + " ".join(r.notes))
    return "\n".join(lines) + "\n"


def write_reports(results: list[ScenarioResult], out_dir: Path | str) -> tuple[Path, Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    json_path = out_dir / f"emulation-{stamp}.json"
    md_path = out_dir / f"emulation-{stamp}.md"
    json_path.write_text(
        json.dumps([r.to_dict() for r in results], indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    md_path.write_text(render_markdown(results), encoding="utf-8")
    return json_path, md_path
