"""opensoc-emulate: launches Atomic Red Team scenarios and checks whether Wazuh detects them.

For use in your own lab only. Without --execute it only shows what it would do.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from ..opensearch import (
    IndexerClient,
    IndexerConfig,
    IndexerError,
    silence_insecure_warning,
)
from ..paths import DEFAULT_DETECTIONS_DIR, REPORTS_DIR, SCENARIOS_FILE
from .checker import DetectionChecker
from .detections import DetectionIndex
from .executor import AtomicExecutor, RemoteSession
from .runner import (
    EmulationRunner,
    LabGuardError,
    Status,
    ensure_lab_target,
    parse_lab_targets,
    write_reports,
)
from .scenarios import PLATFORMS, CatalogError, load_scenarios, select_scenarios

BANNER = (
    "OpenSOC · Atomic Red Team emulation. FOR YOUR OWN LAB ONLY: "
    "do not run these tests on hosts you do not control."
)


def _parse_input_args(values: list[str]) -> dict[str, dict[str, str]]:
    """EMU-06.remote_file=http://x -> {"EMU-06": {"remote_file": "http://x"}}"""
    overrides: dict[str, dict[str, str]] = defaultdict(dict)
    for item in values:
        key, sep, value = item.partition("=")
        scenario_id, dot, arg = key.partition(".")
        if not sep or not dot or not scenario_id or not arg:
            raise argparse.ArgumentTypeError(f"--input-arg must have the format EMU-NN.argument=value: {item!r}")
        overrides[scenario_id.strip().upper()][arg.strip()] = value
    return dict(overrides)


def _parse_time(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    moment = datetime.fromisoformat(text)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="opensoc-emulate", description=__doc__)
    parser.add_argument("--catalog", default=str(SCENARIOS_FILE), help="Scenario catalog (YAML)")
    parser.add_argument("--detections", default=str(DEFAULT_DETECTIONS_DIR), help="Detections directory")
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="List the scenarios")
    p_list.add_argument("--platform", choices=PLATFORMS)
    p_list.add_argument("--json", action="store_true")

    p_cov = sub.add_parser("coverage", help="Cross-check the scenarios against the /detections rules")
    p_cov.add_argument("--fail-on-gap", action="store_true",
                       help="Exit with code 1 if any scenario has no detection")

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--target", required=True, help="agent.name (or agent.id) of the host in Wazuh")
        p.add_argument("--scenario", "-s", action="append", default=[], help="EMU-NN (repeatable)")
        p.add_argument("--platform", choices=PLATFORMS, help="Filter scenarios by platform")
        p.add_argument("--strict", action="store_true",
                       help="Only /detections rules or the scenario rule_ids count")
        p.add_argument("--report-dir", default=str(REPORTS_DIR))
        p.add_argument("--no-report", action="store_true")

    p_run = sub.add_parser("run", help="Run scenarios (dry run unless --execute)")
    add_common(p_run)
    p_run.add_argument("--all", action="store_true", help="Every scenario of the given platform")
    p_run.add_argument("--execute", action="store_true",
                       help="Really execute (the target must be in OPENSOC_LAB_TARGETS)")
    p_run.add_argument("--prereqs", action="store_true", help="Run -GetPrereqs before each test")
    p_run.add_argument("--no-cleanup", action="store_true")
    p_run.add_argument("--allow-irreversible", action="store_true",
                       help="Allow scenarios without cleanup (e.g. log clearing)")
    p_run.add_argument("--input-arg", action="append", default=[], metavar="EMU-NN.arg=value")
    p_run.add_argument("--shell", default=os.environ.get("OPENSOC_PWSH", "pwsh"))
    p_run.add_argument("--module", default=os.environ.get("OPENSOC_ART_MODULE", "Invoke-AtomicRedTeam"),
                       help="Module name or path")
    p_run.add_argument("--atomics-path", default=os.environ.get("OPENSOC_ATOMICS_PATH"),
                       help="atomics/ folder if it is not the default one")
    p_run.add_argument("--session-host", help="Run remotely through a PSSession (Invoke-AtomicTest -Session)")
    p_run.add_argument("--session-user")
    p_run.add_argument("--transport", choices=["ssh", "winrm"], default="ssh")
    p_run.add_argument("--test-timeout", type=int, default=120, help="Invoke-AtomicTest -TimeoutSeconds")
    p_run.add_argument("--poll-interval", type=float, default=15.0)
    p_run.add_argument("--detection-timeout", type=float,
                       help="Seconds to wait for the alert (overrides the timeout of each scenario)")
    p_run.add_argument("--clock-skew", type=float, default=30.0, help="Seconds of margin at the start of the window")

    p_check = sub.add_parser("check", help="Only check for alerts (scenario launched by hand)")
    add_common(p_check)
    p_check.add_argument("--since", required=True, help="Start of the window (ISO 8601, UTC by default)")
    p_check.add_argument("--until", help="End of the window (default: now)")
    return parser


def _cmd_list(args, scenarios) -> int:
    scenarios = select_scenarios(scenarios, platform=args.platform)
    if args.json:
        print(json.dumps([
            {"id": s.id, "name": s.name, "platform": s.platform, "technique": s.technique,
             "aliases": list(s.technique_aliases), "atomic_guid": s.atomic.guid, "hypotheses": list(s.hypotheses)}
            for s in scenarios
        ], indent=2, ensure_ascii=False))
        return 0
    for s in scenarios:
        alias = f" (alias {', '.join(s.technique_aliases)})" if s.technique_aliases else ""
        flags = " [irreversible]" if s.irreversible else ""
        print(f"{s.id}  {s.platform:<7} {s.technique:<10}{alias}  {s.name}{flags}")
        print(f"        ART: {s.atomic.technique} · {s.atomic.name} · {s.atomic.guid}")
    return 0


def _cmd_coverage(args, scenarios) -> int:
    root = Path(args.detections)
    index = DetectionIndex.from_dir(root)
    if not root.is_dir():
        print(f"WARNING: {root} does not exist; cannot cross-check against /detections. "
              "The check will only use rule.mitre.id from the Wazuh ruleset.")
    gaps = 0
    for s in scenarios:
        refs = index.for_scenario(s)
        mark = "OK " if refs else "GAP"
        gaps += 0 if refs else 1
        print(f"[{mark}] {s.id} {s.technique:<10} {s.name}")
        for ref in refs:
            print(f"        - {ref.label()}")
    print(f"\n{len(scenarios) - gaps}/{len(scenarios)} scenarios with a detection in {root}")
    return 1 if (gaps and args.fail_on_gap) else 0


def _make_checker(args) -> DetectionChecker:
    config = IndexerConfig.from_env()
    silence_insecure_warning(config.verify)
    return DetectionChecker(IndexerClient(config), time_field=config.time_field,
                            poll_interval=getattr(args, "poll_interval", 15.0))


def _finish(args, results) -> int:
    if not args.no_report:
        json_path, md_path = write_reports(results, args.report_dir)
        print(f"\nReport: {md_path}\n        {json_path}")
    print()
    for r in results:
        print(f"{r.scenario_id:<7} {r.status.value:<11} {r.technique:<10} {r.name}")
        for note in r.notes:
            print(f"        {note}")
    bad = {Status.MISSED, Status.EXEC_ERROR, Status.CHECK_ERROR}
    return 1 if any(r.status in bad for r in results) else 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        scenarios = load_scenarios(args.catalog)
        if args.command == "list":
            return _cmd_list(args, scenarios)
        if args.command == "coverage":
            return _cmd_coverage(args, scenarios)

        print(BANNER, file=sys.stderr)
        if args.command == "run" and not args.scenario and not args.all:
            print("Pass --scenario EMU-NN or --all", file=sys.stderr)
            return 2
        selected = select_scenarios(scenarios, ids=args.scenario, platform=args.platform)
        if not selected:
            print("No scenario matches the filter", file=sys.stderr)
            return 2
        index = DetectionIndex.from_dir(args.detections)
        lab_targets = parse_lab_targets(os.environ.get("OPENSOC_LAB_TARGETS"))

        if args.command == "check":
            runner = EmulationRunner(AtomicExecutor(), _make_checker(args), target=args.target,
                                     lab_targets=lab_targets, strict=args.strict, detection_index=index)
            since = _parse_time(args.since)
            until = _parse_time(args.until) if args.until else None
            return _finish(args, [runner.check_only(s, since, until) for s in selected])

        if args.execute:
            ensure_lab_target(args.target, lab_targets)
        remote = RemoteSession(args.session_host, args.session_user, args.transport) if args.session_host else None
        executor = AtomicExecutor(shell=args.shell, module=args.module, atomics_path=args.atomics_path,
                                  remote=remote, test_timeout=args.test_timeout)
        runner = EmulationRunner(
            executor,
            _make_checker(args) if args.execute else None,
            target=args.target,
            lab_targets=lab_targets,
            execute=args.execute,
            prereqs=args.prereqs,
            cleanup=not args.no_cleanup,
            strict=args.strict,
            allow_irreversible=args.allow_irreversible,
            detection_index=index,
            input_overrides=_parse_input_args(args.input_arg),
            clock_skew=args.clock_skew,
            detection_timeout=args.detection_timeout,
        )
        results = runner.run(selected)
        if not args.execute:
            for r in results:
                if r.execution and "script" in r.execution:
                    print(f"\n# {r.scenario_id} · {r.name}\n{r.execution['script']}")
        return _finish(args, results)
    except (CatalogError, LabGuardError, IndexerError, argparse.ArgumentTypeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
