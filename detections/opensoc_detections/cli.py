"""Command line interface: ``python -m opensoc_detections <command>``.

Commands
  validate        sigma-cli check + OpenSOC policy (metadata, ATT&CK, samples, conversion)
  convert         Sigma -> Wazuh XML (output/wazuh/opensoc_sigma_rules.xml), assigns rule IDs
  coverage        ATT&CK Navigator layer + Markdown matrix (coverage/)
  build           validate + convert + coverage
  attack-update   refresh the bundled ATT&CK extract from the official STIX bundle
  wazuh-index     rebuild the stock Wazuh ruleset index / MITRE ID list from a manager container

``convert`` and ``coverage`` accept ``--check``: nothing is written and the command
fails if the committed artifacts are not up to date (used by CI).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from opensoc_detections import config


def _print_issues(issues) -> int:
    errors = [i for i in issues if i.severity == "error"]
    for i in issues:
        print(i)
    print(f"\n{len(errors)} error(s), {len(issues) - len(errors)} warning(s)")
    return 1 if errors else 0


def _convert(check: bool, output: Path) -> tuple[int, list]:
    from opensoc_detections.loader import load_collection
    from opensoc_detections.wazuh.backend import WazuhBackend
    from opensoc_detections.wazuh.ids import RuleIdRegistry

    registry = RuleIdRegistry()
    backend = WazuhBackend(id_registry=registry)
    xml = backend.convert(load_collection())
    status = 0
    if check:
        if registry.dirty:
            print(f"ERROR: {config.RULE_IDS_FILE.name} is missing IDs for new rules - run `convert` and commit")
            status = 1
        if not output.exists() or output.read_text(encoding="utf-8") != xml:
            print(f"ERROR: {output} is out of date - run `python -m opensoc_detections convert` and commit")
            status = 1
        if status == 0:
            print(f"OK: {output.relative_to(config.ROOT)} and rule ID registry are up to date")
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(xml, encoding="utf-8")
        if registry.dirty:
            registry.save()
        total = sum(len(c.wazuh_ids) for c in backend.converted)
        print(f"Converted {len(backend.converted)} Sigma rules into {total} Wazuh rules -> {output}")
    return status, backend.converted


def cmd_validate(args) -> int:
    from opensoc_detections.validate import validate

    issues, code, output = validate(sigma_cli=not args.no_sigma_cli, attack_stix=args.attack_stix)
    if output:
        print("=== sigma check (sigma-cli) ===")
        print(output)
        print()
    print("=== OpenSOC policy ===")
    return _print_issues(issues)


def cmd_convert(args) -> int:
    status, _ = _convert(args.check, Path(args.output))
    return status


def cmd_coverage(args) -> int:
    from opensoc_detections import coverage
    from opensoc_detections.loader import load_collection
    from opensoc_detections.wazuh.backend import WazuhBackend
    from opensoc_detections.wazuh.ids import RuleIdRegistry

    # Convert in memory to know how many Wazuh rules each Sigma rule produces.
    registry = RuleIdRegistry()
    backend = WazuhBackend(id_registry=registry)
    backend.convert(load_collection())
    counts = {c.sigma_id: len(c.wazuh_ids) for c in backend.converted}
    rules = coverage.collect(registry=registry, branch_counts=counts)
    out_dir = Path(args.output_dir)
    if args.check:
        layer = json.dumps(coverage.navigator_layer(rules), indent=2, ensure_ascii=False) + "\n"
        md = coverage.markdown(rules)
        stale = [
            p for p, content in ((out_dir / "attack_navigator_layer.json", layer), (out_dir / "COVERAGE.md", md))
            if not p.exists() or p.read_text(encoding="utf-8") != content
        ]
        if registry.dirty:
            print("ERROR: new rules have no Wazuh rule ID yet - run `python -m opensoc_detections convert` first")
        for p in stale:
            print(f"ERROR: {p} is out of date - run `python -m opensoc_detections coverage` and commit")
        if not stale and not registry.dirty:
            print("OK: coverage matrix is up to date")
        return 1 if stale or registry.dirty else 0
    if registry.dirty:
        print("ERROR: new rules have no Wazuh rule ID yet - run `python -m opensoc_detections convert` first")
        return 1
    layer_path, md_path = coverage.write(rules, out_dir)
    print(f"Coverage of {len(rules)} rules -> {layer_path}, {md_path}")
    return 0


def cmd_build(args) -> int:
    status = cmd_validate(args)
    if status:
        return status
    args.check, args.output = False, str(config.WAZUH_OUTPUT)
    args.output_dir = str(config.COVERAGE_DIR)
    return cmd_convert(args) or cmd_coverage(args)


def cmd_attack_update(args) -> int:
    from opensoc_detections import attack

    data = attack.update(args.stix)
    print(f"ATT&CK v{data['attack_version']}: {len(data['techniques'])} techniques -> {attack.DATA_FILE}")
    return 0


def cmd_wazuh_index(args) -> int:
    import subprocess

    from opensoc_detections import attack
    from opensoc_detections.wazuh import ruleset_index

    index = ruleset_index.index_from_container(args.container)
    ruleset_index.write_index(index)
    print(f"Indexed {len(index['rules'])} stock rules of Wazuh {index['wazuh_version']} -> {ruleset_index.INDEX_FILE}")
    script = (
        "import sqlite3, json\n"
        "c = sqlite3.connect('/var/ossec/var/db/mitre.db')\n"
        "print(json.dumps(sorted({r[0] for r in c.execute(\"select external_id from reference where "
        "source='mitre-attack' and type='technique' and external_id like 'T%'\")})))\n"
    )
    out = subprocess.run(
        ["docker", "exec", args.container, "/var/ossec/framework/python/bin/python3", "-c", script],
        capture_output=True, text=True, check=True,
    ).stdout
    ids = json.loads(out)
    path = Path(attack.DATA_FILE).parent / "wazuh_mitre_ids.json"
    payload = {
        "wazuh_version": index["wazuh_version"],
        "note": "Technique IDs known to the MITRE database bundled with this Wazuh version (var/db/mitre.db)",
        "technique_ids": ids,
    }
    path.write_text(json.dumps(payload, indent=0) + "\n", encoding="utf-8")
    print(f"{len(ids)} MITRE technique IDs known by Wazuh -> {path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="opensoc_detections", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    def add_validate_opts(p):
        p.add_argument("--no-sigma-cli", action="store_true", help="skip `sigma check`")
        p.add_argument("--attack-stix", help="local ATT&CK STIX bundle for pySigma (offline use)")

    p = sub.add_parser("validate", help="validate rules")
    add_validate_opts(p)
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("convert", help="convert rules to Wazuh XML")
    p.add_argument("--output", default=str(config.WAZUH_OUTPUT))
    p.add_argument("--check", action="store_true", help="fail if committed output is stale")
    p.set_defaults(func=cmd_convert)

    p = sub.add_parser("coverage", help="generate the ATT&CK coverage matrix")
    p.add_argument("--output-dir", default=str(config.COVERAGE_DIR))
    p.add_argument("--check", action="store_true", help="fail if committed coverage files are stale")
    p.set_defaults(func=cmd_coverage)

    p = sub.add_parser("build", help="validate + convert + coverage")
    add_validate_opts(p)
    p.set_defaults(func=cmd_build)

    p = sub.add_parser("attack-update", help="refresh bundled ATT&CK data")
    p.add_argument("--stix", default=None, help="STIX bundle path or URL (default: official MITRE repo)")
    p.set_defaults(func=cmd_attack_update)

    p = sub.add_parser("wazuh-index", help="rebuild the stock Wazuh ruleset index from a container")
    p.add_argument("--container", required=True)
    p.set_defaults(func=cmd_wazuh_index)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "command", None) == "attack-update" and args.stix is None:
        from opensoc_detections import attack

        args.stix = attack.STIX_URL
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
