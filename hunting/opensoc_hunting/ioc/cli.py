"""opensoc-ioc: imports and exports IOCs (STIX 2.1 / CSV) against MISP.

  export      MISP -> file (STIX 2.1 or CSV)
  import      file -> MISP (new or existing event)
  convert     STIX <-> CSV without touching MISP
  validate    checks an IOC file
  hunt-query  OpenSearch query to look for the IOCs in Wazuh (hypothesis H15)
  ping        checks the connection to MISP

The MISP URL and API key are read from MISP_URL and MISP_KEY (never from arguments,
so that the key does not end up in the shell history or in the process list).
"""

from __future__ import annotations

import argparse
import json
import sys

from ..opensearch import silence_insecure_warning
from .fileio import FORMATS, guess_format, load_iocs, save_iocs
from .hunt_query import build_hunt_query
from .misp import EXPORTABLE_MISP_TYPES, MispClient, MispError
from .model import IOCError, normalize_tlp


def _err(msg: str) -> None:
    print(msg, file=sys.stderr)


def _report_load(result, *, strict: bool) -> bool:
    for warning in result.warnings:
        _err(f"warning: {warning}")
    for error in result.errors:
        _err(f"error: {error}")
    if result.errors and strict:
        _err(f"{len(result.errors)} validation errors; fix the file or use --skip-invalid")
        return False
    return True


def _client() -> MispClient:
    client = MispClient.from_env()
    silence_insecure_warning(client.verify)
    return client


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="opensoc-ioc", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p_exp = sub.add_parser("export", help="MISP -> file")
    p_exp.add_argument("-o", "--output", default="-", help="Output file (- = stdout)")
    p_exp.add_argument("-f", "--format", choices=("auto", *FORMATS), default="auto")
    p_exp.add_argument("--event-id")
    p_exp.add_argument("--tag", action="append", default=[], help="Filter by tag (repeatable), e.g. tlp:amber")
    p_exp.add_argument("--type", action="append", default=[], choices=EXPORTABLE_MISP_TYPES, metavar="MISP_TYPE")
    p_exp.add_argument("--last", help="Recent attributes only: 7d, 24h...")
    p_exp.add_argument("--to-ids-only", action="store_true")
    p_exp.add_argument("--published-only", action="store_true")
    p_exp.add_argument("--defang", action="store_true", help="CSV with defanged values (hxxp, [.])")
    p_exp.add_argument("--producer", default="OpenSOC Lab", help="Name of the STIX identity")

    p_imp = sub.add_parser("import", help="file -> MISP")
    p_imp.add_argument("input", help="STIX 2.1 (.json) or CSV file (- = stdin)")
    p_imp.add_argument("-f", "--format", choices=("auto", *FORMATS), default="auto")
    target = p_imp.add_mutually_exclusive_group(required=True)
    target.add_argument("--event-id", help="Add to an existing event (skips duplicates)")
    target.add_argument("--event-info", help="Create a new event with this title")
    p_imp.add_argument("--tlp", help="Default TLP for IOCs without TLP, and tag of the new event")
    p_imp.add_argument("--tag", action="append", default=[], help="Tag of the new event (repeatable)")
    p_imp.add_argument("--distribution", type=int, choices=range(0, 4), default=0,
                       help="Distribution of the new event (0 = your organization only)")
    p_imp.add_argument("--ip-type", choices=("ip-dst", "ip-src"), default="ip-dst")
    p_imp.add_argument("--publish", action="store_true", help="Publish the event at the end")
    p_imp.add_argument("--dry-run", action="store_true", help="Do not write to MISP")
    p_imp.add_argument("--skip-invalid", action="store_true", help="Import even if there are invalid rows")

    p_conv = sub.add_parser("convert", help="STIX <-> CSV")
    p_conv.add_argument("input")
    p_conv.add_argument("output")
    p_conv.add_argument("--from", dest="src_format", choices=("auto", *FORMATS), default="auto")
    p_conv.add_argument("--to", dest="dst_format", choices=("auto", *FORMATS), default="auto")
    p_conv.add_argument("--defang", action="store_true")
    p_conv.add_argument("--producer", default="OpenSOC Lab")
    p_conv.add_argument("--skip-invalid", action="store_true")

    p_val = sub.add_parser("validate", help="Validate an IOC file")
    p_val.add_argument("input")
    p_val.add_argument("-f", "--format", choices=("auto", *FORMATS), default="auto")

    p_hq = sub.add_parser("hunt-query", help="OpenSearch query with the IOCs (H15)")
    p_hq.add_argument("input")
    p_hq.add_argument("-f", "--format", choices=("auto", *FORMATS), default="auto")
    p_hq.add_argument("--since", default="now-7d")
    p_hq.add_argument("--time-field", default="timestamp")
    p_hq.add_argument("--include-filenames", action="store_true")
    p_hq.add_argument("--all", action="store_true", help="Include IOCs with to_ids=false")

    sub.add_parser("ping", help="Check the connection and the MISP API key")
    return parser


def _cmd_export(args) -> int:
    client = _client()
    result = client.export_iocs(
        event_id=args.event_id,
        tags=args.tag or None,
        types=args.type or None,
        last=args.last,
        to_ids=True if args.to_ids_only else None,
        published=True if args.published_only else None,
    )
    for error in result.errors:
        _err(f"warning: {error}")
    for kind, count in sorted(result.skipped.items()):
        _err(f"warning: {count} attributes of unsupported type {kind}")
    fmt = save_iocs(result.iocs, args.output, args.format, producer=args.producer, defanged=args.defang)
    _err(f"{len(result.iocs)} IOCs exported ({fmt})")
    return 0


def _cmd_import(args) -> int:
    loaded = load_iocs(args.input, args.format)
    if not _report_load(loaded, strict=not args.skip_invalid):
        return 1
    if not loaded.iocs:
        _err("There are no IOCs to import")
        return 1
    tlp = normalize_tlp(args.tlp) if args.tlp else None
    iocs = [i if i.tlp or not tlp else i.with_changes(tlp=tlp) for i in loaded.iocs]
    event_tags = list(args.tag) + ([f"tlp:{tlp}"] if tlp else [])
    client = _client()
    result = client.import_iocs(
        iocs,
        event_id=args.event_id,
        event_info=args.event_info,
        event_tags=event_tags,
        distribution=args.distribution,
        ip_type=args.ip_type,
        publish=args.publish,
        dry_run=args.dry_run,
    )
    for ioc, reason in result.failed:
        _err(f"error: {ioc.type} {ioc.value}: {reason}")
    print(result.summary())
    return 1 if result.failed else 0


def _cmd_convert(args) -> int:
    loaded = load_iocs(args.input, args.src_format)
    if not _report_load(loaded, strict=not args.skip_invalid):
        return 1
    dst = guess_format(args.output) if args.dst_format == "auto" else args.dst_format
    save_iocs(loaded.iocs, args.output, dst, producer=args.producer, defanged=args.defang)
    _err(f"{len(loaded.iocs)} IOCs: {loaded.format} -> {dst}")
    return 0


def _cmd_validate(args) -> int:
    loaded = load_iocs(args.input, args.format)
    _report_load(loaded, strict=False)
    by_type: dict[str, int] = {}
    for ioc in loaded.iocs:
        by_type[ioc.type] = by_type.get(ioc.type, 0) + 1
    summary = ", ".join(f"{k}={v}" for k, v in sorted(by_type.items())) or "none"
    print(f"{loaded.format}: {len(loaded.iocs)} valid IOCs ({summary}), {len(loaded.errors)} errors")
    return 1 if loaded.errors else 0


def _cmd_hunt_query(args) -> int:
    loaded = load_iocs(args.input, args.format)
    _report_load(loaded, strict=False)
    query, warnings = build_hunt_query(
        loaded.iocs,
        time_field=args.time_field,
        since=args.since,
        include_filenames=args.include_filenames,
        only_to_ids=not args.all,
    )
    for warning in warnings:
        _err(f"warning: {warning}")
    print(json.dumps(query, indent=2, ensure_ascii=False))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "export":
            return _cmd_export(args)
        if args.command == "import":
            return _cmd_import(args)
        if args.command == "convert":
            return _cmd_convert(args)
        if args.command == "validate":
            return _cmd_validate(args)
        if args.command == "hunt-query":
            return _cmd_hunt_query(args)
        if args.command == "ping":
            print(f"MISP {_client().get_version()} OK")
            return 0
    except (MispError, IOCError, ValueError, OSError) as exc:
        _err(f"ERROR: {exc}")
        return 2
    return 2  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
