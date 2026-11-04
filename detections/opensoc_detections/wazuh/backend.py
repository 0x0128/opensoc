"""pySigma backend that converts Sigma rules into Wazuh XML rules.

Conversion model
----------------
Wazuh rules can only AND their conditions (``<field>``, ``<regex>``...). OR logic
is only available *inside* a single PCRE2 expression. The backend therefore:

1. converts the Sigma condition tree into an intermediate representation (IR) of
   AND/OR/NOT nodes over *atoms* (one field + one PCRE2 pattern);
2. pushes negations down to the atoms (negation normal form);
3. merges ORed atoms on the same field into one alternation ``(?:a|b)`` (and NOTed
   atoms that are ANDed: ``not a and not b == not (a|b)``);
4. expands the result to disjunctive normal form: every conjunction becomes one
   Wazuh rule. Rules of a Sigma rule share description/MITRE mapping and use
   consecutive IDs from the block reserved in ``config/wazuh_rule_ids.yml``.

Known semantic limits (documented in README):
* a negated condition only matches when the field exists (Wazuh evaluates
  ``negate="yes"`` on present fields only);
* numeric comparisons, field references and ``exists: false`` are not supported.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from typing import Any, ClassVar, Iterable
from xml.sax.saxutils import escape, quoteattr

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.conversion.base import Backend
from sigma.conversion.state import ConversionState
from sigma.exceptions import SigmaConversionError, SigmaFeatureNotSupportedByBackendError
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule
from sigma.types import (
    Placeholder,
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
    SigmaString,
    SpecialChars,
)

from opensoc_detections import attack
from opensoc_detections.config import ROOT, LogsourceMapping, mapping_for
from opensoc_detections.wazuh.ids import BLOCK_SIZE, RuleIdRegistry
from opensoc_detections.wazuh.pipeline import opensoc_wazuh_pipeline
from opensoc_detections.wazuh.ruleset_index import grouping_closure

LEVELS = {"informational": 3, "low": 5, "medium": 8, "high": 12, "critical": 14}
MAX_BRANCHES = BLOCK_SIZE
SKIPPED_STATUS = {"deprecated", "unsupported"}
PCRE_SPECIAL = frozenset("\\.^$|?*+()[]{}")
ANY_VALUE = "^"  # matches any value of a present field (used for `exists: true`)


# --------------------------------------------------------------------------- IR
@dataclass(frozen=True)
class Atom:
    """A single Wazuh condition: field (None = event message) matches PCRE2 pattern."""

    field: str | None
    pattern: str
    ci: bool = True  # case-insensitive
    negated: bool = False

    def negate(self) -> "Atom":
        return replace(self, negated=not self.negated)

    @property
    def expression(self) -> str:
        return ("(?i)" if self.ci else "") + self.pattern


@dataclass(frozen=True)
class Node:
    op: str  # "and" | "or" | "not"
    args: tuple[Any, ...]


Branch = tuple[Atom, ...]


def pcre_escape(s: str) -> str:
    return "".join("\\" + c if c in PCRE_SPECIAL else c for c in s)


def alternation(patterns: Iterable[str]) -> str:
    unique = list(dict.fromkeys(patterns))
    if len(unique) == 1:
        return unique[0]
    return "(?:" + "|".join(unique) + ")"


def string_pattern(value: SigmaString, anchored: bool = True) -> str:
    """Sigma string (with wildcards) -> PCRE2 search pattern."""
    parts = list(value.iter_parts())
    if any(isinstance(p, Placeholder) for p in parts):
        raise SigmaFeatureNotSupportedByBackendError("Unresolved placeholders are not supported")
    lead = bool(parts) and parts[0] == SpecialChars.WILDCARD_MULTI
    if lead:
        parts = parts[1:]
    trail = bool(parts) and parts[-1] == SpecialChars.WILDCARD_MULTI
    if trail:
        parts = parts[:-1]
    if not parts and (lead or trail):
        return ANY_VALUE  # "*": any value
    body = []
    for p in parts:
        if p == SpecialChars.WILDCARD_MULTI:
            body.append(".*")
        elif p == SpecialChars.WILDCARD_SINGLE:
            body.append(".")
        else:
            body.append(pcre_escape(p))
    start = "^" if anchored and not lead else ""
    end = "$" if anchored and not trail else ""
    return start + "".join(body) + end


def wildcard_pattern(value: str) -> str:
    """Plain wildcard string ('10.*', 'fe8?:*') -> anchored PCRE2 pattern."""
    out = []
    for c in value:
        out.append(".*" if c == "*" else "." if c == "?" else pcre_escape(c))
    pat = "^" + "".join(out)
    if pat.endswith(".*"):
        return pat[:-2]
    return pat + "$"


# -------------------------------------------------------------- normalization
def to_nnf(node: Any, negate: bool = False) -> Any:
    if isinstance(node, Atom):
        return node.negate() if negate else node
    if node.op == "not":
        return to_nnf(node.args[0], not negate)
    op = node.op
    if negate:
        op = "or" if op == "and" else "and"
    return Node(op, tuple(to_nnf(a, negate) for a in node.args))


def merge_atoms(node: Any) -> Any:
    """Flatten nested and/or nodes and merge same-field atoms into alternations."""
    if isinstance(node, Atom):
        return node
    flat: list[Any] = []
    for child in (merge_atoms(a) for a in node.args):
        if isinstance(child, Node) and child.op == node.op:
            flat.extend(child.args)
        else:
            flat.append(child)
    # OR of positive atoms == one atom with alternation; AND of negated atoms likewise.
    mergeable_negation = node.op == "and"
    groups: dict[tuple, list[Atom]] = {}
    order: list[Any] = []
    for child in flat:
        if isinstance(child, Atom) and child.negated == mergeable_negation:
            key = (child.field, child.ci, child.negated)
            if key not in groups:
                groups[key] = []
                order.append(key)
            groups[key].append(child)
        else:
            order.append(child)
    result = []
    for item in order:
        if isinstance(item, tuple):
            atoms = groups[item]
            if len(atoms) == 1:
                result.append(atoms[0])
            else:
                result.append(replace(atoms[0], pattern=alternation(a.pattern for a in atoms)))
        else:
            result.append(item)
    if len(result) == 1:
        return result[0]
    return Node(node.op, tuple(result))


def to_dnf(node: Any, limit: int = 256) -> list[Branch]:
    if isinstance(node, Atom):
        return [(node,)]
    if node.op == "or":
        return [b for a in node.args for b in to_dnf(a, limit)]
    branches: list[Branch] = [()]
    for a in node.args:
        branches = [x + y for x in branches for y in to_dnf(a, limit)]
        if len(branches) > limit:
            raise SigmaConversionError("condition explodes into too many Wazuh rules")
    return branches


def _merge_branch_pair(a: Branch, b: Branch) -> Branch | None:
    """Merge two conjunctions that only differ in one positive atom on the same field."""
    if len(a) != len(b):
        return None
    diff = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
    if len(diff) != 1:
        return None
    x, y = a[diff[0]], b[diff[0]]
    if x.negated or y.negated or (x.field, x.ci) != (y.field, y.ci):
        return None
    merged = replace(x, pattern=alternation([x.pattern, y.pattern]))
    return a[: diff[0]] + (merged,) + a[diff[0] + 1 :]


def simplify_branches(branches: list[Branch]) -> list[Branch]:
    # dedupe atoms inside a conjunction, then dedupe conjunctions
    result = list(dict.fromkeys(tuple(dict.fromkeys(b)) for b in branches))
    changed = True
    while changed:
        changed = False
        for i in range(len(result)):
            for j in range(i + 1, len(result)):
                merged = _merge_branch_pair(result[i], result[j])
                if merged is not None:
                    result[i] = merged
                    del result[j]
                    changed = True
                    break
            if changed:
                break
    return result


def condition_to_branches(ir: Any) -> list[Branch]:
    return simplify_branches(to_dnf(merge_atoms(to_nnf(ir))))


# ----------------------------------------------------------------- results
@dataclass
class ConvertedRule:
    rule: SigmaRule
    mapping: LogsourceMapping
    branches: list[Branch] = field(default_factory=list)
    wazuh_ids: list[int] = field(default_factory=list)
    xml: str = ""

    @property
    def sigma_id(self) -> str:
        return str(self.rule.id)


@dataclass
class _ConvertedQuery:
    rule: SigmaRule
    mapping: LogsourceMapping
    branches: list[Branch]


# ----------------------------------------------------------------- backend
class WazuhBackend(Backend):
    """Sigma -> Wazuh XML rules (OpenSOC field mappings)."""

    name: ClassVar[str] = "OpenSOC Wazuh"
    identifier: ClassVar[str] = "opensoc_wazuh"
    formats: ClassVar[dict[str, str]] = {
        "default": "Wazuh XML ruleset (one file)",
        "converted": "List of ConvertedRule objects (API use)",
    }
    requires_pipeline: ClassVar[bool] = False
    explicit_not_exists_expression: ClassVar[bool] = True

    def __init__(
        self,
        processing_pipeline: ProcessingPipeline | None = None,
        collect_errors: bool = False,
        id_registry: RuleIdRegistry | None = None,
        mitre_ids: str = "wazuh",
        **backend_options: Any,
    ):
        super().__init__(processing_pipeline or ProcessingPipeline(), collect_errors, **backend_options)
        self.backend_processing_pipeline = opensoc_wazuh_pipeline()
        self.id_registry = id_registry if id_registry is not None else RuleIdRegistry()
        if mitre_ids not in ("wazuh", "current"):
            raise ValueError("mitre_ids must be 'wazuh' or 'current'")
        self.mitre_ids = mitre_ids
        self.converted: list[ConvertedRule] = []

    # -- entry points -----------------------------------------------------
    def convert_rule(self, rule: SigmaRule, output_format: str | None = None, callback=None) -> list[Any]:
        status = rule.status.name.lower() if rule.status else ""
        if status in SKIPPED_STATUS:
            return []
        if mapping_for(rule.logsource) is None:
            err = SigmaFeatureNotSupportedByBackendError(
                f"Logsource {rule.logsource} has no Wazuh mapping in config/wazuh_mapping.yml",
                source=rule.source,
            )
            if self.collect_errors:
                self.errors.append((rule, err))
                return []
            raise err
        return super().convert_rule(rule, output_format, callback)

    # -- condition tree -> IR --------------------------------------------
    def convert_condition_and(self, cond: ConditionAND, state: ConversionState) -> Node:
        return Node("and", tuple(self.convert_condition(a, state) for a in cond.args))

    def convert_condition_or(self, cond: ConditionOR, state: ConversionState) -> Node:
        return Node("or", tuple(self.convert_condition(a, state) for a in cond.args))

    def convert_condition_not(self, cond: ConditionNOT, state: ConversionState) -> Node:
        return Node("not", (self.convert_condition(cond.args[0], state),))

    def convert_condition_as_in_expression(self, cond, state):  # pragma: no cover - disabled
        raise NotImplementedError

    def convert_condition_field_eq_val_str(self, cond: ConditionFieldEqualsValueExpression, state) -> Atom:
        return Atom(cond.field, string_pattern(cond.value), ci=True)

    def convert_condition_field_eq_val_str_case_sensitive(self, cond, state) -> Atom:
        return Atom(cond.field, string_pattern(cond.value), ci=False)

    def convert_condition_field_eq_val_num(self, cond, state) -> Atom:
        return Atom(cond.field, "^" + pcre_escape(str(cond.value)) + "$", ci=False)

    def convert_condition_field_eq_val_bool(self, cond, state) -> Atom:
        value: SigmaBool = cond.value
        return Atom(cond.field, "^true$" if value.boolean else "^false$", ci=True)

    def convert_condition_field_eq_val_re(self, cond, state) -> Atom:
        return self._regex_atom(cond.field, cond.value)

    def convert_condition_field_eq_val_cidr(self, cond, state) -> Atom:
        value: SigmaCIDRExpression = cond.value
        return Atom(cond.field, alternation(wildcard_pattern(w) for w in value.expand(wildcard="*")), ci=True)

    def convert_condition_field_eq_val_null(self, cond, state) -> Atom:
        return Atom(cond.field, "^$", ci=False)

    def convert_condition_field_exists(self, cond, state) -> Atom:
        return Atom(cond.field, ANY_VALUE, ci=False)

    def convert_condition_field_not_exists(self, cond, state):
        raise SigmaFeatureNotSupportedByBackendError(
            "Wazuh cannot test for the absence of a field (exists: false)", source=cond.source
        )

    def convert_condition_field_compare_op_val(self, cond, state):
        raise SigmaFeatureNotSupportedByBackendError(
            "Numeric comparison operators are not supported by Wazuh field matching", source=cond.source
        )

    def convert_condition_field_eq_field(self, cond, state):
        raise SigmaFeatureNotSupportedByBackendError("Field references are not supported", source=cond.source)

    def convert_condition_field_eq_val_timestamp_part(self, cond, state):
        raise SigmaFeatureNotSupportedByBackendError("Timestamp modifiers are not supported", source=cond.source)

    def convert_condition_field_eq_query_expr(self, cond, state):
        raise SigmaFeatureNotSupportedByBackendError("Query expressions are not supported", source=cond.source)

    def convert_condition_query_expr(self, cond, state):
        raise SigmaFeatureNotSupportedByBackendError("Query expressions are not supported", source=cond.source)

    def convert_condition_val_str(self, cond: ConditionValueExpression, state) -> Atom:
        return Atom(None, string_pattern(cond.value, anchored=False), ci=not isinstance(cond.value, SigmaCasedString))

    def convert_condition_val_num(self, cond: ConditionValueExpression, state) -> Atom:
        return Atom(None, pcre_escape(str(cond.value)), ci=False)

    def convert_condition_val_re(self, cond: ConditionValueExpression, state) -> Atom:
        return self._regex_atom(None, cond.value)

    # -- correlation rules ----------------------------------------------------
    def _no_correlation(self, rule, *args, **kwargs):
        raise SigmaFeatureNotSupportedByBackendError(
            "Sigma correlation rules are not supported by the OpenSOC Wazuh backend yet",
            source=getattr(rule, "source", None),
        )

    convert_correlation_event_count_rule = _no_correlation
    convert_correlation_value_count_rule = _no_correlation
    convert_correlation_temporal_rule = _no_correlation
    convert_correlation_temporal_ordered_rule = _no_correlation
    convert_correlation_extended_temporal_rule = _no_correlation
    convert_correlation_extended_temporal_ordered_rule = _no_correlation
    convert_correlation_value_sum_rule = _no_correlation
    convert_correlation_value_avg_rule = _no_correlation
    convert_correlation_value_percentile_rule = _no_correlation
    convert_correlation_value_median_rule = _no_correlation

    @staticmethod
    def _regex_atom(field_name: str | None, value: SigmaRegularExpression) -> Atom:
        inline = ""
        if SigmaRegularExpressionFlag.MULTILINE in value.flags:
            inline += "m"
        if SigmaRegularExpressionFlag.DOTALL in value.flags:
            inline += "s"
        pattern = (f"(?{inline})" if inline else "") + str(value.regexp)
        return Atom(field_name, pattern, ci=SigmaRegularExpressionFlag.IGNORECASE in value.flags)

    # -- IR -> branches -----------------------------------------------------
    def finalize_query_default(self, rule: SigmaRule, query: Any, index: int, state: ConversionState):
        mapping = mapping_for(rule.logsource)
        assert mapping is not None
        branches = condition_to_branches(query)
        for branch in branches:
            for atom in branch:
                if atom.field is None and not mapping.keywords:
                    raise SigmaFeatureNotSupportedByBackendError(
                        f"Keyword detections are not supported for logsource '{mapping.id}'",
                        source=rule.source,
                    )
                if atom.negated and atom.pattern == ANY_VALUE:
                    raise SigmaFeatureNotSupportedByBackendError(
                        "Negated 'exists'/'*' conditions cannot be expressed in Wazuh", source=rule.source
                    )
            if all(a.negated for a in branch):
                raise SigmaConversionError(
                    "A Wazuh rule needs at least one positive condition "
                    f"(rule {rule.id} has a purely negated branch)"
                )
        return _ConvertedQuery(rule, mapping, branches)

    finalize_query_converted = finalize_query_default

    # -- output -------------------------------------------------------------
    def _collect(self, queries: list[_ConvertedQuery]) -> list[ConvertedRule]:
        by_rule: dict[int, ConvertedRule] = {}
        for q in queries:
            cr = by_rule.setdefault(id(q.rule), ConvertedRule(q.rule, q.mapping))
            cr.branches.extend(q.branches)
        converted = []
        for cr in by_rule.values():
            cr.branches = simplify_branches(cr.branches)
            if len(cr.branches) > MAX_BRANCHES:
                raise SigmaConversionError(
                    f"Rule {cr.sigma_id} needs {len(cr.branches)} Wazuh rules (max {MAX_BRANCHES}); "
                    "simplify its condition",
                    source=cr.rule.source,
                )
            base = self.id_registry.assign(cr.sigma_id)
            cr.wazuh_ids = [base + i for i in range(len(cr.branches))]
            cr.xml = render_rule(cr, self.mitre_ids)
            converted.append(cr)
        converted.sort(key=lambda c: c.wazuh_ids[0])
        self.converted = converted
        return converted

    def finalize_output_default(self, queries: list[_ConvertedQuery]) -> str:
        return render_ruleset(self._collect(queries))

    def finalize_output_converted(self, queries: list[_ConvertedQuery]) -> list[ConvertedRule]:
        return self._collect(queries)


# ------------------------------------------------------------------ XML
def _mitre_ids(rule: SigmaRule, mode: str) -> list[str]:
    techniques, _ = attack.parse_tags(str(t) for t in rule.tags)
    if mode == "current":
        return list(dict.fromkeys(techniques))
    known = wazuh_known_techniques()
    data = attack.load()
    out = []
    for tid in techniques:
        if tid not in known and data.legacy_ids.get(tid) in known:
            tid = data.legacy_ids[tid]
        out.append(tid)
    return list(dict.fromkeys(out))


def wazuh_known_techniques() -> frozenset[str]:
    import json

    path = os.path.join(os.path.dirname(attack.DATA_FILE), "wazuh_mitre_ids.json")
    with open(path, encoding="utf-8") as fh:
        return frozenset(json.load(fh)["technique_ids"])


def _comment(text: str) -> str:
    return "<!-- " + text.replace("--", "- -") + " -->"


def _keyword_regex(atoms: list[Atom]) -> tuple[str, bool]:
    """Combine keyword atoms of one conjunction into a single <regex>."""
    if len(atoms) == 1:
        return atoms[0].expression, atoms[0].negated
    parts = []
    for a in atoms:
        inner = ("(?i:" if a.ci else "(?:") + a.pattern + ")"
        parts.append(("(?!" if a.negated else "(?=") + ".*?" + inner + ")")
    return "^" + "".join(parts), False


def render_rule(cr: ConvertedRule, mitre_mode: str = "wazuh") -> str:
    rule, mapping = cr.rule, cr.mapping
    level = LEVELS[rule.level.name.lower()] if rule.level else LEVELS["medium"]
    mitre = _mitre_ids(rule, mitre_mode)
    _, tactics = attack.parse_tags(str(t) for t in rule.tags)
    groups = [f"sigma_{rule.level.name.lower()}" if rule.level else "sigma_medium"]
    groups += [f"attack_{t}" for t in tactics]
    source = ""
    if rule.source is not None and getattr(rule.source, "path", None):
        try:
            source = os.path.relpath(str(rule.source.path), str(ROOT))
        except ValueError:
            source = str(rule.source.path)
    lines = [
        "  " + _comment(f"{rule.title} | sigma {rule.id} | {source}".rstrip(" |")),
    ]
    total = len(cr.branches)
    for n, (wid, branch) in enumerate(zip(cr.wazuh_ids, cr.branches), start=1):
        lines.append(f'  <rule id="{wid}" level="{level}">')
        parent = mapping.parent
        if "if_sid" in parent:
            # Hook below the logsource parent AND every stock level-0 grouping rule that can
            # swallow the event first (see opensoc_detections/wazuh/ruleset_index.py).
            sids = grouping_closure(list(parent["if_sid"])) if parent.get("hook_grouping_rules", True) else parent["if_sid"]
            lines.append(f"    <if_sid>{', '.join(str(s) for s in sids)}</if_sid>")
        if "if_group" in parent:
            lines.append(f"    <if_group>{escape(parent['if_group'])}</if_group>")
        if "decoded_as" in parent:
            lines.append(f"    <decoded_as>{escape(parent['decoded_as'])}</decoded_as>")
        for fname, pattern in mapping.anchor.items():
            lines.append(f'    <field name={quoteattr(fname)} type="pcre2">{escape(pattern)}</field>')
        keyword_atoms = [a for a in branch if a.field is None]
        for atom in branch:
            if atom.field is None:
                continue
            neg = ' negate="yes"' if atom.negated else ""
            lines.append(
                f'    <field name={quoteattr(atom.field)} type="pcre2"{neg}>{escape(atom.expression)}</field>'
            )
        if keyword_atoms:
            expr, neg = _keyword_regex(keyword_atoms)
            neg_attr = ' negate="yes"' if neg else ""
            lines.append(f'    <regex type="pcre2"{neg_attr}>{escape(expr)}</regex>')
        variant = f" (variant {n}/{total})" if total > 1 else ""
        lines.append(f"    <description>{escape(rule.title)}{variant}</description>")
        if mitre:
            lines.append("    <mitre>")
            lines.extend(f"      <id>{t}</id>" for t in mitre)
            lines.append("    </mitre>")
        lines.append(f"    <info type=\"text\">Sigma rule {rule.id}</info>")
        if rule.references:
            lines.append(f'    <info type="link">{escape(str(rule.references[0]))}</info>')
        for opt in mapping.options:
            lines.append(f"    <options>{escape(opt)}</options>")
        lines.append(f"    <group>{','.join(groups)},</group>")
        lines.append("  </rule>")
    return "\n".join(lines)


def render_ruleset(converted: list[ConvertedRule]) -> str:
    from opensoc_detections import __version__

    out = [
        _comment(
            "OpenSOC Sigma detections for Wazuh - GENERATED FILE, DO NOT EDIT. "
            f"Built by opensoc-detections {__version__} from detections/rules "
            "(python -m opensoc_detections convert)"
        ),
        _comment("Install: copy to /var/ossec/etc/rules/ on the Wazuh manager and restart it."),
        "",
    ]
    by_mapping: dict[str, list[ConvertedRule]] = {}
    for cr in converted:
        by_mapping.setdefault(cr.mapping.id, []).append(cr)
    for mapping_id in sorted(by_mapping, key=lambda m: by_mapping[m][0].wazuh_ids[0]):
        rules = by_mapping[mapping_id]
        out.append(f'<group name="opensoc,sigma,{mapping_id},">')
        out.append("")
        for cr in rules:
            out.append(cr.xml)
            out.append("")
        out.append("</group>")
        out.append("")
    return "\n".join(out)
