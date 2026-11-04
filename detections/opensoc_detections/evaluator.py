"""Reference Sigma evaluator used by the sample tests.

Evaluates the condition tree pySigma parses from a rule (modifiers already applied)
against a normalized event that uses Sigma field names. It is deliberately
independent from the Wazuh converter, so the same samples cross-check both:

    Sigma semantics (this module)  <->  converted Wazuh XML in a real wazuh-logtest
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, Iterator

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.rule import SigmaRule
from sigma.types import (
    CompareOperators,
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
    SigmaString,
    SpecialChars,
)

_MISSING = object()


def _lookup(event: Any, field: str) -> Any:
    """Exact key first, then dotted path traversal (CloudTrail style nesting)."""
    if isinstance(event, dict) and field in event:
        return event[field]
    if not isinstance(event, dict):
        return _MISSING
    parts = field.split(".")
    for i in range(1, len(parts)):
        head = ".".join(parts[:i])
        if head in event:
            found = _lookup(event[head], ".".join(parts[i:]))
            if found is not _MISSING:
                return found
    return _MISSING


def _scalars(value: Any) -> list[Any]:
    """Candidate values: lists match if any element matches, or as their JSON text."""
    if isinstance(value, list):
        out = []
        for v in value:
            out.extend(_scalars(v))
        out.append(json.dumps(value, separators=(",", ":")))
        return out
    if isinstance(value, dict):
        return [json.dumps(value, separators=(",", ":"))]
    return [value]


def _text(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def _string_regex(value: SigmaString) -> re.Pattern:
    out = []
    for part in value.iter_parts():
        if part == SpecialChars.WILDCARD_MULTI:
            out.append(".*")
        elif part == SpecialChars.WILDCARD_SINGLE:
            out.append(".")
        else:
            out.append(re.escape(part))
    flags = re.DOTALL | (0 if isinstance(value, SigmaCasedString) else re.IGNORECASE)
    return re.compile("".join(out), flags)


def _iter_event_values(event: Any) -> Iterator[Any]:
    if isinstance(event, dict):
        for v in event.values():
            yield from _iter_event_values(v)
    elif isinstance(event, list):
        for v in event:
            yield from _iter_event_values(v)
    elif event is not None:
        yield event


def _compare(op: CompareOperators, left: float, right: float) -> bool:
    return {
        CompareOperators.LT: left < right,
        CompareOperators.LTE: left <= right,
        CompareOperators.GT: left > right,
        CompareOperators.GTE: left >= right,
        CompareOperators.NEQ: left != right,
    }[op]


def match_value(value: Any, raw: Any, event: dict) -> bool:
    present = raw is not _MISSING and raw is not None
    if isinstance(value, SigmaExpansion):
        return any(match_value(v, raw, event) for v in value.values)
    if isinstance(value, SigmaNull):
        return not present
    if isinstance(value, SigmaExists):
        return present == bool(value)
    if not present:
        return False
    candidates = [c for c in _scalars(raw) if c is not None]
    if isinstance(value, SigmaString):
        rx = _string_regex(value)
        return any(rx.fullmatch(_text(c)) for c in candidates)
    if isinstance(value, SigmaBool):
        return any(_text(c).lower() == ("true" if value.boolean else "false") for c in candidates)
    if isinstance(value, SigmaNumber):
        for c in candidates:
            try:
                if float(c) == float(value.number):
                    return True
            except (TypeError, ValueError):
                continue
        return False
    if isinstance(value, SigmaRegularExpression):
        flags = 0
        if SigmaRegularExpressionFlag.IGNORECASE in value.flags:
            flags |= re.IGNORECASE
        if SigmaRegularExpressionFlag.MULTILINE in value.flags:
            flags |= re.MULTILINE
        if SigmaRegularExpressionFlag.DOTALL in value.flags:
            flags |= re.DOTALL
        rx = re.compile(str(value.regexp), flags)
        return any(rx.search(_text(c)) for c in candidates)
    if isinstance(value, SigmaCIDRExpression):
        for c in candidates:
            try:
                if ipaddress.ip_address(_text(c)) in value.network:
                    return True
            except ValueError:
                continue
        return False
    if isinstance(value, SigmaCompareExpression):
        for c in candidates:
            try:
                if _compare(value.op, float(c), float(value.number.number)):
                    return True
            except (TypeError, ValueError):
                continue
        return False
    if isinstance(value, SigmaFieldReference):
        other = _lookup(event, value.field)
        return other is not _MISSING and any(_text(c) == _text(o) for c in candidates for o in _scalars(other))
    raise TypeError(f"unsupported Sigma value type {type(value).__name__}")


def _eval(node: Any, event: dict) -> bool:
    if isinstance(node, ConditionAND):
        return all(_eval(a, event) for a in node.args)
    if isinstance(node, ConditionOR):
        return any(_eval(a, event) for a in node.args)
    if isinstance(node, ConditionNOT):
        return not _eval(node.args[0], event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return match_value(node.value, _lookup(event, node.field), event)
    if isinstance(node, ConditionValueExpression):
        # Keywords: substring/wildcard search over every value of the event.
        value = node.value
        if isinstance(value, SigmaString):
            rx = _string_regex(value)
            return any(rx.search(_text(v)) for v in _iter_event_values(event))
        if isinstance(value, SigmaRegularExpression):
            rx = re.compile(str(value.regexp))
            return any(rx.search(_text(v)) for v in _iter_event_values(event))
        return any(_text(v) == _text(value) for v in _iter_event_values(event))
    if node is None:
        return False
    raise TypeError(f"unsupported condition node {type(node).__name__}")


def evaluate(rule: SigmaRule, event: dict) -> bool:
    """True if the event satisfies any of the rule's conditions."""
    return any(_eval(cond.parsed, event) for cond in rule.detection.parsed_condition)
