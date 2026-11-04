"""Per-rule samples: the `match` event must fire the Sigma rule, `no_match` must not.

Evaluated with the reference evaluator on the rule as parsed by pySigma (Sigma
semantics, before any Wazuh field mapping).
"""

import pytest

from conftest import RULE_FILES, SAMPLE_CASES
from opensoc_detections.evaluator import evaluate
from opensoc_detections.loader import load_rule, load_samples, sample_path


@pytest.mark.parametrize("path,index,case", SAMPLE_CASES)
def test_sample(path, index, case):
    rule = load_rule(path)
    assert evaluate(rule, case.event) is case.should_match, (
        f"{path.name} / {case.name}: expected {case.expect}"
    )


@pytest.mark.parametrize("path", RULE_FILES, ids=[p.stem for p in RULE_FILES])
def test_samples_cover_both_outcomes(path):
    samples = load_samples(sample_path(path))
    assert samples.rule_id == str(load_rule(path).id)
    assert {c.expect for c in samples.cases} == {"match", "no_match"}
