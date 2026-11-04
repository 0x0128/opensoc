"""`sigma check` (sigma-cli / pySigma validators) passes on the whole rule set."""

from opensoc_detections.config import RULES_DIR
from opensoc_detections.validate import run_sigma_check


def test_sigma_check_passes(attack_stix):
    code, output = run_sigma_check([RULES_DIR], attack_stix)
    assert code == 0, output
    assert "Found 0 errors, 0 condition errors and 0 issues" in output, output
