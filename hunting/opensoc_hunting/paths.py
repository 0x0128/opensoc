"""Default paths inside the repository."""

from __future__ import annotations

from pathlib import Path

HUNTING_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = HUNTING_ROOT.parent

SCENARIOS_FILE = HUNTING_ROOT / "emulation" / "scenarios.yaml"
HYPOTHESES_DIR = HUNTING_ROOT / "hypotheses"
REPORTS_DIR = HUNTING_ROOT / "reports"
DEFAULT_DETECTIONS_DIR = REPO_ROOT / "detections"
