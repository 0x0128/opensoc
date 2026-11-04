"""Adversary emulation with Atomic Red Team and validation of the detections in Wazuh."""

from .scenarios import Scenario, load_scenarios

__all__ = ["Scenario", "load_scenarios"]
