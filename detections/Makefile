# OpenSOC detection-as-code - common tasks (run from detections/)
PYTHON ?= python3
VENV   ?= .venv
PY     := $(VENV)/bin/python

.PHONY: help install validate convert coverage build test test-unit test-wazuh check clean

help:
	@echo "install     create $(VENV) and install the toolchain (pySigma, sigma-cli, pytest)"
	@echo "validate    sigma-cli check + OpenSOC policy"
	@echo "convert     Sigma -> Wazuh XML (output/wazuh/opensoc_sigma_rules.xml)"
	@echo "coverage    ATT&CK Navigator layer + coverage/COVERAGE.md"
	@echo "build       validate + convert + coverage"
	@echo "test        all tests (Wazuh integration tests need Docker)"
	@echo "test-unit   tests without Docker"
	@echo "test-wazuh  only the wazuh-logtest integration tests"
	@echo "check       what CI runs: validate, drift checks, all tests"

$(PY):
	$(PYTHON) -m venv $(VENV)
	$(PY) -m pip install -q --upgrade pip
	$(PY) -m pip install -q -r requirements.txt -e .

install: $(PY)

validate: $(PY)
	$(PY) -m opensoc_detections validate

convert: $(PY)
	$(PY) -m opensoc_detections convert

coverage: $(PY)
	$(PY) -m opensoc_detections coverage

build: $(PY)
	$(PY) -m opensoc_detections build

test: $(PY)
	$(PY) -m pytest

test-unit: $(PY)
	$(PY) -m pytest -m "not wazuh"

test-wazuh: $(PY)
	OPENSOC_REQUIRE_WAZUH=1 $(PY) -m pytest -m wazuh

check: $(PY)
	$(PY) -m opensoc_detections validate
	$(PY) -m opensoc_detections convert --check
	$(PY) -m opensoc_detections coverage --check
	OPENSOC_REQUIRE_WAZUH=1 $(PY) -m pytest

clean:
	rm -rf $(VENV) .pytest_cache build *.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
