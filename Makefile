# Shadowprint — Model Context Protocol Security Auditor & Exploit Knowledge Graph
# Hackathon Track 01: Agents That Act on Connected Data
# Co-builders: Gaurang Udgirkar & Jasjyot Singh

.PHONY: help install run audit scorecard triage test docker clean

PYTHON ?= python

help:
	@echo "Shadowprint Commands:"
	@echo "  make run        - Launch one-click runner & dashboard at http://localhost:8080"
	@echo "  make audit      - Run security audit against vulnerable_runner"
	@echo "  make scorecard  - Run 7-fixture automated benchmark recall scorecard"
	@echo "  make triage     - Run FalkorDB AI Triage Agent decision"
	@echo "  make test       - Run pytest test suite"
	@echo "  make docker     - Build and run full Docker Compose environment"
	@echo "  make install    - Install frozen dependencies"
	@echo "  make clean      - Clean cache and temporary files"

install:
	$(PYTHON) -m pip install -r requirements.txt
	$(PYTHON) -m pip install -e .

run:
	$(PYTHON) start.py

audit:
	$(PYTHON) -m shadowprint.cli audit fixtures/vulnerable_runner

scorecard:
	$(PYTHON) -m shadowprint.cli scorecard

triage:
	$(PYTHON) -m shadowprint.cli graph triage fixtures/compound_exploit_server --use-test-double

test:
	$(PYTHON) -m pytest tests/ -v

docker:
	docker compose up --build

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache/ *.egg-info/
