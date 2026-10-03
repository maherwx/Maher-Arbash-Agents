#!/usr/bin/env bash
set -e
python3 -m pip install -e .
maher-bounty run --scope "${1:-examples/scope.yaml}" --rules "${2:-examples/rules.yaml}"
