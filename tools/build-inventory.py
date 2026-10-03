#!/usr/bin/env python3
import argparse
import json
from maher_bounty.result_store import build_inventory

parser = argparse.ArgumentParser(description="Normalize and deduplicate Maher Bounty recon results")
parser.add_argument("result_dir", help="Directory produced by recon-passive.sh")
args = parser.parse_args()

inventory = build_inventory(args.result_dir)
print(json.dumps(inventory["counts"], indent=2))
print(f"Inventory: {args.result_dir}/inventory.json")
