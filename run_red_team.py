#!/usr/bin/env python3
"""Fire the AI Red Team battery at the Sentinel firewall.

    python run_red_team.py

Runs fully offline (deterministic trust engine). Add an LLM key
(OPENAI_API_KEY or MINIMAX_API_KEY + SENTINEL_LLM_PROVIDER=minimax) to upgrade
social-engineering detection. AWS creds + boto3 route breach logs to CloudWatch.
"""

from __future__ import annotations

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

import sys

from src.red_team.simulator import demonstrate_learning, print_report, run_campaign


if __name__ == "__main__":
    print_report(run_campaign())
    if "--no-learn" not in sys.argv:
        demonstrate_learning()
