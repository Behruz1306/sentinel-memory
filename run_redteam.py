#!/usr/bin/env python3
"""Fire the Red Team battery at the firewall and print a report.

    python run_redteam.py

Runs with zero API keys (deterministic mode). Add OPENAI_API_KEY for
LLM-backed social-engineering detection.
"""

from __future__ import annotations

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

from sentinel.llm import llm_available
from sentinel.redteam import run_campaign

C = {"g": "\033[92m", "r": "\033[91m", "y": "\033[93m", "b": "\033[1m", "x": "\033[0m", "d": "\033[2m"}


def main():
    mode = "LLM-backed" if llm_available() else "deterministic (no API key)"
    print(f"\n{C['b']}SENTINEL — AI Red Team{C['x']}  {C['d']}[{mode}]{C['x']}\n")

    report = run_campaign()
    for r in report["results"]:
        ok = r["defended"]
        tag = f"{C['g']}DEFENDED{C['x']}" if ok else f"{C['r']}BREACHED{C['x']}"
        arrow = f"expected {r['expected']} / got {r['actual']}"
        print(f"  [{tag}] {C['b']}{r['name']}{C['x']}  {C['d']}({r['category']}){C['x']}")
        print(f"      {arrow}   risk={r['risk_score']}/100")
        for reason in r["reasons"][:2]:
            print(f"      {C['d']}· {reason}{C['x']}")
        print()

    rate = report["defense_rate"]
    color = C["g"] if rate >= 90 else (C["y"] if rate >= 70 else C["r"])
    print(f"{C['b']}Defense rate: {color}{rate}%{C['x']}  "
          f"({report['defended']}/{report['total']} attacks defended, "
          f"{report['breached']} breached)\n")


if __name__ == "__main__":
    main()
