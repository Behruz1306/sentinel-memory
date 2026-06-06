#!/usr/bin/env python3
"""Autonomous live-call demo (no audio hardware required).

Streams a scripted call's partial STT tokens through the full Sentinel
pipeline, showing predictive pre-fetch warming the cache *before* the caller
finishes, then the trust-gated verdict.

    python demo_call.py                 # runs the deepfake-CEO call
    python demo_call.py call-verified-ceo
    python demo_call.py --list
"""

from __future__ import annotations

import sys

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

from src.middleware.pipeline import SentinelPipeline
from src.middleware.stream_simulator import CALLS, get_call, play

C = {"g": "\033[92m", "r": "\033[91m", "y": "\033[93m", "c": "\033[96m",
     "b": "\033[1m", "d": "\033[2m", "x": "\033[0m"}


def _print_event(kind, payload):
    if kind == "interim":
        line = f"  {C['d']}🎙  …{payload['heard']}{C['x']}"
        if payload["prefetched"]:
            line += f"   {C['c']}⚡ pre-fetch: {', '.join(payload['prefetched'])}{C['x']}"
        print(line)
    else:
        turn = payload["turn"]
        r = turn.result
        print()
        if turn.denied:
            print(f"  {C['r']}{C['b']}⛔ BLOCKED{C['x']} — retrieval denied by Sentinel")
        elif turn.decision == "REDACT":
            print(f"  {C['y']}{C['b']}▒ REDACTED{C['x']} — served with PII masked")
        else:
            print(f"  {C['g']}{C['b']}✓ ALLOWED{C['x']} — request authorized")
        if r:
            t = r["trust"]
            print(f"  {C['d']}trust {t['score']}/100  ·  SE-risk {t['se_risk']}/100  "
                  f"·  identity {t['identity_trust']}  ·  deepfake −{t['deepfake_penalty']}{C['x']}")
            for reason in r["reasons"][:3]:
                print(f"  {C['d']}↳ {reason}{C['x']}")
            pf = r.get("predictive") or {}
            if pf.get("warm"):
                print(f"  {C['c']}↳ {pf['note']} (warm cache hit){C['x']}")
            if r.get("action"):
                a = r["action"]
                state = (f"{C['g']}AUTHORIZED{C['x']}" if a["authorized"]
                         else f"{C['r']}BLOCKED{C['x']}")
                print(f"  {C['b']}⚙ action:{C['x']} {a['name']} [{state}] "
                      f"{C['d']}→ {a['method']} {a['endpoint']} {a['arguments']}{C['x']}")


def main():
    args = [a for a in sys.argv[1:]]
    if "--list" in args:
        print("\nAvailable calls:")
        for c in CALLS:
            print(f"  {c.id:22} {c.title}")
        print()
        return

    call_id = args[0] if args else "call-deepfake-cfo"
    call = get_call(call_id)
    if not call:
        print(f"Unknown call '{call_id}'. Use --list.")
        return

    print(f"\n{C['b']}📞 Incoming call — {call.title}{C['x']}")
    print(f"{C['d']}caller {call.caller_id} · claims '{call.claimed_identity}' · "
          f"origin {call.origin} ({call.origin_ip}) · voice-anomaly {call.voice_anomaly:.2f}{C['x']}")
    print(f"{C['d']}{call.notes}{C['x']}\n")

    play(call, SentinelPipeline(), delay=0.12, on_event=_print_event)
    print()


if __name__ == "__main__":
    main()
