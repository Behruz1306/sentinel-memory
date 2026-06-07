# 🛡️ Sentinel Memory

### The secure, predictive, trust-aware retrieval layer for AI agents.

> **Every AI agent can talk. Very few can retrieve, reason, and act *securely*.**

Sentinel is middleware that sits between **voice (LiveKit)** and the **knowledge
base (Moss paradigm)**. Every retrieval an agent makes passes through it, and
Sentinel decides — based on **session trust**, not just semantic similarity —
what may be **retrieved, redacted, blocked, or acted on**.

Built for the **Moss Conversational AI Hackathon @ Y Combinator** · June 2026.

**Repo:** https://github.com/Behruz1306/sentinel-memory · **Demo runbook:** [DEMO.md](DEMO.md)

> One-command demo (after setup below): `./run_demo.sh` → open http://localhost:8000
> Live-verified: Moss semantic retrieval, LiveKit voice agent registered as
> `sentinel`, in-browser voice with a real-time trust-gated verdict stream,
> 100% red-team defense.

---

## Why it fits the hackathon

> Moss: *"Voice is solved. Retrieval is the bottleneck. Agents should instantly
> look up complex facts and act on them."*

The moment agents can retrieve **and act**, the agent becomes the new attack
surface — one deepfake call can exfiltrate millions. Sentinel reinvents
retrieval as a **security decision**.

| Moss says | Sentinel does |
|---|---|
| Voice is solved | Uses voice only as the interface (LiveKit + aggressive VAD) |
| **Retrieval is the bottleneck** | **Predictive pre-fetch** warms the cache *before* you finish speaking |
| Fluid conversations | Scores the live transcript for manipulation in real time |
| Instantly look up complex facts | **Graph memory** (User→Role→Permission→Document) reasons over relationships |
| **Act on retrieved knowledge** | **Action-aware** retrieval emits executable workflows — only when trust clears policy |

---

## Architecture

```
 LiveKit voice ──interim STT tokens──▶  Predictive Engine ──pre-fetch──▶ Graph KB
       │                                      (warms cache mid-sentence)     │
       │ final utterance                                                     │
       ▼                                                                     ▼
 Session State ──▶ Trust & Risk Engine ──▶ Permission Matrix ──▶ ALLOW / REDACT / BLOCK
 (caller, origin,    SessionTrustScore        Public>10                    │
  voice-anomaly)     0..100                   Internal>50            Action-Aware
                                              Financial>90           Workflow object
                                                   │                       │
                                          AccessDeniedException      AWS CloudWatch
                                                                     🚨 RED ALERT
```

**Trust ≠ claim.** Claiming to be the CEO over an unverified line earns almost
nothing; a synthetic-voice (deepfake) signal crushes it further:

```
SessionTrustScore = origin_baseline + 0.7·(role_trust × verification) − deepfake − social_eng
"CEO", claimed_only, spoofed origin, voice-anomaly 0.84  →  trust 0/100  →  payroll BLOCKED
"CEO", cryptographic SSO, clean voice                    →  trust 100/100 →  payroll ALLOWED
```

---

## Layout

```
src/
  core/
    graph_kb.py       # User→Role→Permission→Document graph + sensitivity-tagged docs + retrieval
    session.py        # live voice-session security state (caller, origin, voice anomaly)
    trust_engine.py   # SessionTrustScore + permission matrix + AccessDeniedException
    predictive.py     # entity-triggered pre-fetch worker (Moss paradigm)
    actions.py        # action-aware executable workflow registry
    retrieval.py      # the orchestrator: predictive → trust gate → action
    cloudwatch.py     # AWS CloudWatch breach logging (local fallback)
    llm.py            # OpenAI / MiniMax / gateway-agnostic wrapper (+ deterministic fallback)
  middleware/
    livekit_agent.py  # LiveKit Agents 1.x handler: aggressive VAD + interim STT piping
    pipeline.py       # SentinelPipeline (transport-agnostic)
    stream_simulator.py # scripted STT stream for the offline demo
  red_team/
    attacks.py        # deepfake / prompt-injection / wire-fraud catalog
    simulator.py      # campaign runner + formatted terminal report
server.py             # FastAPI + live dashboard   ·   static/dashboard.html
run_red_team.py       # terminal red-team report
demo_call.py          # autonomous live-call play-by-play (no audio hardware)
```

---

## Live integrations

| Layer | Powered by | Status |
|---|---|---|
| Voice transport + STT/LLM/TTS | **LiveKit** Agents 1.5 + Inference | live (`src/middleware/livekit_agent.py`) |
| Semantic retrieval | **Moss** (`sentinel_knowledge` index) | live, sub-10ms |
| Trust-engine LLM reasoning | **MiniMax-M3** (OpenAI-compatible) | wired (deterministic fallback) |
| Breach logging | **AWS** CloudWatch | wired (local fallback) |
| Document ingestion | **Unsiloed** (PDF → chunks) | optional |

## Run it

Moss needs Python ≥3.10 — use the uv-managed venv:

```bash
uv venv --python 3.12 .venv
uv pip install --python .venv -r requirements.txt
cp .env.example .env            # paste your LiveKit + Moss (+ MiniMax) keys

# 0) Build the Moss knowledge index (once):
.venv/bin/python build_moss_index.py

# 1) AI Red Team (terminal) — the reliable backup demo:
.venv/bin/python run_red_team.py

# 2) Autonomous live call (predictive pre-fetch + verdict, no mic):
.venv/bin/python demo_call.py                 # deepfake CEO  -> BLOCK
.venv/bin/python demo_call.py call-verified-ceo   # same ask, verified -> ALLOW
.venv/bin/python demo_call.py call-book-carrier   # authorized action

# 3) Live dashboard:
.venv/bin/python -m uvicorn server:app --port 8000
open http://localhost:8000

# 4) Real voice agent (LiveKit Inference — no OpenAI/Deepgram key):
.venv/bin/python -m src.middleware.livekit_agent console   # talk via terminal mic
# or `... start` to run as a worker the moss-hacker-starter frontend can dispatch to
# (set the frontend AGENT_NAME=sentinel). Stamp dispatch metadata to set trust, e.g.
# {"claimed_identity":"ceo","verification":"cryptographic","origin":"corporate_sso",
#  "verified_user_id":"user:mark"} for the allow path.
```

**No keys?** Everything still runs: retrieval falls back to a local lexical
index, trust scoring is deterministic, breaches log to `security_events.jsonl`.

---

## 3-minute demo script

1. **Hook (15s)** — "Voice is solved, so we gave an AI agent a company's payroll,
   contracts and bank details. Watch what one phone call does."
2. **The deepfake (40s)** — `python demo_call.py` → watch the predictive engine
   **pre-fetch "payroll" before the caller finishes the sentence** (latency gone),
   then trust craters to **0/100** (claimed CEO + spoofed origin + deepfake voice)
   → **payroll BLOCKED**, 🚨 red alert logged to CloudWatch.
3. **Not paranoid (25s)** — `python demo_call.py call-verified-ceo` → *same ask*,
   cryptographically verified → trust **100** → **ALLOWED**.
4. **Action-aware (25s)** — `python demo_call.py call-book-carrier` → "book our
   preferred carrier" → authorized → Sentinel emits an **executable workflow**
   (`POST /tms/bookings …`). Retrieval becomes safe autonomous action.
5. **Red Team (40s)** — `python run_red_team.py` → deepfake + 2 prompt injections
   + wire fraud, all **BLOCKED**, **100% defended**, with remediation priorities.
6. **Vision (15s)** — "Sentinel is the Cloudflare for AI agents: the trust layer
   controlling what every autonomous agent knows, retrieves, and does."
```
