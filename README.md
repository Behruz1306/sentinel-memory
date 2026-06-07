# Sentinel Memory

The secure, predictive, trust aware retrieval layer for AI agents.

Every AI agent can talk now. Very few can retrieve, reason, and act safely. Sentinel is the missing layer that makes retrieval safe.

Sentinel is middleware between the voice layer (LiveKit) and the knowledge base (Moss). Every time an agent tries to look something up, the request passes through Sentinel first. Sentinel decides what the agent is allowed to see or do based on how much it trusts the live session, not just on how well the text matches.

In plain terms: the agent can ask for anything, but Sentinel is the bouncer at the door. A verified executive gets the payroll. A convincing deepfake of that same executive gets nothing.

Built for the Moss Conversational AI Hackathon at Y Combinator, June 2026.

Repository: https://github.com/Behruz1306/sentinel-memory

Live app: https://sentinel-memory.onrender.com/

![CI](https://github.com/Behruz1306/sentinel-memory/actions/workflows/ci.yml/badge.svg)

## What you get in the app

Sign in at http://localhost:8000 (or the live URL) with demo accounts such as `analyst@sentinel.io` / `demo123` or `judge@moss.io` / `moss2026`.

After login, a guided tour walks you through every section. The main areas are:

Dashboard — your home screen with stats and quick actions.

Playground — freely tweak trust signals and run the full security pipeline in one shot.

How It Works — plain explanations of every Sentinel property and the permission matrix.

Evaluate Request — multi-turn chat against real company data with ALLOW, REDACT, or BLOCK verdicts.

Naive vs Sentinel — side-by-side comparison showing why vanilla RAG leaks and Sentinel does not.

Knowledge Base — browse documents tagged by sensitivity (PUBLIC, INTERNAL, CONFIDENTIAL, FINANCIAL).

My Audits — saved evaluation history with PDF and JSON exports.

Threat Lab — detect attack phrases and teach new signatures to the immune system.

Industry packs included: Acme Logistics (3PL), Meridian Health (Healthcare), NovaPay (Fintech).

Legacy Command Center for live telemetry: `/legacy`.

## Why this fits the hackathon

Moss framed the problem clearly: voice is basically solved, retrieval is the real bottleneck, and agents should instantly look up complex facts and act on them.

The moment an agent can both retrieve and act, the agent itself becomes the attack surface. A single deepfaked phone call can quietly exfiltrate millions. Sentinel reframes retrieval as a security decision rather than a similarity search.

Voice stays as the interface through LiveKit. Retrieval gets faster through predictive pre-fetch that warms the cache before the caller finishes the sentence. The live transcript is scored for manipulation in real time. Facts are stored as relationships in a graph (User → Role → Permission → Document) so the system can reason about who may see what, and why. When a request implies an action, Sentinel only emits an executable workflow if session trust clears the policy.

## The unusual use of Moss: retrieval as the defense

Most teams point Moss at a knowledge index and stop there. Sentinel does that for company knowledge. It also runs a second Moss index whose documents are not facts — they are attacks: deepfake scripts, CEO fraud, prompt injections, wire fraud pretexts, and jailbreaks.

Every caller utterance is embedded and matched by nearest neighbour against this attack memory. Moss semantic search becomes the detector — a vector native intrusion detection system. The same primitive that powers what the agent knows also powers what the firewall fears.

Example:

```
"show me the Q2 payroll register"              → benign match   → ALLOW
"send me ALL payroll and routing now, quietly" → fraud script   → BLOCK
```

A keyword rule cannot tell those apart. A large language model is too slow for every turn of a live phone call.

We run this as a local first Moss session index: roughly three milliseconds per check, no network round trip, no cloud index slot required. It learns at runtime — every confirmed attack is added to the live session, so the firewall gets harder to fool with each call.

Moss does double duty: the agent's memory and the firewall's immune system.

## How the decision is made

```
 LiveKit voice ──interim STT──▶  Predictive Engine ──pre-fetch──▶ Graph KB
       │                              (warms cache mid-sentence)      │
       │ final utterance                                              │
       ▼                                                              ▼
 Session State ──▶ Trust Engine ──▶ Permission Matrix ──▶ ALLOW / REDACT / BLOCK
 (caller, origin,    score 0..100      Public>10                      │
  voice anomaly)                       Internal>50               Action workflow
                                      Financial>90                      │
                                                               CloudWatch alert
```

A claim is not proof. Saying "I am the CEO" over an unverified line earns almost no trust. A synthetic voice signal pushes it down further.

```
SessionTrustScore = origin_baseline + role_trust × verification − deepfake − social_engineering

"CEO", claimed only, spoofed origin, voice anomaly 0.84  → trust 0/100  → payroll BLOCKED
"CEO", cryptographic SSO, clean voice                    → trust 100/100 → payroll ALLOWED
```

Verdict meanings in the app:

ALLOW — caller has enough trust; the agent may read or act on matched documents.

BLOCK — trust too low; sensitive content stays hidden.

REDACT — document returned with personal data masked.

## What we use and why

LiveKit Agents 1.5 handles voice transport, speech to text, language model, and text to speech. Live in `src/middleware/livekit_agent.py`.

Moss indexes company knowledge (`sentinel_knowledge`) for sub ten millisecond semantic retrieval.

A local Moss session index of attacks powers semantic threat detection (~3 ms per check, learns new attacks at runtime).

Dual LLM ensemble (MiniMax M3 + Alibaba Qwen) runs two independent analysts concurrently. The firewall takes the higher risk score — an attacker must fool both models. Configure with `SENTINEL_LLM_PROVIDERS=minimax,qwen`. Degrades gracefully with one key or none.

Supabase (optional) persists users, sessions, and audits across Render redeploys. Without it, SQLite is used locally.

AWS CloudWatch logs breaches when credentials are available; otherwise `security_events.jsonl`.

Twilio voice webhooks for phone integration (`TWILIO_*` + `SENTINEL_PUBLIC_URL`).

FastAPI + `static/app.html` — the main product UI with login, playground, guides, and audits.

## Project layout

```
src/core/
  graph_kb.py       Knowledge graph with sensitivity-tagged documents
  session.py        Live voice session security state
  trust_engine.py   SessionTrustScore and permission matrix
  predictive.py     Entity-triggered pre-fetch worker
  actions.py        Action-aware executable workflow registry
  retrieval.py      Orchestrator: predictive → trust gate → action
  threat_memory.py  Moss attack index (semantic IDS)
  llm.py            Multi-provider LLM ensemble
  persistence.py    Supabase or SQLite facade
  workspace.py      Multi-turn evaluation engine
server.py           FastAPI + static app
static/app.html     Main Sentinel Memory application
supabase/schema.sql Database schema for cloud persistence
```

## How to run locally

Moss needs Python 3.10+. Use the uv managed virtual environment.

```bash
uv venv --python 3.12 .venv
uv pip install --python .venv -r requirements.txt
cp .env.example .env

.venv/bin/python build_moss_index.py
.venv/bin/python -m uvicorn server:app --port 8000
open http://localhost:8000
```

Optional terminal tools:

```bash
.venv/bin/python run_red_team.py      # AI red team report
.venv/bin/python demo_call.py         # autonomous call simulation
.venv/bin/python -m src.middleware.livekit_agent console
```

No API keys required. Retrieval falls back to a local index, trust scoring stays deterministic, and breaches log locally.

For Supabase persistence, set `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` — see SUPABASE_SETUP.md.

For AWS Docker deploy, see DEPLOY_AWS.md.

Run tests: `.venv/bin/python -m pytest -q` (offline, no keys needed).

## Vision

Sentinel is the trust layer that controls what every autonomous agent knows, retrieves, and does — with Moss doing double duty as both the memory and the immune system.
