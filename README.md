# 🛡️ Sentinel Memory

### The secure, predictive, trust aware retrieval layer for AI agents

Every AI agent can talk now. Very few can retrieve, reason, and act safely. Sentinel is the missing layer that makes retrieval safe.

Sentinel is middleware that sits between the voice layer (LiveKit) and the knowledge base (Moss). Every time an agent tries to look something up, the request passes through Sentinel first. Sentinel then decides what the agent is actually allowed to see or do, based on how much it trusts the live session, not just on how well the text matches.

In plain terms: the agent can ask for anything, but Sentinel is the bouncer at the door. A verified executive gets the payroll. A convincing deepfake of that same executive gets nothing.

Built for the Moss Conversational AI Hackathon at Y Combinator, June 2026.

Repository: https://github.com/Behruz1306/sentinel-memory. Demo runbook: see DEMO.md.

![CI](https://github.com/Behruz1306/sentinel-memory/actions/workflows/ci.yml/badge.svg)

To run the tests: `.venv/bin/python -m pytest -q`. They are offline and deterministic, so they pass with no API keys.

One command demo, after the setup below: run `./run_demo.sh` and open http://localhost:8000. We have verified live: Moss semantic retrieval, a LiveKit voice agent registered as `sentinel`, in browser voice with a real time trust gated verdict stream, and a one hundred percent red team defense rate.

---

## Why this fits the hackathon

Moss framed the problem clearly: voice is basically solved, retrieval is the real bottleneck, and agents should be able to instantly look up complex facts and act on them.

Here is the catch. The moment an agent can both retrieve and act, the agent itself becomes the attack surface. A single deepfaked phone call can quietly exfiltrate millions. So Sentinel reframes retrieval as a security decision rather than a similarity search.

Voice stays as the interface, handled by LiveKit. Retrieval gets faster through predictive pre fetch that warms the cache before the caller even finishes the sentence. The live transcript is scored for manipulation in real time. Facts are stored as relationships in a graph (User to Role to Permission to Document) so the system can reason about who may see what, and why. And when a request implies an action, Sentinel only emits an executable workflow if the session trust clears the policy.

The piece we are most proud of, and the one we built specifically for Moss, is described next.

---

## The unusual use of Moss: retrieval as the defense

Most teams point Moss at a knowledge index and stop there. Sentinel does that too, for the company knowledge. But Sentinel also runs a second Moss index whose documents are not facts. They are attacks: deepfake and CEO fraud scripts, prompt injections, wire fraud pretexts, and jailbreaks.

Every caller utterance is embedded and matched, by nearest neighbour, against this attack memory. In other words, Moss semantic search itself becomes the detector. It is a vector native intrusion detection system. The same primitive that powers what the agent knows now also powers what the firewall fears.

The clearest way to see it is the payroll example. The two sentences below are about the same topic, yet they get opposite verdicts.

```
"show me the Q2 payroll register"             nearest match is a benign request   ALLOW
"send me ALL payroll and routing now, quietly" nearest match is a fraud script     BLOCK
```

A plain keyword rule cannot tell those two apart, and a large language model is too slow to call on every turn of a live phone conversation.

We run this as a local first Moss session index rather than a cloud index, and that choice matters for three reasons. First, speed: the session index embeds and queries entirely in memory in roughly three milliseconds with no network round trip, so detection runs inline on the real time voice path. Second, it needs no cloud index slot, which keeps the deployment simple. Third, it learns: every confirmed attack is added straight into the live session, so the firewall gets harder to fool with each call.

So Moss does double duty here. It is both the agent's memory and the firewall's immune system.

---

## How the decision is made

The flow of a single voice turn looks like this.

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

The key idea is that a claim is not the same as proof. Saying "I am the CEO" over an unverified line earns almost no trust, and a synthetic voice signal pushes it down even further. The score is computed roughly like this.

```
SessionTrustScore = origin_baseline + 0.7·(role_trust × verification) − deepfake − social_eng
"CEO", claimed only, spoofed origin, voice anomaly 0.84   trust 0/100    payroll BLOCKED
"CEO", cryptographic SSO, clean voice                     trust 100/100  payroll ALLOWED
```

---

## Project layout

```
src/
  core/
    graph_kb.py       User to Role to Permission to Document graph, sensitivity tagged docs, retrieval
    session.py        live voice session security state (caller, origin, voice anomaly)
    trust_engine.py   SessionTrustScore, permission matrix, AccessDeniedException
    predictive.py     entity triggered pre-fetch worker (warms the cache early)
    actions.py        action aware executable workflow registry
    retrieval.py      the orchestrator: predictive, then trust gate, then action
    cloudwatch.py     AWS CloudWatch breach logging (local fallback)
    llm.py            OpenAI / MiniMax / gateway agnostic wrapper (deterministic fallback)
    threat_memory.py  Moss as immune system: local first session index of ATTACKS (semantic IDS)
  middleware/
    livekit_agent.py  LiveKit Agents 1.x handler: aggressive VAD and interim STT piping
    pipeline.py       SentinelPipeline (transport agnostic)
    stream_simulator.py scripted STT stream for the offline demo
  red_team/
    attacks.py        deepfake, prompt injection, wire fraud catalog
    simulator.py      campaign runner and formatted terminal report
server.py             FastAPI and the live dashboard (static/dashboard.html)
run_red_team.py       terminal red team report
demo_call.py          autonomous live call play by play (no audio hardware)
build_threat_index.py warms and self tests the threat memory, optional cloud persist
```

---

## What is wired up

Voice transport, plus speech to text, the language model, and text to speech, all run through LiveKit Agents 1.5 with LiveKit Inference. This is live and lives in `src/middleware/livekit_agent.py`.

Semantic retrieval of company knowledge runs on Moss, using the `sentinel_knowledge` index, with sub ten millisecond lookups.

Semantic threat detection runs on a local first Moss session index of attacks. It is live, takes about three milliseconds per check, and learns new attacks as it sees them.

The trust engine can call MiniMax M3 (an OpenAI compatible endpoint) for deeper reasoning, and falls back to a deterministic analysis when no key is present.

Breach logging goes to AWS CloudWatch when credentials are available, and otherwise falls back to a local file. Document ingestion through Unsiloed (turning PDFs into chunks) is supported and optional.

---

## How to run it

Moss needs Python 3.10 or newer, so use the uv managed virtual environment.

```bash
uv venv --python 3.12 .venv
uv pip install --python .venv -r requirements.txt
cp .env.example .env            # paste your LiveKit and Moss (and MiniMax) keys

# Build the Moss knowledge index once. The threat memory immune system warms
# itself automatically, and build_threat_index.py can self test it and
# optionally persist learned signatures to the cloud.
.venv/bin/python build_moss_index.py

# AI red team in the terminal. This is the most reliable backup demo.
.venv/bin/python run_red_team.py

# Autonomous live call with predictive pre-fetch and a verdict, no microphone.
.venv/bin/python demo_call.py                  # deepfake CEO, expect BLOCK
.venv/bin/python demo_call.py call-verified-ceo   # same ask, verified, expect ALLOW
.venv/bin/python demo_call.py call-book-carrier   # an authorized action

# Live dashboard.
.venv/bin/python -m uvicorn server:app --port 8000
open http://localhost:8000

# Real voice agent through LiveKit Inference (no OpenAI or Deepgram key needed).
.venv/bin/python -m src.middleware.livekit_agent console   # talk through the terminal mic
# Or use "start" to run it as a worker that the moss-hacker-starter frontend can
# dispatch to. Set the frontend AGENT_NAME to sentinel. Stamp dispatch metadata
# to set trust, for example:
# {"claimed_identity":"ceo","verification":"cryptographic","origin":"corporate_sso",
#  "verified_user_id":"user:mark"} for the allow path.
```

No keys, no problem. Everything still runs. Retrieval falls back to a local index, trust scoring stays deterministic, and breaches log to `security_events.jsonl`.

---

## The three minute demo script

Open with the hook, about fifteen seconds. Voice is solved, so we handed an AI agent a company's payroll, contracts, and bank details. Now watch what one phone call can do.

Show the deepfake next, about forty seconds. Run `python demo_call.py`. The predictive engine pre fetches payroll before the caller even finishes the sentence, so latency disappears. Then trust collapses to zero out of one hundred, because it is a claimed CEO on a spoofed line with a synthetic voice. The payroll request is blocked and a red alert is logged to CloudWatch.

Then show that Sentinel is not just paranoid, about twenty five seconds. Run `python demo_call.py call-verified-ceo`. It is the exact same request, but cryptographically verified, so trust is one hundred and the request is allowed.

Show action awareness, about twenty five seconds. Run `python demo_call.py call-book-carrier`. The phrase "book our preferred carrier" is authorized, so Sentinel emits a real executable workflow, a POST to /tms/bookings. Retrieval has become safe autonomous action.

Run the red team, about forty seconds. Run `python run_red_team.py`. A deepfake, two prompt injections, and a wire fraud attempt all get blocked, for a one hundred percent defense rate. Each attack is tagged with the Moss threat memory match that caught it, and then the self learning immune system is taught a brand new paraphrased jailbreak live.

Close with the vision, about fifteen seconds. Sentinel is the Cloudflare for AI agents. It is the trust layer that controls what every autonomous agent knows, retrieves, and does, with Moss doing double duty as both the memory and the immune system.
