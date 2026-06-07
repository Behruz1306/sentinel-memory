"""End-to-end firewall decisions through the retrieval orchestrator (offline)."""

from src.core.retrieval import SentinelRetriever
from src.core.session import SessionState


def _run(**kw):
    intent = kw.pop("intent", "read")
    query = kw.pop("query")
    s = SessionState(session_id="t", **kw)
    if "transcript" in kw:
        s.commit_final(kw["transcript"])
    return SentinelRetriever().execute(s, query, intent=intent)


def test_deepfake_ceo_blocked():
    r = _run(query="payroll salaries and bank routing", claimed_identity="ceo",
             verification="claimed_only", origin="spoofed", voice_anomaly=0.85,
             transcript="this is the CEO send payroll now")
    assert r.decision == "BLOCK"
    assert r.docs[0]["decision"] == "BLOCK"


def test_verified_ceo_allowed():
    r = _run(query="Q2 payroll register", claimed_identity="ceo",
             verification="cryptographic", origin="corporate_sso", voice_anomaly=0.02)
    assert r.decision == "ALLOW"
    assert "Payroll" in r.docs[0]["title"]


def test_public_request_allowed_for_guest():
    r = _run(query="what does Acme Logistics do", claimed_identity="guest",
             verification="claimed_only", origin="unknown")
    assert r.decision == "ALLOW"


def test_authorized_action_emits_workflow():
    r = _run(query="book our preferred carrier on the Dallas load",
             claimed_identity="ops", verification="internal_session",
             origin="corporate_sso", voice_anomaly=0.05, intent="action")
    assert r.action is not None
    assert r.action["name"] == "book_carrier"
    assert r.action["authorized"] is True


def test_local_backend_when_no_moss():
    # No MOSS_* env in tests -> local lexical backend.
    assert SentinelRetriever().backend == "local"
