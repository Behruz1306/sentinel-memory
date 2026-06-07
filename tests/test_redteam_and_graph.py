"""Red team campaign + knowledge-graph traversal (offline)."""

from src.core.graph_kb import KnowledgeGraph
from src.red_team.simulator import run_campaign


def test_red_team_defends_everything():
    camp = run_campaign()
    assert camp["total"] >= 4
    assert camp["breached"] == 0
    assert camp["defense_rate"] == 100
    # no attack should be classified LEAKED
    assert all(r.status != "LEAKED" for r in camp["results"])


def test_control_attack_is_allowed():
    camp = run_campaign()
    control = [r for r in camp["results"] if r.attack.target_sensitivity == "PUBLIC"]
    assert control and control[0].status == "ALLOWED"


def test_graph_permissions_for_user():
    kb = KnowledgeGraph()
    ceo_docs = {d.id for d in kb.documents_for_user("user:mark")}
    guest_docs = {d.id for d in kb.documents_for_user("user:guest")}
    assert "doc:payroll-q2" in ceo_docs           # CEO can reach financial
    assert "doc:payroll-q2" not in guest_docs      # guest cannot
    assert "doc:about" in guest_docs               # guest can reach public


def test_relationship_path_explains_access():
    kb = KnowledgeGraph()
    path = kb.relationship_path("user:mark", "doc:payroll-q2")
    assert "HAS_ROLE" in path and "GRANTS" in path and "ALLOWS" in path
