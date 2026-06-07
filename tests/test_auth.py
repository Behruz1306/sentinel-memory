"""Auth + user-scoped sessions."""

import os
import tempfile

import pytest

os.environ["SENTINEL_LLM_PROVIDERS"] = ""
os.environ["RENDER"] = "true"


@pytest.fixture
def tmp_db(monkeypatch):
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    monkeypatch.setenv("SENTINEL_DB_PATH", path)
    import src.core.sqlite_store as sqlite_store
    sqlite_store.reset_connection()
    yield
    sqlite_store.reset_connection()
    try:
        os.unlink(path)
    except OSError:
        pass


def test_login_demo_user(tmp_db):
    from src.core import auth

    auth.ensure_demo_users()
    out = auth.login("analyst@sentinel.io", "demo123")
    assert "token" in out
    assert out["user"]["email"] == "analyst@sentinel.io"
    me = auth.resolve_token(out["token"])
    assert me["name"] == "Alex Rivera"


def test_user_scoped_session(tmp_db):
    from src.core import auth, persistence as db

    auth.ensure_demo_users()
    tok = auth.login("judge@moss.io", "moss2026")["token"]
    user = auth.resolve_token(tok)
    sid = db.create_session(company_id="acme-logistics", user_id=user["id"])
    mine = db.list_sessions(user_id=user["id"])
    assert any(s["id"] == sid for s in mine)
    all_sess = db.list_sessions()
    assert len(all_sess) >= 1


def test_knowledge_list():
    from src.core.company_kb import list_documents

    docs = list_documents("meridian-health")
    assert len(docs) >= 4
    assert any(d["sensitivity"] == "RESTRICTED" for d in docs)
