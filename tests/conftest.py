import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))
os.environ.setdefault("SECRET_KEY", "test-secret-key")


@pytest.fixture()
def app(tmp_path):
    from app import create_app
    from app.security import ratelimit
    ratelimit.reset()
    return create_app({"DATABASE_URL": f"sqlite:///{tmp_path / 'test.db'}", "TESTING": True, "ADMIN_EMAIL": "admin@example.com",
                       "RATE_LIMIT_SCAN_PER_MIN": 1000, "RATE_LIMIT_AUTH_PER_MIN": 1000})


@pytest.fixture()
def client(app):
    return app.test_client()


def _register(client, name, email, pw="Str0ngPassw0rd!"):
    r = client.post("/api/auth/register", json={"username": name, "email": email, "password": pw})
    assert r.status_code == 201, r.get_json()
    return {"Authorization": "Bearer " + r.get_json()["token"]}


@pytest.fixture()
def auth(client):
    return _register(client, "alice", "alice@example.com")


@pytest.fixture()
def make_user(client):
    return lambda name, email: _register(client, name, email)
