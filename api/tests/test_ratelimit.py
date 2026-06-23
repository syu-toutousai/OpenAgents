import os
os.environ.setdefault("JWT_SECRET", "test-secret-for-ratelimit-tests")

import time
from unittest.mock import patch

import jwt
import pytest
from fastapi.testclient import TestClient

from api.middleware.auth import JWT_ALGORITHM


@pytest.fixture
def client():
    from api.main import app
    return TestClient(app)


def _make_token(roles=None):
    payload = {
        "sub": "test-user",
        "address": "0xtest",
        "roles": roles or [],
        "type": "access",
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
        "jti": "test-jti-" + str(time.time()),
    }
    return jwt.encode(payload, os.environ["JWT_SECRET"], algorithm=JWT_ALGORITHM)


class TestTierLimits:
    def test_anonymous_tier(self, client):
        for _ in range(60):
            r = client.get("/agents", headers={})
            assert r.status_code == 200
        r = client.get("/agents", headers={})
        assert r.status_code == 429
        assert "Retry-After" in r.headers

    def test_authenticated_tier(self, client):
        token = _make_token(roles=["user"])
        for _ in range(300):
            r = client.get("/agents", headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 200
        r = client.get("/agents", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 429

    def test_premium_tier(self, client):
        token = _make_token(roles=["premium"])
        for _ in range(1000):
            r = client.get("/agents", headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 200
        r = client.get("/agents", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 429

    def test_token_without_premium_gets_authenticated(self, client):
        token = _make_token(roles=["user"])
        r = client.get("/agents", headers={"Authorization": f"Bearer {token}"})
        assert "X-RateLimit-Limit" in r.headers
        assert r.headers["X-RateLimit-Limit"] == "300"


class TestHeaders:
    def test_rate_limit_headers_present(self, client):
        r = client.get("/agents", headers={})
        assert "X-RateLimit-Limit" in r.headers
        assert "X-RateLimit-Remaining" in r.headers
        assert "X-RateLimit-Reset" in r.headers

    def test_rate_limit_headers_values(self, client):
        r = client.get("/agents", headers={})
        assert r.headers["X-RateLimit-Limit"] == "60"
        assert r.headers["X-RateLimit-Remaining"] == "59"
        assert r.headers["X-RateLimit-Reset"].isdigit()

    def test_anonymous_limit_header(self, client):
        r = client.get("/agents", headers={})
        assert r.headers["X-RateLimit-Limit"] == "60"
        assert int(r.headers["X-RateLimit-Remaining"]) < 60


class Test429Response:
    def test_retry_after_header(self, client):
        for _ in range(60):
            client.get("/agents", headers={})
        r = client.get("/agents", headers={})
        assert r.status_code == 429
        assert "Retry-After" in r.headers
        assert int(r.headers["Retry-After"]) > 0

    def test_429_body(self, client):
        for _ in range(60):
            client.get("/agents", headers={})
        r = client.get("/agents", headers={})
        body = r.json()
        assert "error" in body
        assert "tier" in body
        assert body["tier"] == "anonymous"
