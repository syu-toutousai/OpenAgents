import os
os.environ.setdefault("JWT_SECRET", "test-secret-for-ratelimit-tests")

import time
from unittest.mock import patch

import jwt
import pytest
from fastapi.testclient import TestClient

from api.middleware.auth import JWT_ALGORITHM
from api.middleware.ratelimit import TIER_LIMITS, WINDOW_SECONDS, _request_counts
from api.main import app


client = TestClient(app)


def _make_token(roles: list = None):
    import uuid
    from datetime import datetime, timedelta
    payload = {
        "sub": "test_user",
        "address": "0x123",
        "roles": roles or [],
        "exp": datetime.utcnow() + timedelta(hours=1),
        "iat": datetime.utcnow(),
        "type": "access",
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, os.environ["JWT_SECRET"], algorithm=JWT_ALGORITHM)


class TestAnonymousTier:
    def test_anonymous_gets_60_limit_header(self):
        _request_counts.clear()
        resp = client.get("/agents")
        assert resp.status_code == 200
        assert resp.headers.get("X-RateLimit-Limit") == str(TIER_LIMITS["anonymous"])

    def test_anonymous_exhausted_gets_429(self):
        _request_counts.clear()
        limit = TIER_LIMITS["anonymous"]
        for _ in range(limit):
            resp = client.get("/agents")
            assert resp.status_code == 200
        resp = client.get("/agents")
        assert resp.status_code == 429
        data = resp.json()
        assert data["error"] == "Rate limit exceeded"
        assert data["tier"] == "anonymous"
        assert "retry_after" in data

    def test_anonymous_429_has_retry_after(self):
        _request_counts.clear()
        limit = TIER_LIMITS["anonymous"]
        for _ in range(limit):
            client.get("/agents")
        resp = client.get("/agents")
        assert resp.status_code == 429
        assert "Retry-After" in resp.headers
        assert int(resp.headers["Retry-After"]) > 0


class TestAuthenticatedTier:
    def test_authenticated_gets_300_limit(self):
        _request_counts.clear()
        token = _make_token()
        headers = {"Authorization": f"Bearer {token}"}
        limit = TIER_LIMITS["authenticated"]
        for _ in range(limit):
            resp = client.get("/agents", headers=headers)
            assert resp.status_code == 200
        resp = client.get("/agents", headers=headers)
        assert resp.status_code == 429

    def test_authenticated_tier_in_response(self):
        _request_counts.clear()
        token = _make_token()
        headers = {"Authorization": f"Bearer {token}"}
        resp = client.get("/agents", headers=headers)
        assert resp.status_code == 200
        assert resp.headers.get("X-RateLimit-Limit") == str(TIER_LIMITS["authenticated"])


class TestPremiumTier:
    def test_premium_gets_1000_limit(self):
        _request_counts.clear()
        token = _make_token(roles=["premium"])
        headers = {"Authorization": f"Bearer {token}"}
        limit = TIER_LIMITS["premium"]
        for _ in range(limit):
            resp = client.get("/agents", headers=headers)
            assert resp.status_code == 200
        resp = client.get("/agents", headers=headers)
        assert resp.status_code == 429

    def test_premium_tier_in_response(self):
        _request_counts.clear()
        token = _make_token(roles=["premium"])
        headers = {"Authorization": f"Bearer {token}"}
        resp = client.get("/agents", headers=headers)
        assert resp.status_code == 200
        assert resp.headers.get("X-RateLimit-Limit") == str(TIER_LIMITS["premium"])

    def test_invalid_token_falls_back_to_anonymous(self):
        _request_counts.clear()
        headers = {"Authorization": "Bearer invalid_token"}
        resp = client.get("/agents", headers=headers)
        assert resp.status_code == 200
        assert resp.headers.get("X-RateLimit-Limit") == str(TIER_LIMITS["anonymous"])


class TestAPIKeyTier:
    def test_valid_api_key_gets_premium(self):
        _request_counts.clear()
        with patch.dict(os.environ, {"PREMIUM_API_KEYS": "sk-test-key-123", "JWT_SECRET": os.environ["JWT_SECRET"]}):
            headers = {"X-API-Key": "sk-test-key-123"}
            resp = client.get("/agents", headers=headers)
            assert resp.status_code == 200
            assert resp.headers.get("X-RateLimit-Limit") == str(TIER_LIMITS["premium"])


class TestRateLimitHeaders:
    def test_headers_present_on_success(self):
        _request_counts.clear()
        resp = client.get("/agents")
        assert resp.status_code == 200
        assert "X-RateLimit-Limit" in resp.headers
        assert "X-RateLimit-Remaining" in resp.headers
        assert "X-RateLimit-Reset" in resp.headers

    def test_headers_values_are_valid(self):
        _request_counts.clear()
        resp = client.get("/agents")
        assert resp.status_code == 200
        assert int(resp.headers["X-RateLimit-Limit"]) > 0
        assert int(resp.headers["X-RateLimit-Remaining"]) >= 0
        assert int(resp.headers["X-RateLimit-Reset"]) >= 0


class TestHealthEndpoint:
    def test_health_not_rate_limited(self):
        _request_counts.clear()
        for _ in range(200):
            resp = client.get("/health")
            assert resp.status_code == 200
