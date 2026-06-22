import jwt
import time
import os
import uuid
from unittest.mock import patch
from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException

from api.middleware.auth import (
    JWT_SECRET, JWT_ALGORITHM,
    create_access_token, create_refresh_token, decode_token,
    get_current_user, generate_login_tokens, revoke_token, is_token_revoked,
    _revoked_tokens, ACCESS_TOKEN_EXPIRE_MINUTES,
)
from fastapi.security import HTTPAuthorizationCredentials


class TestAlgorithmNone:
    def test_rejects_none_algorithm(self):
        forged = jwt.encode({"sub": "test"}, key="", algorithm="none")
        with pytest.raises(HTTPException) as exc:
            decode_token(forged)
        assert exc.value.status_code == 401

    def test_rejects_none_algorithm_case_variations(self):
        import base64, json
        payload_b64 = base64.urlsafe_b64encode(json.dumps({"sub": "test"}).encode()).rstrip(b"=").decode()
        for alg in ["None", "NONE", "nOnE"]:
            header_b64 = base64.urlsafe_b64encode(json.dumps({"alg": alg, "typ": "JWT"}).encode()).rstrip(b"=").decode()
            forged = f"{header_b64}.{payload_b64}."
            with pytest.raises(HTTPException) as exc:
                decode_token(forged)
            assert exc.value.status_code == 401

    def test_rejects_empty_signature(self):
        token_parts = jwt.encode({"sub": "test"}, key="test", algorithm="HS256").rsplit(".", 1)
        forged = token_parts[0] + "."
        with pytest.raises(HTTPException) as exc:
            decode_token(forged)
        assert exc.value.status_code == 401

    def test_valid_hs256_succeeds(self):
        token = create_access_token({"sub": "user1", "address": "0x123"})
        payload = decode_token(token)
        assert payload["sub"] == "user1"
        assert payload["type"] == "access"


class TestMissingSecret:
    def test_does_not_crash_on_missing_env(self):
        with patch.dict(os.environ, {}, clear=True):
            import importlib
            import api.middleware.auth
            importlib.reload(api.middleware.auth)
            secret = api.middleware.auth.JWT_SECRET
            assert secret is not None
            assert secret == "dev-secret-change-in-production"


class TestTokenRevocation:
    def test_revoked_token_is_rejected(self):
        token = create_access_token({"sub": "user1"})
        payload = decode_token(token)
        jti = payload["jti"]
        revoke_token(jti)
        assert is_token_revoked(jti) is True
        with pytest.raises(HTTPException) as exc:
            decode_token(token)
        assert exc.value.detail == "Token has been revoked"

    def test_unrevoked_token_still_valid(self):
        token = create_access_token({"sub": "user1"})
        payload = decode_token(token)
        assert payload["sub"] == "user1"

    def test_revocation_does_not_affect_other_tokens(self):
        t1 = create_access_token({"sub": "a"})
        t2 = create_access_token({"sub": "b"})
        p1 = decode_token(t1)
        p2 = decode_token(t2)
        revoke_token(p1["jti"])
        with pytest.raises(HTTPException):
            decode_token(t1)
        decode_token(t2)


class TestExpiredToken:
    def test_expired_token_is_rejected(self):
        payload = {
            "sub": "user1",
            "exp": datetime.utcnow() - timedelta(hours=1),
            "iat": datetime.utcnow() - timedelta(hours=2),
            "type": "access",
            "jti": uuid.uuid4().hex,
        }
        expired = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
        with pytest.raises(HTTPException) as exc:
            decode_token(expired)
        assert exc.value.detail == "Token has expired"


class TestRefreshToken:
    def test_refresh_token_has_correct_type(self):
        token = create_refresh_token({"sub": "user1"})
        payload = decode_token(token)
        assert payload["type"] == "refresh"

    def test_access_token_type_is_access(self):
        token = create_access_token({"sub": "user1"})
        payload = decode_token(token)
        assert payload["type"] == "access"


class TestJtiPresent:
    def test_access_token_has_jti(self):
        token = create_access_token({"sub": "user1"})
        payload = decode_token(token)
        assert "jti" in payload

    def test_refresh_token_has_jti(self):
        token = create_refresh_token({"sub": "user1"})
        payload = decode_token(token)
        assert "jti" in payload


class TestRevokedTokensSet:
    def test_revoked_tokens_is_set(self):
        assert isinstance(_revoked_tokens, set)


class TestGenerateLoginTokens:
    def test_structure(self):
        result = generate_login_tokens("user1", "0x123", ["admin"])
        assert "token" in result
        assert "refresh_token" in result
        assert result["expires_in"] == ACCESS_TOKEN_EXPIRE_MINUTES * 60
        payload = decode_token(result["token"])
        assert payload["sub"] == "user1"
        assert payload["address"] == "0x123"
        assert payload["roles"] == ["admin"]


class TestInvalidSignature:
    def test_wrong_secret_rejected(self):
        token = jwt.encode(
            {"sub": "test", "exp": datetime.utcnow() + timedelta(hours=1)},
            "wrong-secret",
            algorithm="HS256",
        )
        with pytest.raises(HTTPException) as exc:
            decode_token(token)
        assert exc.value.status_code == 401


class TestMissingSub:
    def test_token_without_sub_rejected_by_current_user(self):
        token = create_access_token({"address": "0x123"})
        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
        with pytest.raises(HTTPException) as exc:
            import asyncio
            asyncio.run(get_current_user(creds))
        assert exc.value.status_code == 401


class TestPendingRevocation:
    def test_token_revoked_then_refresh_fails(self):
        tok = create_refresh_token({"sub": "user1", "address": "0xabc"})
        payload = decode_token(tok)
        revoke_token(payload["jti"])
        with pytest.raises(HTTPException) as exc:
            decode_token(tok)
        assert exc.value.detail == "Token has been revoked"


class TestAlgHeaderTampering:
    def test_mismatched_alg_header_rejected(self):
        token = create_access_token({"sub": "user1"})
        header = jwt.get_unverified_header(token)
        assert header["alg"] == "HS256"

        parts = token.split(".")
        import base64, json
        tampered_header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        tampered = tampered_header + "." + parts[1] + "."
        with pytest.raises(HTTPException) as exc:
            decode_token(tampered)
        assert exc.value.status_code == 401
