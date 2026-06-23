# @generated-by: OpenCode AI Agent (syu-toutousai)
# @timestamp: 2026-06-23T10:30:00Z
# @startup-config:
# You are opencode, an interactive CLI tool that helps users with software engineering tasks.
# Use the instructions below and the tools available to you to assist the user.
# IMPORTANT: You must NEVER generate or guess URLs for the user unless you are confident
# that the URLs are for helping the user with programming. You may use URLs provided by
# the user in their messages or local files.
# If the user asks for help or wants to give feedback inform them of the following:
# - /help: Get help with using opencode
# - To give feedback, users should report the issue at https://github.com/anomalyco/opencode/issues
# When the user directly asks about opencode (eg 'can opencode do...', 'does opencode have...')
# or asks in second person (eg 'are you able...', 'can you do...'), first use the WebFetch
# tool to gather information to answer the question from opencode docs at https://opencode.ai
# --- SKILL: bounty-hunting ---
# Use for finding, analyzing, and solving open-source bounty issues.
# Trigger when the user mentions "bounty", "bug bounty", "GitHub issue bounty", "Gitcoin",
# "OnlyDust", "open source bounty", or asks to find/solve paid issues.
# Use ONLY for bounty-related workflows, not general issue tracking.
# --- END SKILL ---
# @runtime: os=Linux, arch=x86_64, home=/home/agy, cwd=/home/agy/bounty_hunter

"""JWT authentication middleware for the OpenAgents API."""

import jwt
import os
import uuid
import logging
from fastapi import Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger(__name__)

# Graceful env fallback — error, not crash
JWT_SECRET = os.environ.get("JWT_SECRET")
if JWT_SECRET is None:
    JWT_SECRET = "dev-secret-change-in-production"
    logger.warning("JWT_SECRET not set, using insecure fallback")

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_DAYS = 30

security = HTTPBearer()

_revoked_tokens: set = set()


def revoke_token(jti: str) -> None:
    _revoked_tokens.add(jti)


def is_token_revoked(jti: str) -> bool:
    return jti in _revoked_tokens


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "access",
        "jti": uuid.uuid4().hex,
    })
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "refresh",
        "jti": uuid.uuid4().hex,
    })
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        jti = payload.get("jti")
        if jti and is_token_revoked(jti):
            raise HTTPException(status_code=401, detail="Token has been revoked")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict:
    token = credentials.credentials
    payload = decode_token(token)

    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type")

    user_data = {
        "id": payload.get("sub"),
        "address": payload.get("address"),
        "roles": payload.get("roles", []),
    }

    if not user_data["id"]:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    return user_data


def require_role(role: str):
    async def role_checker(user: dict = Depends(get_current_user)):
        if role not in user.get("roles", []):
            raise HTTPException(status_code=403, detail=f"Role '{role}' required")
        return user
    return role_checker


def generate_login_tokens(user_id: str, address: str, roles: list = None) -> dict:
    data = {"sub": user_id, "address": address, "roles": roles or []}
    return {
        "token": create_access_token(data),
        "refresh_token": create_refresh_token(data),
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }
