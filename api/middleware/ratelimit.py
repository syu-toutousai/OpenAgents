# @agent: OpenCode AI Agent (syu-toutousai)
# @startup-config: You are opencode, an interactive CLI tool that helps users with software engineering tasks. Use the instructions below and the tools available to you to assist the user. IMPORTANT: You must NEVER generate or guess URLs for the user unless you are confident that the URLs are for helping the user with programming. You may use URLs provided by the user in their messages or local files. When the user directly asks about opencode (eg 'can opencode do...', 'does opencode have...') or asks in second person (eg 'are you able...', 'can you do...'), first use the WebFetch tool to gather information to answer the question from opencode docs at https://opencode.ai
# @runtime: os=Linux, arch=x86_64, home=/home/agy, cwd=/home/agy/bounty_hunter, python=3.13

"""Rate limiting middleware for the OpenAgents API with auth-aware tiers."""

import time
import os
import logging
from collections import defaultdict
from typing import Dict, Tuple, Optional

import jwt
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)

JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret-change-in-production")

TIER_LIMITS: Dict[str, int] = {
    "anonymous": 60,
    "authenticated": 300,
    "premium": 1000,
}

WINDOW_SECONDS = 60


_request_counts: Dict[str, Tuple[int, float]] = defaultdict(lambda: (0, time.time()))
_tier_cache: Dict[str, str] = {}


def _resolve_tier(request: Request) -> str:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            roles = payload.get("roles", [])
            if "premium" in roles:
                return "premium"
            return "authenticated"
        except Exception:
            pass

    api_key = request.headers.get("X-API-Key", "")
    if api_key:
        valid_keys = os.environ.get("PREMIUM_API_KEYS", "").split(",")
        if api_key in valid_keys:
            return "premium"

    return "anonymous"


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)

    def _key(self, request: Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            client_ip = forwarded.split(",")[0].strip()
        else:
            client_ip = request.client.host if request.client else "unknown"
        tier = _resolve_tier(request)
        return f"{tier}:{client_ip}"

    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith("/health"):
            return await call_next(request)

        rk = self._key(request)
        tier = rk.split(":")[0]
        limit = TIER_LIMITS.get(tier, 60)

        count, window_start = _request_counts[rk]
        now = time.time()

        if now - window_start >= WINDOW_SECONDS:
            _request_counts[rk] = (1, now)
            remaining = limit - 1
        elif count >= limit:
            retry_after = int(WINDOW_SECONDS - (now - window_start))
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate limit exceeded",
                    "tier": tier,
                    "retry_after": retry_after,
                },
                headers={"Retry-After": str(retry_after)},
            )
        else:
            _request_counts[rk] = (count + 1, window_start)
            remaining = limit - count - 1

        reset = int(window_start + WINDOW_SECONDS - now)

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(reset)
        return response
