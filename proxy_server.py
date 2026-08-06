from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import sys
import time
from collections import defaultdict, deque
from pathlib import Path
from threading import Lock
from typing import Any

import httpx
import redis.asyncio as aioredis
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

os.environ.setdefault("WAF_DETECTION_RULES_LAYER_MODE", "active_block")
os.environ.setdefault("WAF_REPUTATION_CHALLENGE_THRESHOLD", "3")
os.environ.setdefault("WAF_REPUTATION_BLOCK_THRESHOLD", "5")

PROTECTED_ROOT = Path(__file__).resolve().parent / "protected_runtime"
if str(PROTECTED_ROOT) not in sys.path:
    sys.path.insert(0, str(PROTECTED_ROOT))

sys.path.insert(0, str(PROTECTED_ROOT))

try:
    import protected_runtime.analysis.signature_matching as analysis_signature_matching
    import protected_runtime.shieldcore_waf as shieldcore_waf_runtime
    import protected_runtime.core.proxy_token as core_proxy_token_runtime
    import protected_runtime.logic_engine as logic_engine_runtime
    import protected_runtime.analysis.signature_matching as protected_signature_matching
    SignatureMatchingLayer = protected_signature_matching.SignatureMatchingLayer
    DetectionRulesLayer = shieldcore_waf_runtime.DetectionRulesLayer
    build_proxy_token = core_proxy_token_runtime.build_proxy_token
    BusinessLogicEngine = logic_engine_runtime.BusinessLogicEngine
except Exception:
    import protected_runtime.analysis_signature_matching as analysis_signature_matching
    import protected_runtime.shieldcore_waf as shieldcore_waf_runtime
    import protected_runtime.core_proxy_token as core_proxy_token_runtime
    import protected_runtime.logic_engine as logic_engine_runtime
    import protected_runtime.signature_matching as protected_signature_matching
    SignatureMatchingLayer = protected_signature_matching.SignatureMatchingLayer
    DetectionRulesLayer = shieldcore_waf_runtime.DetectionRulesLayer
    build_proxy_token = core_proxy_token_runtime.build_proxy_token
    BusinessLogicEngine = logic_engine_runtime.BusinessLogicEngine

# Prefer the protected shim explicitly when the source tree is backed up.
if "analysis.signature_matching" not in sys.modules:
    sys.modules["analysis.signature_matching"] = analysis_signature_matching

app = FastAPI(title="Henzo Proxy Server")

TARGET_URL = os.getenv("TARGET_BACKEND_URL", "http://127.0.0.1:8002").rstrip("/")
REDIS_HOST = os.getenv("REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
SHARED_SECRET = os.getenv("WAF_PROXY_SHARED_SECRET", "change-this-secret")
INPUT_NORMALIZATION_PASSES = 5
EARLY_RATE_LIMIT_RPS = max(1, int(os.getenv("WAF_EARLY_RATE_LIMIT_RPS", "50")))
EARLY_RATE_LIMIT_WINDOW_SECONDS = max(1, int(os.getenv("WAF_EARLY_RATE_LIMIT_WINDOW_SECONDS", "1")))

try:
    signature_layer = SignatureMatchingLayer()
except Exception:
    class _FallbackSignatureLayer:
        def process(self, data: Any) -> Any:
            return {"packets": []}
    signature_layer = _FallbackSignatureLayer()

detection_layer = DetectionRulesLayer()

_RATE_LIMIT_BUCKETS: dict[str, deque[float]] = defaultdict(deque)
_RATE_LIMIT_LOCK = Lock()

# Business logic engine (uses redis when available)
business_engine: BusinessLogicEngine | None = None

redis_client = None
http_client = httpx.AsyncClient(
    timeout=httpx.Timeout(3.0, connect=1.0, read=3.0),
    limits=httpx.Limits(max_connections=1000, max_keepalive_connections=200),
)


@app.on_event("shutdown")
async def shutdown_http_client() -> None:
    await http_client.aclose()


async def get_redis_client():
    global redis_client
    if redis_client is None:
        redis_client = aioredis.from_url(f"redis://{REDIS_HOST}:{REDIS_PORT}/0", decode_responses=True)
    try:
        await redis_client.ping()
    except Exception:
        redis_client = None
    return redis_client


async def get_business_engine():
    global business_engine
    if business_engine is None:
        r = await get_redis_client()
        business_engine = BusinessLogicEngine(redis_client=r)
    return business_engine


def _extract_client_ip(request: Request) -> str:
    if request.client and request.client.host:
        return request.client.host
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.headers.get("x-real-ip", "127.0.0.1")


def _is_early_rate_limited(request: Request) -> bool:
    path = request.url.path
    if path in {"/health", "/docs", "/openapi.json"}:
        return False
    client_ip = _extract_client_ip(request) or "127.0.0.1"
    now = time.monotonic()
    with _RATE_LIMIT_LOCK:
        timestamps = _RATE_LIMIT_BUCKETS[client_ip]
        cutoff = now - EARLY_RATE_LIMIT_WINDOW_SECONDS
        while timestamps and timestamps[0] < cutoff:
            timestamps.popleft()
        timestamps.append(now)
        return len(timestamps) > EARLY_RATE_LIMIT_RPS


def _sanitize_headers_for_detection(request: Request) -> dict[str, str]:
    headers: dict[str, str] = {}
    for header_name, header_value in request.headers.items():
        name = header_name.lower()
        if name in {
            "host",
            "content-length",
            "connection",
            "keep-alive",
            "proxy-authorization",
            "proxy-connection",
            "te",
            "transfer-encoding",
            "via",
            "forwarded",
            "x-forwarded-for",
            "x-real-ip",
            "x-forwarded-proto",
            "x-forwarded-host",
            "x-forwarded-port",
        }:
            continue
        if name.startswith("x-forwarded-") or name.startswith("x-shieldcore-"):
            continue
        headers[header_name] = header_value
    return headers


@app.middleware("http")
async def normalize_and_route(request: Request, call_next):
    if request.url.path in {"/health", "/docs", "/openapi.json"}:
        return await call_next(request)

    if _is_early_rate_limited(request):
        return JSONResponse(status_code=429, content={"detail": "Too Many Requests"})

    # Lightweight normalization pass for the lab scenario.
    normalized_path = request.url.path
    normalized_query = request.url.query
    if request.method in {"POST", "PUT", "PATCH"}:
        try:
            body = await asyncio.wait_for(request.body(), timeout=2.0)
        except asyncio.TimeoutError:
            return JSONResponse(status_code=408, content={"detail": "request_timeout"})
        except Exception:
            body = b""
    else:
        body = b""
    if len(body) > 8192:
        return JSONResponse(status_code=413, content={"detail": "payload_too_large"})

    if len(str(request.url.query).encode("utf-8")) > 8192:
        return JSONResponse(status_code=413, content={"detail": "payload_too_large"})

    suspicious_headers = []
    for header_name, header_value in request.headers.items():
        name = header_name.lower()
        if name.startswith("x-forwarded-") or name.startswith("x-shieldcore-"):
            suspicious_headers.append(header_name)
            continue
        if name in {"proxy-connection", "te", "transfer-encoding", "via", "forwarded", "x-real-ip"}:
            suspicious_headers.append(header_name)
            continue
        if name == "connection":
            tokens = {token.strip().lower() for token in header_value.split(",") if token.strip()}
            if tokens & {"x-forwarded-for", "x-real-ip", "x-forwarded-proto", "x-forwarded-host", "x-forwarded-port", "proxy-authorization", "proxy-connection", "te", "transfer-encoding", "upgrade", "forwarded", "x-shieldcore-signature", "x-shieldcore-timestamp"}:
                suspicious_headers.append(header_name)
    if suspicious_headers:
        return JSONResponse(status_code=403, content={"detail": "header_spoofing_attempt"})

    # Pass through to the detection layer.
    detection_result = detection_layer.process({
        "method": request.method,
        "path": normalized_path,
        "headers": _sanitize_headers_for_detection(request),
        "query": normalized_query,
        "body": body.decode("utf-8", errors="ignore"),
        "client_ip": request.client.host if request.client else "127.0.0.1",
    })
    if detection_result.get("verdict") == "block":
        return JSONResponse(status_code=403, content={"detail": "blocked", "reasons": detection_result.get("reasons", [])})
    if detection_result.get("verdict") == "challenge":
        return JSONResponse(status_code=403, content={"detail": "challenge_required"})

    # Business logic checks: run only for state-changing or payload-bearing requests.
    payload = None
    if request.method in {"POST", "PUT", "PATCH"}:
        try:
            payload = json.loads(body.decode("utf-8", errors="ignore")) if body else None
        except Exception:
            payload = None

    if request.method != "GET" or payload is not None:
        try:
            engine = await get_business_engine()
            session_id = request.cookies.get("session_id") or request.headers.get("x-session-id")
            ok, reason = await engine.check_fsm(session_id, normalized_path)
            if not ok:
                return JSONResponse(status_code=403, content={"detail": "state_boundary_violation", "reason": reason})

            idempotency_key = request.headers.get("Idempotency-Key")
            ok, reason = await engine.check_idempotency(idempotency_key)
            if not ok:
                return JSONResponse(status_code=409, content={"detail": "duplicate_request", "reason": reason})

            if request.method in {"POST", "PUT", "PATCH"}:
                ok, reason = await engine.validate_schema(normalized_path, payload)
                if not ok:
                    return JSONResponse(status_code=400, content={"detail": "schema_violation", "reason": reason})

            params = dict(request.query_params)
            try:
                if payload and isinstance(payload, dict):
                    params.update(payload)
            except Exception:
                pass
            ok, reason = await engine.check_idor(session_id, params)
            if not ok:
                return JSONResponse(status_code=403, content={"detail": "idor_violation", "reason": reason})
        except Exception:
            pass
    headers = {}
    for k, v in request.headers.items():
        name = k.lower()
        if name in {
            "host",
            "content-length",
            "connection",
            "keep-alive",
            "proxy-authorization",
            "proxy-connection",
            "te",
            "transfer-encoding",
            "via",
            "forwarded",
        }:
            continue
        if name.startswith("x-forwarded-") or name.startswith("x-shieldcore-"):
            continue
        headers[k] = v

    signature_timestamp = str(int(time.time()))
    payload = f"{signature_timestamp}:{request.method}:{request.url.path}".encode("utf-8")
    signature = hmac.new(SHARED_SECRET.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    headers["X-ShieldCore-Signature"] = f"{signature_timestamp}:{signature}"
    headers["X-ShieldCore-Timestamp"] = signature_timestamp
    try:
        rclient = await get_redis_client()
        if rclient is not None:
            await rclient.hset(f"shieldcore:reputation:{request.client.host if request.client else 'unknown'}", mapping={"score": "0", "last_seen": str(int(time.time()))})
            await rclient.expire(f"shieldcore:reputation:{request.client.host if request.client else 'unknown'}", 300)
    except Exception:
        pass
    upstream_url = f"{TARGET_URL}{request.url.path}"
    try:
        if request.method == "GET":
            response = await http_client.get(upstream_url, headers=headers, params=request.query_params)
        elif request.method == "POST":
            response = await http_client.post(upstream_url, headers=headers, content=body)
        else:
            response = await http_client.request(request.method, upstream_url, headers=headers, content=body)
    except httpx.ConnectError:
        return JSONResponse(status_code=502, content={"detail": "upstream_unavailable"})
    except httpx.TimeoutException:
        return JSONResponse(status_code=504, content={"detail": "upstream_timeout"})
    except Exception:
        return JSONResponse(status_code=502, content={"detail": "upstream_unavailable"})

    try:
        payload = response.json() if response.content else {}
    except ValueError:
        payload = {"detail": response.text}
    return JSONResponse(content=payload, status_code=response.status_code)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
