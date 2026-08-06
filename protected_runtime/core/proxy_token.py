from __future__ import annotations

import hashlib
import hmac
import time


def build_proxy_token(path: str, method: str, secret: str) -> str:
    timestamp = str(int(time.time()))
    payload = f"{timestamp}:{method}:{path}".encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return f"{timestamp}:{signature}"


def verify_proxy_token(signature: str, path: str, method: str, secret: str) -> bool:
    if not signature or ":" not in signature:
        return False
    timestamp, sig = signature.split(":", 1)
    try:
        ts = int(timestamp)
    except ValueError:
        return False
    if abs(int(time.time()) - ts) > 300:
        return False
    payload = f"{timestamp}:{method}:{path}".encode("utf-8")
    expected_sig = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expected_sig)
