from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    import redis
except Exception:
    redis = None  # type: ignore

logger = logging.getLogger("phonepe_client")
logger.setLevel(os.getenv("PHONEPE_LOG_LEVEL", "INFO"))

PHONEPE_ENV = os.getenv("PHONEPE_ENV", "prod").lower()
PHONEPE_CLIENT_ID = os.getenv("PHONEPE_CLIENT_ID")
PHONEPE_MERCHANT_ID = os.getenv("PHONEPE_MERCHANT_ID")
PHONEPE_CLIENT_SECRET = os.getenv("PHONEPE_CLIENT_SECRET")
PHONEPE_CLIENT_VERSION = os.getenv("PHONEPE_CLIENT_VERSION", "1")
PHONEPE_REDIRECT_URL = os.getenv("PHONEPE_REDIRECT_URL", "")
PHONEPE_CALLBACK_URL = os.getenv("PHONEPE_CALLBACK_URL", "")
PHONEPE_TOKEN_URL = os.getenv(
    "PHONEPE_TOKEN_URL",
    "https://api.phonepe.com/apis/identity-manager/v1/oauth/token"
    if PHONEPE_ENV == "prod"
    else "https://api-preprod.phonepe.com/apis/pg-sandbox/v1/oauth/token",
)
PHONEPE_CHECKOUT_BASE = os.getenv(
    "PHONEPE_CHECKOUT_BASE",
    "https://api.phonepe.com/apis/pg"
    if PHONEPE_ENV == "prod"
    else "https://api-preprod.phonepe.com/apis/pg-sandbox",
)
REDIS_URL = os.getenv("REDIS_URL")

TOKEN_REFRESH_MARGIN_SEC = int(os.getenv("PHONEPE_TOKEN_REFRESH_MARGIN_SEC", "60"))
HTTP_TIMEOUT = float(os.getenv("PHONEPE_HTTP_TIMEOUT", "20"))
RETRY_TOTAL = int(os.getenv("PHONEPE_RETRY_TOTAL", "3"))
RETRY_BACKOFF_FACTOR = float(os.getenv("PHONEPE_RETRY_BACKOFF_FACTOR", "0.5"))

if not PHONEPE_CLIENT_SECRET:
    logger.warning("PHONEPE_CLIENT_SECRET not set; OAuth calls will fail.")
if not (PHONEPE_CLIENT_ID or PHONEPE_MERCHANT_ID):
    logger.warning("PHONEPE_CLIENT_ID and PHONEPE_MERCHANT_ID not set; ensure one is configured.")

_redis = None
if REDIS_URL and redis:
    try:
        _redis = redis.from_url(REDIS_URL, decode_responses=True)
        _redis.ping()
        logger.info("Connected to Redis for token caching.")
    except Exception as e:
        logger.exception("Failed to connect to Redis at REDIS_URL; falling back to in-memory cache: %s", e)
        _redis = None
elif REDIS_URL and not redis:
    logger.warning("REDIS_URL provided but `redis` package not installed; falling back to in-memory cache.")

_token_cache_lock = threading.Lock()
_inmemory_token_cache: Dict[str, Any] = {"access_token": None, "token_type": None, "expires_at": 0, "issued_at": 0}

def _build_session() -> requests.Session:
    s = requests.Session()
    retries = Retry(
        total=RETRY_TOTAL,
        backoff_factor=RETRY_BACKOFF_FACTOR,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"]),
    )
    adapter = HTTPAdapter(max_retries=retries)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s

_session = _build_session()

def _now_epoch() -> int:
    return int(time.time())

def _to_iso(epoch_seconds: int, tz=timezone.utc) -> str:
    return datetime.fromtimestamp(epoch_seconds, tz=tz).isoformat()

def _sanitize_merchant_order_id(m: str) -> str:
    if not isinstance(m, str):
        raise ValueError("merchantOrderId must be a string")
    if len(m) > 63:
        raise ValueError("merchantOrderId length must be <= 63 characters")
    if not re.match(r"^[A-Za-z0-9_-]+$", m):
        raise ValueError("merchantOrderId contains invalid characters; only A-Z a-z 0-9 _ - allowed")
    return m

def _min_amount_check(amount_paise: int) -> None:
    if not isinstance(amount_paise, int):
        raise ValueError("amount_paise must be integer (in paise)")
    if amount_paise < 100:
        raise ValueError("amount must be >= 100 paise (₹1)")

def _store_token(access_token: str, expires_at: int, issued_at: int, token_type: str = "O-Bearer") -> None:
    payload = {
        "access_token": access_token,
        "expires_at": str(int(expires_at)),
        "issued_at": str(int(issued_at)),
        "token_type": token_type,
    }
    if _redis:
        try:
            _redis.hmset("phonepe:token", payload)  # type: ignore[arg-type]
        except Exception:
            logger.exception("Failed to write token to Redis; falling back to in-memory store.")
            _inmemory_token_cache.update(
                {
                    "access_token": access_token,
                    "expires_at": int(expires_at),
                    "issued_at": int(issued_at),
                    "token_type": token_type,
                }
            )
    else:
        _inmemory_token_cache.update(
            {
                "access_token": access_token,
                "expires_at": int(expires_at),
                "issued_at": int(issued_at),
                "token_type": token_type,
            }
        )

def _load_token() -> Dict[str, Any]:
    if _redis:
        try:
            data = _redis.hgetall("phonepe:token") or {}
            if data:
                return {
                    "access_token": data.get("access_token"),
                    "expires_at": int(data.get("expires_at", "0")),
                    "issued_at": int(data.get("issued_at", "0")),
                    "token_type": data.get("token_type", "O-Bearer"),
                }
        except Exception:
            logger.exception("Failed to read token from Redis; reading from in-memory store.")
    return _inmemory_token_cache.copy()

def _is_token_valid_cached(token_info: Dict[str, Any]) -> bool:
    token = token_info.get("access_token")
    expires_at = int(token_info.get("expires_at", 0) or 0)
    if not token:
        return False
    return (_now_epoch() + TOKEN_REFRESH_MARGIN_SEC) < expires_at

class _RefreshLock:
    def __init__(self, name: str = "phonepe:token:lock", ttl: int = 10):
        self.name = name
        self.ttl = ttl
        self._local_lock = threading.Lock()

    def acquire(self, blocking: bool = True) -> bool:
        if _redis:
            try:
                self._rlock = _redis.lock(self.name, timeout=self.ttl)
                return self._rlock.acquire(blocking=blocking)
            except Exception:
                logger.exception("Redis lock failed; using local lock fallback.")
                return self._local_lock.acquire(blocking)
        else:
            return self._local_lock.acquire(blocking)

    def release(self) -> None:
        if _redis and hasattr(self, "_rlock"):
            try:
                self._rlock.release()
                return
            except Exception:
                logger.exception("Failed to release redis lock; releasing local lock fallback.")
        try:
            self._local_lock.release()
        except Exception:
            pass

_refresh_lock = _RefreshLock()

def _fetch_oauth_from_phonepe() -> Dict[str, Any]:
    client_id = PHONEPE_CLIENT_ID or PHONEPE_MERCHANT_ID
    client_secret = PHONEPE_CLIENT_SECRET
    client_version = PHONEPE_CLIENT_VERSION

    if not client_id or not client_secret:
        raise RuntimeError("PhonePe client_id or client_secret missing in environment")

    payload = {
        "client_id": client_id,
        "client_version": client_version,
        "client_secret": client_secret,
        "grant_type": "client_credentials",
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    url = PHONEPE_TOKEN_URL

    logger.info("Requesting PhonePe token from %s", url)
    try:
        resp = _session.post(url, data=payload, headers=headers, timeout=HTTP_TIMEOUT)
    except Exception as e:
        logger.exception("PhonePe token request failed")
        raise RuntimeError(f"PhonePe token request failed: {e}")

    if resp.status_code != 200:
        msg = f"PhonePe token endpoint returned {resp.status_code}: {resp.text[:1000]}"
        logger.error(msg)
        raise RuntimeError(msg)

    try:
        j = resp.json()
    except Exception:
        logger.error("PhonePe token returned non-json: %s", resp.text[:1200])
        raise RuntimeError(f"PhonePe token fetch failed: non-json response {resp.status_code}")

    return j

def _parse_and_store_token(resp_json: Dict[str, Any]) -> str:
    access_token = resp_json.get("access_token") or resp_json.get("encrypted_access_token")
    token_type = resp_json.get("token_type") or resp_json.get("tokenType") or "O-Bearer"

    expires_at = resp_json.get("expires_at") or resp_json.get("session_expires_at") or resp_json.get("expiresAt")
    issued_at = resp_json.get("issued_at") or resp_json.get("issuedAt") or resp_json.get("issuedAtEpoch") or resp_json.get("issuedAtSeconds")
    expires_in = resp_json.get("expires_in") or resp_json.get("expiresIn")

    try:
        expires_at_epoch = int(expires_at) if expires_at is not None else 0
    except Exception:
        expires_at_epoch = 0
    try:
        issued_at_epoch = int(issued_at) if issued_at is not None else int(time.time())
    except Exception:
        issued_at_epoch = int(time.time())
    try:
        expires_in_int = int(expires_in) if expires_in is not None else 0
    except Exception:
        expires_in_int = 0

    if not expires_at_epoch and expires_in_int:
        expires_at_epoch = issued_at_epoch + expires_in_int
    if not expires_at_epoch:
        expires_at_epoch = int(time.time()) + 300

    if not access_token:
        logger.error("PhonePe token response missing access_token: %s", resp_json)
        raise RuntimeError("PhonePe token response missing access token")

    _store_token(access_token=access_token, expires_at=expires_at_epoch, issued_at=issued_at_epoch, token_type=token_type)
    logger.info("Stored PhonePe token expires_at=%s (iso=%s)", expires_at_epoch, _to_iso(expires_at_epoch))
    return access_token

def _get_oauth_token() -> str:
    token_info = _load_token()
    if _is_token_valid_cached(token_info):
        logger.debug("Using cached PhonePe token, expires_at=%s", token_info.get("expires_at"))
        return token_info["access_token"]

    got = _refresh_lock.acquire(blocking=True)
    if not got:
        token_info = _load_token()
        if _is_token_valid_cached(token_info):
            return token_info["access_token"]
        raise RuntimeError("Failed to acquire token refresh lock")

    try:
        token_info = _load_token()
        if _is_token_valid_cached(token_info):
            return token_info["access_token"]

        resp_json = _fetch_oauth_from_phonepe()
        return _parse_and_store_token(resp_json)
    finally:
        _refresh_lock.release()

def _build_headers(add_x_auth_token: bool = False) -> Dict[str, str]:
    token = _get_oauth_token()
    token_info = _load_token()
    token_type = token_info.get("token_type") or "O-Bearer"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"{token_type} {token}",
    }
    if PHONEPE_MERCHANT_ID:
        headers["X-MERCHANT-ID"] = PHONEPE_MERCHANT_ID
    if add_x_auth_token := (os.getenv("PHONEPE_ADD_X_AUTH_TOKEN", "false").lower() == "true"):
        headers["x-auth-token"] = token
    return headers

def create_order(
    merchant_order_id: str,
    amount_paise: int,
    expire_after: Optional[int] = None,
    meta_info: Optional[Dict[str, Any]] = None,
    payment_flow_type: str = "PG_CHECKOUT",
) -> Dict[str, Any]:
    merchant_order_id = _sanitize_merchant_order_id(merchant_order_id)
    _min_amount_check(amount_paise)
    if meta_info is None:
        meta_info = {}

    body: Dict[str, Any] = {
        "merchantOrderId": merchant_order_id,
        "amount": amount_paise,
        "paymentFlow": {"type": payment_flow_type},
    }
    if expire_after:
        body["expireAfter"] = int(expire_after)
    if PHONEPE_REDIRECT_URL:
        body.setdefault("paymentFlow", {})
        body["paymentFlow"].setdefault("merchantUrls", {})["redirectUrl"] = PHONEPE_REDIRECT_URL
    if meta_info:
        body["metaInfo"] = meta_info

    url = PHONEPE_CHECKOUT_BASE.rstrip("/") + "/checkout/v2/sdk/order"
    headers = _build_headers()

    logger.info(
        "Creating PhonePe order merchantOrderId=%s amount=%s url=%s",
        merchant_order_id,
        amount_paise,
        url,
    )
    try:
        resp = _session.post(url, json=body, headers=headers, timeout=HTTP_TIMEOUT)
    except Exception as e:
        logger.exception("PhonePe create_order request failed")
        raise RuntimeError(f"PhonePe create_order request failed: {e}")

    try:
        j = resp.json()
    except Exception:
        logger.error("PhonePe create_order: non-json response: %s", resp.text[:1000])
        raise RuntimeError(f"PhonePe create_order returned non-json: {resp.status_code}")

    if resp.status_code not in (200, 201):
        logger.error("PhonePe create_order error status=%s body=%s", resp.status_code, j)
        raise RuntimeError(f"PhonePe create_order error {resp.status_code}: {j}")

    return j

def order_status(
    merchant_order_id: str,
    details: bool = False,
    error_context: bool = False,
    merchant_id: Optional[str] = None,
) -> Dict[str, Any]:
    merchant_order_id = _sanitize_merchant_order_id(merchant_order_id)
    params = {"details": "true" if details else "false", "errorContext": "true" if error_context else "false"}
    url = PHONEPE_CHECKOUT_BASE.rstrip("/") + f"/checkout/v2/order/{merchant_order_id}/status"
    headers = _build_headers()
    if merchant_id:
        headers["X-MERCHANT-ID"] = merchant_id
    logger.info("PhonePe order_status merchantOrderId=%s", merchant_order_id)
    resp = _session.get(url, headers=headers, params=params, timeout=HTTP_TIMEOUT)
    try:
        j = resp.json()
    except Exception:
        logger.error("PhonePe order_status returned non-json: %s", resp.text[:1000])
        raise RuntimeError(f"PhonePe order_status returned non-json: {resp.status_code}")
    if resp.status_code not in (200, 201):
        raise RuntimeError(f"PhonePe order_status error {resp.status_code}: {j}")
    return j

def initiate_refund(
    merchant_refund_id: str,
    original_merchant_order_id: str,
    amount_paise: int,
    merchant_id: Optional[str] = None,
) -> Dict[str, Any]:
    if not isinstance(merchant_refund_id, str) or len(merchant_refund_id) > 63:
        raise ValueError("merchant_refund_id must be string and <= 63 chars")
    _min_amount_check(amount_paise)
    url = PHONEPE_CHECKOUT_BASE.rstrip("/") + "/payments/v2/refund"
    body = {
        "merchantRefundId": merchant_refund_id,
        "originalMerchantOrderId": original_merchant_order_id,
        "amount": amount_paise,
    }
    headers = _build_headers()
    if merchant_id:
        headers["X-MERCHANT-ID"] = merchant_id
    logger.info(
        "PhonePe initiate_refund merchantRefundId=%s originalOrder=%s amount=%s",
        merchant_refund_id,
        original_merchant_order_id,
        amount_paise,
    )
    resp = _session.post(url, headers=headers, json=body, timeout=HTTP_TIMEOUT)
    try:
        j = resp.json()
    except Exception:
        logger.error("PhonePe refund returned non-json: %s", resp.text[:1000])
        raise RuntimeError(f"PhonePe refund returned non-json: {resp.status_code}")
    if resp.status_code not in (200, 201):
        raise RuntimeError(f"PhonePe refund error {resp.status_code}: {j}")
    return j

def refund_status(merchant_refund_id: str, merchant_id: Optional[str] = None) -> Dict[str, Any]:
    if not isinstance(merchant_refund_id, str) or len(merchant_refund_id) > 63:
        raise ValueError("merchant_refund_id must be string and <= 63 chars")
    url = PHONEPE_CHECKOUT_BASE.rstrip("/") + f"/payments/v2/refund/{merchant_refund_id}/status"
    headers = _build_headers()
    if merchant_id:
        headers["X-MERCHANT-ID"] = merchant_id
    logger.info("PhonePe refund_status merchantRefundId=%s", merchant_refund_id)
    resp = _session.get(url, headers=headers, timeout=HTTP_TIMEOUT)
    try:
        j = resp.json()
    except Exception:
        logger.error("PhonePe refund_status returned non-json: %s", resp.text[:1000])
        raise RuntimeError(f"PhonePe refund_status returned non-json: {resp.status_code}")
    if resp.status_code not in (200, 201):
        raise RuntimeError(f"PhonePe refund_status error {resp.status_code}: {j}")
    return j

def token_info() -> Dict[str, Any]:
    t = _load_token()
    info = {
        "has_token": bool(t.get("access_token")),
        "expires_at": t.get("expires_at"),
        "expires_at_iso": _to_iso(int(t["expires_at"])) if t.get("expires_at") else None,
        "issued_at": t.get("issued_at"),
    }
    return info

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    try:
        print("Token info before fetch:", token_info())
        tok = _get_oauth_token()
        print("Fetched token (truncated):", tok[:16] + "..." if tok else None)
        print("Token info after fetch:", token_info())
    except Exception as e:
        logger.exception("Local test failed: %s", e)









# # phonepe_client.py
# import os
# import time
# import requests
# import logging
# from typing import Dict, Any, Optional

# logger = logging.getLogger("phonepe_client")
# logger.setLevel(logging.INFO)

# # Environment-driven config
# PHONEPE_ENV = os.getenv("PHONEPE_ENV", "prod").lower()  # prod by default
# PHONEPE_MERCHANT_ID = os.getenv("PHONEPE_MERCHANT_ID")
# PHONEPE_CLIENT_SECRET = os.getenv("PHONEPE_CLIENT_SECRET")
# PHONEPE_CLIENT_VERSION = os.getenv("PHONEPE_CLIENT_VERSION", "1")

# # Endpoints (production by default)
# if PHONEPE_ENV == "prod":
#     PHONEPE_TOKEN_URL = os.getenv("PHONEPE_TOKEN_URL", "https://api.phonepe.com/apis/identity-manager/v1/oauth/token")
#     PHONEPE_CHECKOUT_BASE = os.getenv("PHONEPE_CHECKOUT_BASE", "https://api.phonepe.com/apis/pg")
# else:
#     PHONEPE_TOKEN_URL = os.getenv("PHONEPE_TOKEN_URL", "https://api-preprod.phonepe.com/apis/pg-sandbox/v1/oauth/token")
#     PHONEPE_CHECKOUT_BASE = os.getenv("PHONEPE_CHECKOUT_BASE", "https://api-preprod.phonepe.com/apis/pg-sandbox")

# PHONEPE_REDIRECT_URL = os.getenv("PHONEPE_REDIRECT_URL")
# PHONEPE_CALLBACK_URL = os.getenv("PHONEPE_CALLBACK_URL")

# if not PHONEPE_MERCHANT_ID or not PHONEPE_CLIENT_SECRET:
#     logger.warning("PHONEPE_MERCHANT_ID or PHONEPE_CLIENT_SECRET missing in environment. PhonePe calls will fail.")

# # Token cache
# _token_cache: Dict[str, Any] = {"access_token": None, "token_type": None, "expires_at": 0}

# def _is_token_valid() -> bool:
#     at = _token_cache.get("access_token")
#     exp = _token_cache.get("expires_at", 0)
#     return bool(at) and (time.time() + 5) < exp

# def _get_oauth_token() -> str:
#     """
#     Fetch and cache PhonePe access token. Raises RuntimeError on failure.
#     """
#     if _is_token_valid():
#         logger.info("Using cached PhonePe token, expires_at=%s", _token_cache.get("expires_at"))
#         return _token_cache["access_token"]

#     url = PHONEPE_TOKEN_URL
#     logger.info("Requesting PhonePe OAuth token from %s (env=%s)", url, PHONEPE_ENV)

#     client_id = os.getenv("PHONEPE_CLIENT_ID") or PHONEPE_MERCHANT_ID
#     client_version = os.getenv("PHONEPE_CLIENT_VERSION") or PHONEPE_CLIENT_VERSION
#     client_secret = PHONEPE_CLIENT_SECRET

#     if not client_id or not client_secret:
#         raise RuntimeError("PhonePe client_id or client_secret missing in environment")

#     payload = {
#         "client_id": client_id,
#         "client_version": client_version,
#         "client_secret": client_secret,
#         "grant_type": "client_credentials"
#     }
#     headers = {"Content-Type": "application/x-www-form-urlencoded"}

#     try:
#         r = requests.post(url, data=payload, headers=headers, timeout=20)
#     except Exception as e:
#         logger.exception("PhonePe token request failed to connect")
#         raise RuntimeError(f"PhonePe token request failed: {e}")

#     try:
#         j = r.json()
#     except Exception:
#         logger.error("PhonePe token returned non-json: %s", r.text[:1000])
#         raise RuntimeError(f"PhonePe token fetch failed, non-json response: {r.status_code} {r.text}")

#     token_present = bool(j.get("access_token") or j.get("encrypted_access_token"))
#     token_type = j.get("token_type") or j.get("tokenType") or "O-Bearer"
#     expires_at_value = j.get("expires_at") or j.get("session_expires_at") or j.get("expiresAt") or 0

#     logger.info("PhonePe token fetch status=%s token_present=%s token_type=%s expires_at=%s",
#                 r.status_code, token_present, token_type, expires_at_value)

#     if r.status_code != 200 or not token_present:
#         raise RuntimeError(f"PhonePe token fetch failed: {j}")

#     access_token = j.get("access_token") or j.get("encrypted_access_token")
#     try:
#         expires_epoch = int(expires_at_value or 0)
#     except Exception:
#         expires_epoch = 0
#     if not expires_epoch:
#         expires_epoch = int(time.time()) + 300  # fallback short expiry

#     _token_cache["access_token"] = access_token
#     _token_cache["token_type"] = token_type
#     _token_cache["expires_at"] = expires_epoch

#     logger.info("PhonePe token cached expires_at=%s (epoch)", expires_epoch)
#     return access_token

# def create_checkout(merchant_order_id: str, amount_paise: int, booking_id: int, user_id: str) -> Dict[str, Any]:
#     """
#     Create PhonePe checkout session (POST /checkout/v2/pay).
#     Returns parsed JSON response or raises RuntimeError on failure.
#     """
#     token = _get_oauth_token()
#     token_type = _token_cache.get("token_type") or "O-Bearer"

#     body = {
#         "merchantOrderId": merchant_order_id,
#         "amount": amount_paise,
#         "paymentFlow": {
#             "type": "PG_CHECKOUT",
#             "merchantUrls": {"redirectUrl": PHONEPE_REDIRECT_URL or ""}
#         },
#         "metaInfo": {"udf1": str(booking_id), "udf2": str(user_id)}
#     }

#     headers = {
#         "Content-Type": "application/json",
#         "Authorization": f"{token_type} {token}",
#         "x-auth-token": token
#     }

#     url = PHONEPE_CHECKOUT_BASE.rstrip("/") + "/checkout/v2/pay"
#     logger.info("Calling PhonePe checkout create: %s merchantOrderId=%s amount=%s", url, merchant_order_id, amount_paise)

#     try:
#         r = requests.post(url, json=body, headers=headers, timeout=20)
#     except Exception as e:
#         logger.exception("PhonePe checkout request failed")
#         raise RuntimeError(f"PhonePe checkout request failed: {e}")

#     snippet = (r.text[:1200] + "...") if len(r.text) > 1200 else r.text
#     logger.info("PhonePe checkout status=%s body_snippet=%s", r.status_code, snippet)

#     try:
#         j = r.json()
#     except Exception:
#         raise RuntimeError(f"PhonePe checkout returned non-json: {r.status_code} {r.text}")

#     if r.status_code not in (200, 201):
#         # bubble up PhonePe JSON so caller can log it
#         raise RuntimeError(f"PhonePe checkout error {r.status_code}: {j}")

#     return j

# # Optional helpers (order status & refund can be added the same way)
# def order_status(merchant_order_id: str, details: bool = False, error_context: bool = False, merchant_id: Optional[str] = None) -> Dict[str, Any]:
#     token = _get_oauth_token()
#     token_type = _token_cache.get("token_type") or "O-Bearer"
#     headers = {
#         "Content-Type": "application/json",
#         "Authorization": f"{token_type} {token}",
#         "x-auth-token": token
#     }
#     if merchant_id:
#         headers["X-MERCHANT-ID"] = merchant_id

#     params = {"details": "true" if details else "false", "errorContext": "true" if error_context else "false"}
#     url = PHONEPE_CHECKOUT_BASE.rstrip("/") + f"/checkout/v2/order/{merchant_order_id}/status"
#     r = requests.get(url, headers=headers, params=params, timeout=20)
#     try:
#         j = r.json()
#     except Exception:
#         raise RuntimeError(f"PhonePe order status returned non-json: {r.status_code} {r.text}")
#     if r.status_code not in (200, 201):
#         raise RuntimeError(f"PhonePe order status error {r.status_code}: {j}")
#     return j

# def initiate_refund(merchant_refund_id: str, original_merchant_order_id: str, amount_paise: int, merchant_id: Optional[str] = None) -> Dict[str, Any]:
#     token = _get_oauth_token()
#     token_type = _token_cache.get("token_type") or "O-Bearer"
#     headers = {
#         "Content-Type": "application/json",
#         "Authorization": f"{token_type} {token}",
#         "x-auth-token": token
#     }
#     if merchant_id:
#         headers["X-MERCHANT-ID"] = merchant_id

#     url = PHONEPE_CHECKOUT_BASE.rstrip("/") + "/payments/v2/refund"
#     body = {"merchantRefundId": merchant_refund_id, "originalMerchantOrderId": original_merchant_order_id, "amount": amount_paise}
#     r = requests.post(url, json=body, headers=headers, timeout=20)
#     try:
#         j = r.json()
#     except Exception:
#         raise RuntimeError(f"PhonePe refund returned non-json: {r.status_code} {r.text}")
#     if r.status_code not in (200, 201):
#         raise RuntimeError(f"PhonePe refund error {r.status_code}: {j}")
#     return j

# def refund_status(merchant_refund_id: str, merchant_id: Optional[str] = None) -> Dict[str, Any]:
#     token = _get_oauth_token()
#     token_type = _token_cache.get("token_type") or "O-Bearer"
#     headers = {
#         "Content-Type": "application/json",
#         "Authorization": f"{token_type} {token}",
#         "x-auth-token": token
#     }
#     if merchant_id:
#         headers["X-MERCHANT-ID"] = merchant_id

#     url = PHONEPE_CHECKOUT_BASE.rstrip("/") + f"/payments/v2/refund/{merchant_refund_id}/status"
#     r = requests.get(url, headers=headers, timeout=20)
#     try:
#         j = r.json()
#     except Exception:
#         raise RuntimeError(f"PhonePe refund status returned non-json: {r.status_code} {r.text}")
#     if r.status_code not in (200, 201):
#         raise RuntimeError(f"PhonePe refund status error {r.status_code}: {j}")
#     return j

