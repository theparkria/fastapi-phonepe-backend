import os
import time
import requests
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("phonepe_client")
logger.setLevel(logging.INFO)

# Environment-driven config
PHONEPE_ENV = os.getenv("PHONEPE_ENV", "prod").lower()  # prod by default
PHONEPE_MERCHANT_ID = os.getenv("PHONEPE_MERCHANT_ID")
PHONEPE_CLIENT_SECRET = os.getenv("PHONEPE_CLIENT_SECRET")
PHONEPE_CLIENT_VERSION = os.getenv("PHONEPE_CLIENT_VERSION", "1")

# Endpoints (production by default)
if PHONEPE_ENV == "prod":
    PHONEPE_TOKEN_URL = os.getenv("PHONEPE_TOKEN_URL", "https://api.phonepe.com/apis/identity-manager/v1/oauth/token")
    PHONEPE_CHECKOUT_BASE = os.getenv("PHONEPE_CHECKOUT_BASE", "https://api.phonepe.com/apis/pg")
else:
    PHONEPE_TOKEN_URL = os.getenv("PHONEPE_TOKEN_URL", "https://api-preprod.phonepe.com/apis/pg-sandbox/v1/oauth/token")
    PHONEPE_CHECKOUT_BASE = os.getenv("PHONEPE_CHECKOUT_BASE", "https://api-preprod.phonepe.com/apis/pg-sandbox")

PHONEPE_REDIRECT_URL = os.getenv("PHONEPE_REDIRECT_URL")
PHONEPE_CALLBACK_URL = os.getenv("PHONEPE_CALLBACK_URL")

if not PHONEPE_MERCHANT_ID or not PHONEPE_CLIENT_SECRET:
    logger.warning("PHONEPE_MERCHANT_ID or PHONEPE_CLIENT_SECRET missing in environment. PhonePe calls will fail.")

# Token cache
_token_cache: Dict[str, Any] = {"access_token": None, "token_type": None, "expires_at": 0}


def _is_token_valid() -> bool:
    at = _token_cache.get("access_token")
    exp = _token_cache.get("expires_at", 0)
    # add small safety margin
    return bool(at) and (time.time() + 10) < exp


def _get_oauth_token() -> str:
    """
    Fetch and cache PhonePe access token. Raises RuntimeError on failure.
    """
    if _is_token_valid():
        logger.info("Using cached PhonePe token, expires_at=%s", _token_cache.get("expires_at"))
        return _token_cache["access_token"]

    url = PHONEPE_TOKEN_URL
    logger.info("Requesting PhonePe OAuth token from %s (env=%s)", url, PHONEPE_ENV)

    client_id = os.getenv("PHONEPE_CLIENT_ID") or PHONEPE_MERCHANT_ID
    client_version = os.getenv("PHONEPE_CLIENT_VERSION") or PHONEPE_CLIENT_VERSION
    client_secret = PHONEPE_CLIENT_SECRET

    if not client_id or not client_secret:
        raise RuntimeError("PhonePe client_id or client_secret missing in environment")

    # PhonePe expects form-encoded client credentials for certain endpoints
    payload = {
        "client_id": client_id,
        "client_version": client_version,
        "client_secret": client_secret,
        "grant_type": "client_credentials"
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    try:
        r = requests.post(url, data=payload, headers=headers, timeout=20)
    except Exception as e:
        logger.exception("PhonePe token request failed to connect")
        raise RuntimeError(f"PhonePe token request failed: {e}")

    try:
        j = r.json()
    except Exception:
        logger.error("PhonePe token returned non-json: %s", r.text[:1000])
        raise RuntimeError(f"PhonePe token fetch failed, non-json response: {r.status_code} {r.text}")

    # Normalize token fields across possible shapes
    access_token = j.get("access_token") or j.get("encrypted_access_token")
    token_type = j.get("token_type") or j.get("tokenType") or j.get("token_type") or "O-Bearer"
    # PhonePe may return expires_in or expiresAt; prefer expires_in (seconds)
    expires_in = j.get("expires_in") or j.get("expiresIn")
    expires_at_value = j.get("expires_at") or j.get("session_expires_at") or j.get("expiresAt")

    token_present = bool(access_token)
    logger.info("PhonePe token fetch status=%s token_present=%s token_type=%s expires_in=%s expires_at=%s",
                r.status_code, token_present, token_type, expires_in, expires_at_value)

    if r.status_code != 200 or not token_present:
        raise RuntimeError(f"PhonePe token fetch failed: {j}")

    # Compute expiry epoch
    try:
        if expires_in:
            expires_epoch = int(time.time()) + int(expires_in)
        elif expires_at_value:
            # if value is epoch seconds, use directly; otherwise fallback
            expires_epoch = int(expires_at_value)
        else:
            expires_epoch = int(time.time()) + 300  # fallback 5 minutes
    except Exception:
        expires_epoch = int(time.time()) + 300

    _token_cache["access_token"] = access_token
    _token_cache["token_type"] = token_type
    _token_cache["expires_at"] = expires_epoch

    logger.info("PhonePe token cached expires_at=%s (epoch)", expires_epoch)
    return access_token


def create_checkout(merchant_order_id: str, amount_paise: int, booking_id: int, user_id: str) -> Dict[str, Any]:
    """
    Create PhonePe checkout session (POST /checkout/v2/pay).
    Returns parsed JSON response or raises RuntimeError on failure.
    """
    token = _get_oauth_token()
    token_type = _token_cache.get("token_type") or "O-Bearer"

    body = {
        "merchantOrderId": merchant_order_id,
        "amount": amount_paise,
        "paymentFlow": {
            "type": "PG_CHECKOUT",
            "merchantUrls": {"redirectUrl": PHONEPE_REDIRECT_URL or ""}
        },
        "metaInfo": {"udf1": str(booking_id), "udf2": str(user_id)}
    }

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"{token_type} {token}",
        "x-auth-token": token
    }

    # Add merchant id header if configured (some PhonePe endpoints require X-MERCHANT-ID)
    if PHONEPE_MERCHANT_ID:
        headers["X-MERCHANT-ID"] = PHONEPE_MERCHANT_ID

    url = PHONEPE_CHECKOUT_BASE.rstrip("/") + "/checkout/v2/pay"
    logger.info("Calling PhonePe checkout create: %s merchantOrderId=%s amount=%s", url, merchant_order_id, amount_paise)

    try:
        r = requests.post(url, json=body, headers=headers, timeout=20)
    except Exception as e:
        logger.exception("PhonePe checkout request failed")
        raise RuntimeError(f"PhonePe checkout request failed: {e}")

    snippet = (r.text[:1200] + "...") if len(r.text) > 1200 else r.text
    logger.info("PhonePe checkout status=%s body_snippet=%s", r.status_code, snippet)

    try:
        j = r.json()
    except Exception:
        raise RuntimeError(f"PhonePe checkout returned non-json: {r.status_code} {r.text}")

    if r.status_code not in (200, 201):
        # bubble up PhonePe JSON so caller can log it
        raise RuntimeError(f"PhonePe checkout error {r.status_code}: {j}")

    return j


# Optional helpers (order status & refund can be added the same way)
def order_status(merchant_order_id: str, details: bool = False, error_context: bool = False, merchant_id: Optional[str] = None) -> Dict[str, Any]:
    token = _get_oauth_token()
    token_type = _token_cache.get("token_type") or "O-Bearer"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"{token_type} {token}",
        "x-auth-token": token
    }
    if merchant_id:
        headers["X-MERCHANT-ID"] = merchant_id
    elif PHONEPE_MERCHANT_ID:
        headers["X-MERCHANT-ID"] = PHONEPE_MERCHANT_ID

    params = {"details": "true" if details else "false", "errorContext": "true" if error_context else "false"}
    url = PHONEPE_CHECKOUT_BASE.rstrip("/") + f"/checkout/v2/order/{merchant_order_id}/status"
    r = requests.get(url, headers=headers, params=params, timeout=20)
    try:
        j = r.json()
    except Exception:
        raise RuntimeError(f"PhonePe order status returned non-json: {r.status_code} {r.text}")
    if r.status_code not in (200, 201):
        raise RuntimeError(f"PhonePe order status error {r.status_code}: {j}")
    return j


def initiate_refund(merchant_refund_id: str, original_merchant_order_id: str, amount_paise: int, merchant_id: Optional[str] = None) -> Dict[str, Any]:
    token = _get_oauth_token()
    token_type = _token_cache.get("token_type") or "O-Bearer"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"{token_type} {token}",
        "x-auth-token": token
    }
    if merchant_id:
        headers["X-MERCHANT-ID"] = merchant_id
    elif PHONEPE_MERCHANT_ID:
        headers["X-MERCHANT-ID"] = PHONEPE_MERCHANT_ID

    url = PHONEPE_CHECKOUT_BASE.rstrip("/") + "/payments/v2/refund"
    body = {"merchantRefundId": merchant_refund_id, "originalMerchantOrderId": original_merchant_order_id, "amount": amount_paise}
    r = requests.post(url, json=body, headers=headers, timeout=20)
    try:
        j = r.json()
    except Exception:
        raise RuntimeError(f"PhonePe refund returned non-json: {r.status_code} {r.text}")
    if r.status_code not in (200, 201):
        raise RuntimeError(f"PhonePe refund error {r.status_code}: {j}")
    return j


def refund_status(merchant_refund_id: str, merchant_id: Optional[str] = None) -> Dict[str, Any]:
    token = _get_oauth_token()
    token_type = _token_cache.get("token_type") or "O-Bearer"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"{token_type} {token}",
        "x-auth-token": token
    }
    if merchant_id:
        headers["X-MERCHANT-ID"] = merchant_id
    elif PHONEPE_MERCHANT_ID:
        headers["X-MERCHANT-ID"] = PHONEPE_MERCHANT_ID

    url = PHONEPE_CHECKOUT_BASE.rstrip("/") + f"/payments/v2/refund/{merchant_refund_id}/status"
    r = requests.get(url, headers=headers, timeout=20)
    try:
        j = r.json()
    except Exception:
        raise RuntimeError(f"PhonePe refund status returned non-json: {r.status_code} {r.text}")
    if r.status_code not in (200, 201):
        raise RuntimeError(f"PhonePe refund status error {r.status_code}: {j}")
    return j








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

