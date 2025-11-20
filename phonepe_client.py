# # phonepe_client.py
# import os
# import time
# import logging
# import requests
# from typing import Dict, Any, Optional

# logger = logging.getLogger("uvicorn.phonepe_client")
# logger.setLevel(logging.INFO)

# # env config
# PHONEPE_BASE_URL = os.getenv("PHONEPE_BASE_URL", "https://api.phonepe.com")
# PHONEPE_CLIENT_ID = os.getenv("PHONEPE_CLIENT_ID") or os.getenv("PHONEPE_MERCHANT_ID")
# PHONEPE_CLIENT_SECRET = os.getenv("PHONEPE_CLIENT_SECRET")
# PHONEPE_CLIENT_VERSION = os.getenv("PHONEPE_CLIENT_VERSION", "1")
# REDIRECT_BASE_URL = os.getenv("REDIRECT_BASE_URL")  # e.g. https://your-app.com

# if not PHONEPE_CLIENT_ID or not PHONEPE_CLIENT_SECRET or not REDIRECT_BASE_URL:
#     logger.warning("PhonePe env variables missing. PHONEPE_CLIENT_ID/SECRET/REDIRECT_BASE_URL required in env")

# # simple in-memory token cache (short-lived)
# _token_cache = {"access_token": None, "expires_at": 0}

# def _get_oauth_token() -> str:
#     """
#     Request an access token from PhonePe (client_credentials).
#     Caches token until expiry.
#     """
#     now = int(time.time())
#     if _token_cache["access_token"] and _token_cache["expires_at"] - 10 > now:
#         return _token_cache["access_token"]

#     token_url = PHONEPE_BASE_URL.rstrip("/") + "/apis/identity-manager/v1/oauth/token"
#     payload = {
#         "client_id": PHONEPE_CLIENT_ID,
#         "client_version": PHONEPE_CLIENT_VERSION,
#         "client_secret": PHONEPE_CLIENT_SECRET,
#         "grant_type": "client_credentials"
#     }

#     headers = {"Content-Type": "application/x-www-form-urlencoded"}
#     logger.info("Requesting PhonePe OAuth token from %s", token_url)
#     resp = requests.post(token_url, data=payload, headers=headers, timeout=15)
#     logger.info("PhonePe token status=%s", resp.status_code)
#     try:
#         j = resp.json()
#     except Exception:
#         logger.error("PhonePe token invalid JSON: %s", resp.text)
#         resp.raise_for_status()
#     if resp.status_code != 200:
#         logger.error("PhonePe token error: %s", j)
#         raise RuntimeError(f"PhonePe token fetch failed: {j}")

#     access = j.get("access_token") or j.get("encrypted_access_token")
#     expires_at = j.get("expires_at") or (int(time.time()) + (j.get("expires_in", 3600) or 3600))
#     _token_cache["access_token"] = access
#     try:
#         _token_cache["expires_at"] = int(expires_at)
#     except Exception:
#         _token_cache["expires_at"] = int(time.time()) + 3600
#     logger.info("Obtained PhonePe token, expires_at=%s", _token_cache["expires_at"])
#     return access

# def create_checkout(merchant_order_id: str, amount_paise: int, booking_id: int, user_id: str) -> Dict[str, Any]:
#     """
#     Create a PhonePe checkout session using the Standard Checkout API.
#     Returns PhonePe response as a dict (raw).
#     """
#     token = _get_oauth_token()

#     checkout_url = PHONEPE_BASE_URL.rstrip("/") + "/apis/pg/checkout/v2/pay"
#     body = {
#         "merchantOrderId": merchant_order_id,
#         "amount": amount_paise,
#         "paymentFlow": {
#             "type": "PG_CHECKOUT",
#             "merchantUrls": {
#                 "redirectUrl": f"{REDIRECT_BASE_URL.rstrip('/')}/payment-success"
#             }
#         },
#         "metaInfo": {
#             "udf1": f"booking_id:{booking_id}",
#             "udf2": f"user_id:{user_id}"
#         }
#     }

#     headers = {
#         "Content-Type": "application/json",
#         "Authorization": f"O-Bearer {token}"
#     }

#     logger.info("Calling PhonePe checkout endpoint %s", checkout_url)
#     logger.debug("PhonePe request body: %s", body)
#     resp = requests.post(checkout_url, json=body, headers=headers, timeout=20)
#     logger.info("PhonePe checkout status=%s", resp.status_code)
#     try:
#         j = resp.json()
#     except Exception:
#         logger.error("PhonePe checkout invalid JSON: %s", resp.text)
#         resp.raise_for_status()

#     if resp.status_code not in (200, 201):
#         logger.error("PhonePe checkout error: status=%s body=%s", resp.status_code, j)
#         # return or raise as you prefer; we'll raise so caller can handle
#         raise RuntimeError(f"PhonePe checkout failed: {j}")

#     logger.info("PhonePe checkout response: %s", j)
#     return j







# phonepe_client.py
import os
import requests
import logging
from typing import Dict, Any

logger = logging.getLogger("phonepe_client")
logger.setLevel(logging.INFO)

# Load env variables from process environment (use python-dotenv in main if needed)
PHONEPE_MERCHANT_ID = os.getenv("PHONEPE_MERCHANT_ID")               # merchant id (also used as client_id in many integrations)
PHONEPE_CLIENT_SECRET = os.getenv("PHONEPE_CLIENT_SECRET")           # client secret
PHONEPE_CLIENT_VERSION = os.getenv("PHONEPE_CLIENT_VERSION", "1")
# Token URL for production (identity manager) and sandbox token URL for sandbox
PHONEPE_TOKEN_URL = os.getenv("PHONEPE_TOKEN_URL", "https://api.phonepe.com/apis/identity-manager/v1/oauth/token")
# Checkout base URL for production and sandbox counterpart
PHONEPE_CHECKOUT_BASE = os.getenv("PHONEPE_CHECKOUT_BASE", "https://api.phonepe.com/apis/pg")

# Redirect/callback base URLs (full redirect/callback provided by main via env)
REDIRECT_BASE_URL = os.getenv("REDIRECT_BASE_URL")
PHONEPE_REDIRECT_URL = os.getenv("PHONEPE_REDIRECT_URL") or (REDIRECT_BASE_URL + "/payment-success" if REDIRECT_BASE_URL else None)
PHONEPE_CALLBACK_URL = os.getenv("PHONEPE_CALLBACK_URL") or (REDIRECT_BASE_URL + "/payment/callback" if REDIRECT_BASE_URL else None)

if not PHONEPE_MERCHANT_ID or not PHONEPE_CLIENT_SECRET:
    logger.warning("PHONEPE_MERCHANT_ID or PHONEPE_CLIENT_SECRET not set in environment. PhonePe calls will fail until provided.")

def _get_oauth_token() -> str:
    """
    Request O-Bearer token from PhonePe.
    Returns access_token (string) or raise RuntimeError on failure.
    """
    url = PHONEPE_TOKEN_URL
    logger.info(f"Requesting PhonePe OAuth token from {url}")

    # client_id may be same as merchant id; some PhonePe docs call this client_id
    client_id = os.getenv("PHONEPE_CLIENT_ID") or PHONEPE_MERCHANT_ID
    client_version = os.getenv("PHONEPE_CLIENT_VERSION") or PHONEPE_CLIENT_VERSION
    client_secret = PHONEPE_CLIENT_SECRET

    if not client_id or not client_secret:
        raise RuntimeError("PhonePe client_id or client_secret missing in environment")

    payload = {
        "client_id": client_id,
        "client_version": client_version,
        "client_secret": client_secret,
        "grant_type": "client_credentials"
    }

    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    r = requests.post(url, data=payload, headers=headers, timeout=20)
    logger.info(f"PhonePe token status={r.status_code}")
    try:
        j = r.json()
    except Exception:
        raise RuntimeError(f"PhonePe token fetch failed, non-json response: {r.status_code} {r.text}")

    if r.status_code != 200:
        # include body for debugging
        raise RuntimeError(f"PhonePe token fetch failed: {j}")

    # token_type is 'O-Bearer' and access_token key present
    access_token = j.get("access_token") or j.get("encrypted_access_token")
    if not access_token:
        raise RuntimeError(f"PhonePe token missing access_token in response: {j}")

    return access_token

def create_checkout(merchant_order_id: str, amount_paise: int, booking_id: int, user_id: str) -> Dict[str, Any]:
    """
    Create a PhonePe standard checkout (POST /checkout/v2/pay).
    Returns parsed JSON from PhonePe.
    """
    token = _get_oauth_token()
    # Build request body according to PhonePe standard checkout API
    body = {
        "merchantOrderId": merchant_order_id,
        "amount": amount_paise,  # in paise
        # optional expireAfter etc.
        "paymentFlow": {
            "type": "PG_CHECKOUT",
            "merchantUrls": {
                "redirectUrl": PHONEPE_REDIRECT_URL or ""
            }
        },
        "metaInfo": {
            # include small useful metadata (avoid PII). PhonePe returns this back in callbacks.
            "udf1": str(booking_id),
            "udf2": str(user_id)
        }
    }

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"O-Bearer {token}"
    }

    url = PHONEPE_CHECKOUT_BASE.rstrip("/") + "/checkout/v2/pay"
    logger.info(f"Calling PhonePe checkout create: {url} merchantOrderId={merchant_order_id} amount={amount_paise}")

    r = requests.post(url, json=body, headers=headers, timeout=20)
    logger.info(f"PhonePe checkout status={r.status_code}")
    try:
        j = r.json()
    except Exception:
        raise RuntimeError(f"PhonePe checkout returned non-json: {r.status_code} {r.text}")

    if r.status_code not in (200, 201):
        # include body for debugging
        raise RuntimeError(f"PhonePe checkout error {r.status_code}: {j}")

    return j
