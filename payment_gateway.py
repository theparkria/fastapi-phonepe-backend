# # payment_gateway.py
# from fastapi import FastAPI, HTTPException, Request
# from fastapi.middleware.cors import CORSMiddleware
# from pydantic import BaseModel
# from dotenv import load_dotenv
# from datetime import datetime
# import hashlib
# import base64
# import json
# import os
# import requests

# # -------------------------
# # Load environment
# # -------------------------
# load_dotenv()

# PHONEPE_MERCHANT_ID = os.getenv("PHONEPE_MERCHANT_ID", "TEST-M23LRM0EUZZU8_25090")
# PHONEPE_CLIENT_SECRET = os.getenv("PHONEPE_CLIENT_SECRET", "YOUR_TEST_CLIENT_SECRET")
# PHONEPE_CLIENT_VERSION = os.getenv("PHONEPE_CLIENT_VERSION", "1")

# PHONEPE_BASE_URL = "https://api-preprod.phonepe.com/apis/pg-sandbox"

# # Replace with your ngrok URL each time
# NGROK_BASE_URL = os.getenv("NGROK_BASE_URL", "https://acae4b2052f2.ngrok-free.app")

# PHONEPE_REDIRECT_URL = f"{NGROK_BASE_URL}/payment-success"
# PHONEPE_CALLBACK_URL = f"{NGROK_BASE_URL}/payment/callback"

# # -------------------------
# # FastAPI
# # -------------------------
# app = FastAPI(title="PhonePe Payment Gateway")
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],  
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# # -------------------------
# # Models
# # -------------------------
# class PaymentRequest(BaseModel):
#     booking_id: int
#     amount: int  # INR
#     user_id: str

# # -------------------------
# # Utils
# # -------------------------
# def generate_checksum(payload_base64: str, endpoint: str) -> str:
#     """Generate SHA256 checksum for PhonePe API"""
#     to_hash = payload_base64 + endpoint + PHONEPE_CLIENT_SECRET
#     return hashlib.sha256(to_hash.encode("utf-8")).hexdigest() + "###" + PHONEPE_CLIENT_VERSION

# # -------------------------
# # Endpoints
# # -------------------------
# @app.get("/")
# def root():
#     return {"message": "🚀 PhonePe Payment Gateway running via ngrok"}

# @app.post("/create-payment")
# def create_payment(data: PaymentRequest):
#     """
#     Endpoint for Flutter: generates PhonePe checkout URL
#     """
#     try:
#         merchant_txn_id = f"TXN{data.booking_id}{int(datetime.utcnow().timestamp())}"

#         payload = {
#             "merchantId": PHONEPE_MERCHANT_ID,
#             "merchantTransactionId": merchant_txn_id,
#             "merchantUserId": data.user_id,
#             "amount": data.amount * 100,  # in paise
#             "redirectUrl": PHONEPE_REDIRECT_URL,
#             "redirectMode": "REDIRECT",
#             "callbackUrl": PHONEPE_CALLBACK_URL,
#             "paymentInstrument": {"type": "PAY_PAGE"},
#         }

#         payload_str = json.dumps(payload, separators=(",", ":"))
#         payload_base64 = base64.b64encode(payload_str.encode()).decode()
#         checksum = generate_checksum(payload_base64, "/pg/v1/pay")

#         headers = {
#             "Content-Type": "application/json",
#             "X-VERIFY": checksum,
#             "accept": "application/json",
#         }

#         url = f"{PHONEPE_BASE_URL}/pg/v1/pay"
#         res = requests.post(url, json={"request": payload_base64}, headers=headers)

#         if res.status_code != 200:
#             raise HTTPException(status_code=400, detail=f"PhonePe error: {res.text}")

#         return res.json()
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))

# @app.post("/payment/callback")
# async def payment_callback(request: Request):
#     """Server-to-server callback from PhonePe"""
#     body = await request.json()
#     print("📩 Callback received:", body)
#     return {"status": "received", "body": body}

# @app.get("/payment-success")
# def payment_success():
#     """User redirect after payment"""
#     return {"message": "✅ Payment Success! Update booking status in your DB here."}






# payment_gateway.py
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from datetime import datetime
import hashlib
import base64
import json
import os
import requests
import logging
from typing import Dict

# -------------------------
# Load environment (set these in your production env or .env)
# -------------------------
load_dotenv()

# Example: set these in your environment; DO NOT hardcode production secrets in code.
PHONEPE_MERCHANT_ID = os.getenv("PHONEPE_MERCHANT_ID")            # e.g. "MERCHANT-XXXX"
PHONEPE_CLIENT_SECRET = os.getenv("PHONEPE_CLIENT_SECRET")        # production secret
PHONEPE_CLIENT_VERSION = os.getenv("PHONEPE_CLIENT_VERSION", "1")
PHONEPE_BASE_URL = os.getenv("PHONEPE_BASE_URL", "https://api.phonepe.com/apis/hermes")

# Public-facing redirect / callback URLs (your domain, secured with TLS in prod)
REDIRECT_BASE_URL = os.getenv("REDIRECT_BASE_URL")  # e.g. https://app.mydomain.com
PHONEPE_REDIRECT_URL = f"{REDIRECT_BASE_URL}/payment-success"
PHONEPE_CALLBACK_URL = f"{REDIRECT_BASE_URL}/payment/callback"

# Basic runtime checks
if not PHONEPE_MERCHANT_ID or not PHONEPE_CLIENT_SECRET or not REDIRECT_BASE_URL:
    raise RuntimeError("Set PHONEPE_MERCHANT_ID, PHONEPE_CLIENT_SECRET and REDIRECT_BASE_URL in env")

# -------------------------
# FastAPI
# -------------------------
app = FastAPI(title="PhonePe Payment Gateway - Production helper")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://your-frontend.com"],  # lock down to your frontend domains in prod
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

logger = logging.getLogger("uvicorn")
logger.setLevel(logging.INFO)

# -------------------------
# Models
# -------------------------
class PaymentRequest(BaseModel):
    booking_id: int   # your DB booking id or 0 if not created yet
    amount: int       # rupees (not paise) - we'll convert to paise
    user_id: str

# -------------------------
# In-memory map (demo) -> Replace with DB table in prod
# merchantTxId -> booking_id, amount, created_at
# -------------------------
merchant_map: Dict[str, dict] = {}

# -------------------------
# Utils - Checksum / X-VERIFY
# -------------------------
def generate_checksum(payload_base64: str, endpoint: str) -> str:
    """
    Basic PhonePe checksum builder used in many examples:
      hash = sha256(payloadBase64 + endpoint + clientSecret)
      x_verify = hash + "###" + clientVersion
    NOTE: Confirm exact algorithm with PhonePe (this is the common form).
    """
    to_hash = (payload_base64 or "") + endpoint + (PHONEPE_CLIENT_SECRET or "")
    digest = hashlib.sha256(to_hash.encode("utf-8")).hexdigest()
    return f"{digest}###{PHONEPE_CLIENT_VERSION}"

def base64_json(obj: dict) -> str:
    s = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    return base64.b64encode(s.encode("utf-8")).decode("utf-8")

# -------------------------
# Endpoints
# -------------------------
@app.get("/")
def root():
    return {"message": "PhonePe gateway (production helper) up"}

@app.post("/create-payment")
def create_payment(data: PaymentRequest):
    """
    Called by your Flutter app to create PhonePe checkout.
    Returns PhonePe response which typically contains checkout_url and merchantTransactionId.
    """
    try:
        # merchantTransactionId: unique per merchant
        merchant_txn_id = f"parkria_{data.booking_id}_{int(datetime.utcnow().timestamp())}"

        payload = {
            "merchantId": PHONEPE_MERCHANT_ID,
            "merchantTransactionId": merchant_txn_id,
            "merchantUserId": str(data.user_id),
            "amount": int(data.amount) * 100,  # convert INR -> paise
            "redirectUrl": PHONEPE_REDIRECT_URL,
            "redirectMode": "REDIRECT",
            "callbackUrl": PHONEPE_CALLBACK_URL,
            "paymentInstrument": {"type": "PAY_PAGE"}
        }

        payload_base64 = base64_json(payload)
        endpoint_path = "/pg/v1/pay"   # phonepe endpoint path (under /apis/hermes)
        x_verify = generate_checksum(payload_base64, endpoint_path)

        headers = {
            "Content-Type": "application/json",
            "accept": "application/json",
            "X-VERIFY": x_verify,
        }

        url = PHONEPE_BASE_URL.rstrip("/") + endpoint_path
        logger.info(f"Creating PhonePe payment for merchantTxnId={merchant_txn_id} amount={data.amount}")

        resp = requests.post(url, json={"request": payload_base64}, headers=headers, timeout=20)
        if resp.status_code != 200:
            logger.error(f"PhonePe create-pay error {resp.status_code}: {resp.text}")
            raise HTTPException(status_code=400, detail=f"PhonePe error: {resp.text}")

        resp_json = resp.json()
        # store mapping locally (persist to your DB in production)
        merchant_map[merchant_txn_id] = {
            "booking_id": data.booking_id,
            "user_id": data.user_id,
            "amount": data.amount,
            "created_at": datetime.utcnow().isoformat(),
            "phonepe_response": resp_json
        }

        return resp_json
    except Exception as e:
        logger.exception("create_payment failed")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/order-status/{merchant_txn_id}")
def order_status(merchant_txn_id: str):
    """
    Query PhonePe order status for merchant_txn_id.
    Useful to double-check payment after redirect.
    """
    try:
        endpoint_path = f"/pg/v1/status/{PHONEPE_MERCHANT_ID}/{merchant_txn_id}"
        payload_base64 = ""  # many PhonePe examples use empty payload for status
        x_verify = generate_checksum(payload_base64, endpoint_path)
        headers = {
            "Content-Type": "application/json",
            "accept": "application/json",
            "X-VERIFY": x_verify
        }
        url = PHONEPE_BASE_URL.rstrip("/") + endpoint_path
        logger.info(f"Querying order status for {merchant_txn_id}")
        resp = requests.get(url, headers=headers, timeout=20)
        if resp.status_code != 200:
            logger.error(f"PhonePe order-status error {resp.status_code}: {resp.text}")
            raise HTTPException(status_code=400, detail=f"PhonePe status error: {resp.text}")
        return resp.json()
    except Exception as e:
        logger.exception("order_status failed")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/payment/callback")
async def payment_callback(request: Request):
    """
    Server-to-server callback from PhonePe (webhook).
    Validate X-VERIFY if present and then handle the payload.
    IMPORTANT: In production verify X-VERIFY exactly per PhonePe docs.
    """
    try:
        raw_body = await request.body()
        body_text = raw_body.decode("utf-8") if raw_body else ""
        logger.info(f"PhonePe callback raw body: {body_text}")

        # Verify header if provided
        incoming_x_verify = request.headers.get("X-VERIFY") or request.headers.get("x-verify")
        endpoint_path = "/pg/v1/payment/callback"  # adjust if PhonePe documents different callback path
        computed = generate_checksum(base64.b64encode(raw_body).decode("utf-8") if raw_body else "", endpoint_path)

        verified = (incoming_x_verify == computed)
        logger.info(f"X-VERIFY incoming={incoming_x_verify} computed={computed} verified={verified}")

        # parse json
        payload = await request.json()

        # Here: process callback - update DB booking status based on merchantTransactionId / order id
        # Example: phonepe sends merchantTransactionId inside callback payload (check actual payload).
        # For demonstration, we return and log.
        logger.info("PhonePe callback payload: %s", json.dumps(payload))

        # TODO: persist callback, mark booking paid using merchantTransactionId or phonepeOrderId
        return {"status": "ok", "verified": verified}
    except Exception as e:
        logger.exception("callback processing error")
        raise HTTPException(status_code=500, detail=str(e))
