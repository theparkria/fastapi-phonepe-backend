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






from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from datetime import datetime
import razorpay
import os
import hmac
import hashlib
import logging
from typing import Dict

# -------------------------
# Load env
# -------------------------
load_dotenv()

RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET")
REDIRECT_BASE_URL = os.getenv("REDIRECT_BASE_URL")

if not RAZORPAY_KEY_ID or not RAZORPAY_KEY_SECRET or not REDIRECT_BASE_URL:
    raise RuntimeError("Set RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET, REDIRECT_BASE_URL")

# -------------------------
# Razorpay client
# -------------------------
razorpay_client = razorpay.Client(
    auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET)
)

# -------------------------
# FastAPI
# -------------------------
app = FastAPI(title="Razorpay Payment Gateway - Production")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://your-frontend.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

logger = logging.getLogger("uvicorn")
logger.setLevel(logging.INFO)

# -------------------------
# Models
# -------------------------
class PaymentRequest(BaseModel):
    booking_id: int
    amount: int      # INR
    user_id: str

class VerifyPayment(BaseModel):
    razorpay_order_id: str
    razorpay_payment_id: str
    razorpay_signature: str

# -------------------------
# Demo in-memory store (use DB in prod)
# -------------------------
order_map: Dict[str, dict] = {}

# -------------------------
# Routes
# -------------------------
@app.get("/")
def root():
    return {"message": "Razorpay gateway up"}

@app.post("/create-payment")
def create_payment(data: PaymentRequest):
    """
    Create Razorpay Order
    """
    try:
        order = razorpay_client.order.create({
            "amount": data.amount * 100,  # INR -> paise
            "currency": "INR",
            "receipt": f"receipt_{data.booking_id}_{int(datetime.utcnow().timestamp())}",
            "payment_capture": 1
        })

        order_map[order["id"]] = {
            "booking_id": data.booking_id,
            "user_id": data.user_id,
            "amount": data.amount,
            "created_at": datetime.utcnow().isoformat()
        }

        return {
            "order_id": order["id"],
            "razorpay_key": RAZORPAY_KEY_ID,
            "amount": data.amount * 100,
            "currency": "INR",
            "callback_url": f"{REDIRECT_BASE_URL}/payment-success"
        }

    except Exception as e:
        logger.exception("create_payment failed")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/verify-payment")
def verify_payment(data: VerifyPayment):
    """
    Verify Razorpay signature after payment success
    """
    try:
        body = f"{data.razorpay_order_id}|{data.razorpay_payment_id}"
        expected_signature = hmac.new(
            RAZORPAY_KEY_SECRET.encode(),
            body.encode(),
            hashlib.sha256
        ).hexdigest()

        if expected_signature != data.razorpay_signature:
            raise HTTPException(status_code=400, detail="Invalid payment signature")

        # ✅ Payment verified
        order_data = order_map.get(data.razorpay_order_id)

        # TODO: Mark booking paid in DB
        return {
            "status": "success",
            "booking_id": order_data["booking_id"] if order_data else None
        }

    except Exception as e:
        logger.exception("verify_payment failed")
        raise HTTPException(status_code=500, detail=str(e))
