import os
from pathlib import Path
import logging
import hmac
import hashlib
from datetime import datetime

# load dotenv explicitly before importing modules that read env
from dotenv import load_dotenv

# ensure .env located next to this file is loaded (robust even if working dir differs)
env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(env_path)

# safe boolean checks only (DO NOT print secret values)
logger = logging.getLogger("uvicorn.error")
logger.setLevel(logging.INFO)
logger.info("ENV CHECK - SUPABASE_URL present: %s", bool(os.getenv("SUPABASE_URL")))
logger.info("ENV CHECK - SUPABASE_SERVICE_KEY present: %s", bool(os.getenv("SUPABASE_SERVICE_KEY")))
logger.info("ENV CHECK - PHONEPE_MERCHANT_ID present: %s", bool(os.getenv("PHONEPE_MERCHANT_ID")))
logger.info("ENV CHECK - PHONEPE_CLIENT_SECRET present: %s", bool(os.getenv("PHONEPE_CLIENT_SECRET")))
logger.info("ENV CHECK - PHONEPE_ENV present: %s", bool(os.getenv("PHONEPE_ENV")))

# now safe to import app dependencies that may read env
from fastapi import FastAPI, HTTPException, Request, Query, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from supabase import create_client, Client

# password hashing for signup/login - use bcrypt_sha256 to avoid 72-byte limit
from passlib.context import CryptContext

# local phonepe helper (import after env loaded)
# phonepe_client should implement token handling and environment selection (sandbox/prod)
from phonepe_client import create_checkout  # ensure you replaced phonepe_client.py with the improved version

# -----------------------
# Supabase client
# -----------------------
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
    raise RuntimeError("Set SUPABASE_URL and SUPABASE_SERVICE_KEY in environment")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

# -----------------------
# FastAPI
# -----------------------
app = FastAPI(title="Parkria Backend - PhonePe")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------
# Security headers middleware required by PhonePe
# -----------------------
from fastapi import Response

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """
    Adds the response headers PhonePe requires:
      - Referrer-Policy: strict-origin-when-cross-origin
      - Cross-Origin-Opener-Policy: same-origin
    Set them at the app level so they are present on /payment-success and other responses.
    """
    response: Response = await call_next(request)
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    return response

# -----------------------
# Password hashing
# -----------------------
# Use bcrypt_sha256 to avoid bcrypt's 72-byte limit
pwd_context = CryptContext(schemes=["bcrypt_sha256"], deprecated="auto")

# ======================
# Schemas
# ======================
class SendOTPRequest(BaseModel):
    phone: str

class VerifyOTPRequest(BaseModel):
    name: str
    phone: str
    otp: str
    password: str

class UserLogin(BaseModel):
    phone: str
    password: str

class AddVehicleRequest(BaseModel):
    user_id: str
    owner_name: str
    car_brand: str
    car_model: str
    car_type: str
    car_number: str

class ParkingSlotBookRequest(BaseModel):
    slot_id: int
    vehicle_id: int
    user_id: str

class TokenPurchaseRequest(BaseModel):
    service_type_id: int
    user_id: str
    token_count: int

class ConsumeTokenRequest(BaseModel):
    user_id: str
    service_type_id: int
    token_count: int
    booking_date: str
    slot_id: int | None = None

class PaymentRequest(BaseModel):
    booking_id: int
    amount: int
    user_id: str

# ======================
# Helpers: signature verification (stub)
# ======================
def verify_phonepe_signature(raw_body: bytes, signature_header: str | None) -> bool:
    """
    Verify incoming PhonePe callback signature.

    **IMPORTANT:** This implementation assumes the signature header contains
    a hex-encoded HMAC-SHA256 of the raw request body using your
    PHONEPE_CLIENT_SECRET as key.

    *This is an example only.* Please consult PhonePe docs for the exact
    header name and algorithm (they might use base64-encoded HMAC or RSA).
    Update this function to match the production spec provided by PhonePe.*
    """
    secret = os.getenv("PHONEPE_CLIENT_SECRET")
    if not secret:
        logger.warning("PHONEPE_CLIENT_SECRET not configured; skipping signature verification (unsafe!).")
        return False

    if not signature_header:
        logger.warning("No signature header present on callback")
        return False

    try:
        # compute hmac sha256 hex digest
        computed = hmac.new(secret.encode('utf-8'), raw_body, hashlib.sha256).hexdigest()
        # Use constant-time comparison
        return hmac.compare_digest(computed.lower(), signature_header.lower())
    except Exception as e:
        logger.exception("Failed verifying signature: %s", e)
        return False

# ======================
# Root
# ======================
@app.get("/")
def root():
    return {"message": "🚀 API Running"}

# ======================
# Auth & other APIs (unchanged)
# ======================
@app.post("/send-otp")
def send_otp(data: SendOTPRequest):
    return {"message": f"OTP sent to +91{data.phone}", "otp": "1234"}

@app.post("/signup")
def signup(data: VerifyOTPRequest):
    exists = supabase.table("users").select("*").eq("phone", data.phone).execute()
    if exists.data:
        raise HTTPException(status_code=400, detail="User already exists")
    password_hash = pwd_context.hash(data.password)
    res = supabase.table("users").insert({
        "name": data.name,
        "phone": data.phone,
        "password_hash": password_hash,
        "created_at": datetime.utcnow().isoformat()
    }).execute()
    user_id = res.data[0]["id"]
    return {"message": "Signup successful", "user_id": user_id}

@app.post("/login")
def login(user: UserLogin):
    res = supabase.table("users").select("*").eq("phone", user.phone).execute()
    if not res.data:
        raise HTTPException(status_code=401, detail="User not found")
    db_user = res.data[0]
    if not pwd_context.verify(user.password, db_user["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect password")
    return {"message": f"Welcome {db_user.get('name')}", "user": {k:v for k,v in db_user.items() if k!="password_hash"}}

# vehicles, services, tokens, parking slots etc...
@app.post("/vehicles/add")
def add_vehicle(data: AddVehicleRequest):
    exists = supabase.table("vehicles").select("*").eq("car_number", data.car_number).execute()
    if exists.data:
        raise HTTPException(status_code=400, detail="Car number already registered")
    res = supabase.table("vehicles").insert({
        "user_id": data.user_id,
        "owner_name": data.owner_name,
        "car_brand": data.car_brand,
        "car_model": data.car_model,
        "car_type": data.car_type,
        "car_number": data.car_number,
        "created_at": datetime.utcnow().isoformat()
    }).execute()
    return {"message": "Vehicle added", "vehicle": res.data[0]}

@app.get("/vehicles")
def get_user_vehicles(user_id: str = Query(...)):
    res = supabase.table("vehicles").select("vehicle_id, car_number").eq("user_id", user_id).order("vehicle_id").execute()
    return res.data or []

@app.get("/services")
def get_services():
    res = supabase.table("service_types").select("*").execute()
    return res.data or []

@app.post("/purchase-token")
def purchase_token(data: TokenPurchaseRequest):
    existing = supabase.table("purchased_tokens")\
        .select("*")\
        .eq("user_id", data.user_id)\
        .eq("service_type_id", data.service_type_id)\
        .execute()
    if existing.data:
        token_id = existing.data[0]["token_id"]
        new_count = existing.data[0]["token_count"] + data.token_count
        update_res = supabase.table("purchased_tokens")\
            .update({"token_count": new_count, "updated_at": datetime.utcnow().isoformat()})\
            .eq("token_id", token_id).execute()
        return {"message": "Tokens updated successfully", "purchase": update_res.data[0]}
    else:
        insert_res = supabase.table("purchased_tokens").insert({
            "user_id": data.user_id,
            "service_type_id": data.service_type_id,
            "token_count": data.token_count,
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }).execute()
        return {"message": "Purchase saved successfully", "purchase": insert_res.data[0]}

@app.post("/consume-token")
def consume_token(data: ConsumeTokenRequest):
    purchased = supabase.table("purchased_tokens")\
        .select("*")\
        .eq("user_id", data.user_id)\
        .eq("service_type_id", data.service_type_id)\
        .order("created_at")\
        .execute()
    if not purchased.data:
        raise HTTPException(status_code=404, detail="No tokens available")
    remaining = data.token_count
    for row in purchased.data:
        available = row["token_count"]
        use_count = min(available, remaining)
        supabase.table("purchased_tokens").update({
            "token_count": available - use_count,
            "updated_at": datetime.utcnow().isoformat()
        }).eq("token_id", row["token_id"]).execute()
        remaining -= use_count
        if remaining <= 0:
            break
    if remaining > 0:
        raise HTTPException(status_code=400, detail="Insufficient tokens")
    return {"message": "Token consumed successfully"}

@app.get("/user-tokens")
def get_user_tokens(user_id: str = Query(...), service_type_id: int = Query(...)):
    response = supabase.table("purchased_tokens")\
        .select("token_count")\
        .eq("user_id", user_id)\
        .eq("service_type_id", service_type_id)\
        .execute()
    total_tokens = sum(row.get("token_count", 0) for row in response.data or [])
    return {"tokens": total_tokens}

@app.get("/parking-slots")
def get_parking_slots(unit_id: int = Query(...)):
    slots_data = supabase.table("parking_slots").select("*").eq("unit_id", unit_id).execute().data
    total_slots = 30  # fallback, or fetch from DB
    return {
        "total_slots": total_slots,
        "slots": slots_data or []
    }

@app.post("/parking-slots/book")
def book_slot(data: ParkingSlotBookRequest):
    slot = supabase.table("parking_slots").select("*")\
        .eq("slot_id", data.slot_id).eq("status", "available").execute()
    if not slot.data:
        raise HTTPException(status_code=400, detail="Slot not available")
    res = supabase.table("parking_slots").update({
        "status": "occupied",
        "current_vehicle_id": data.vehicle_id,
        "updated_at": datetime.utcnow().isoformat()
    }).eq("slot_id", data.slot_id).execute()
    return {"message": "Slot booked", "slot": res.data[0]}

# ======================
# Orders / PhonePe integration
# ======================
@app.post("/create-payment")
def create_payment(req: PaymentRequest):
    # coerce + validate amount
    try:
        amount_val = float(req.amount)
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid 'amount' — must be numeric")
    if amount_val <= 0:
        raise HTTPException(status_code=400, detail="Invalid amount; must be > 0")

    # merchant_order_id must be unique per attempt - include timestamp
    merchant_order_id = f"ord-{req.booking_id}-{int(datetime.utcnow().timestamp())}"
    amount_paise = int(round(amount_val * 100))

    # coerce user_id to string; if your DB expects UUID ensure frontend sends a proper UUID.
    user_id_str = str(req.user_id)

    # basic heuristic to detect obviously-bad user ids (avoid common DB insertion failures)
    if len(user_id_str) < 6:
        logger.warning("Received suspiciously short user_id; ensure frontend sends user UUID or valid id: %s", user_id_str)

    logger.info("Creating checkout: merchant_order_id=%s amount_paise=%s user_id=%s", merchant_order_id, amount_paise, user_id_str)
    try:
        phonepe_resp = create_checkout(
            merchant_order_id=merchant_order_id,
            amount_paise=amount_paise,
            booking_id=req.booking_id,
            user_id=user_id_str,
        )
    except Exception as e:
        logger.exception("PhonePe create_checkout failed")
        # Return helpful message for frontend to display
        raise HTTPException(status_code=502, detail=f"PhonePe error: {e}")

    # PhonePe may return different shapes depending on SDK vs web checkout
    response_payload = {
        "merchant_order_id": merchant_order_id,
        "state": "PENDING",
    }

    if isinstance(phonepe_resp, dict):
        # SDK-order (preferred) returns orderId + token
        if phonepe_resp.get("orderId") and phonepe_resp.get("token"):
            response_payload.update({
                "order_id": phonepe_resp.get("orderId"),
                "order_token": phonepe_resp.get("token"),
                "flow": "sdk",
            })
        # fallback web checkout may return redirectUrl
        elif phonepe_resp.get("redirectUrl") or (phonepe_resp.get("data") or {}).get("redirectUrl"):
            response_payload.update({
                "checkout_url": phonepe_resp.get("redirectUrl") or (phonepe_resp.get("data") or {}).get("redirectUrl"),
                "flow": "web",
            })
        else:
            # include raw response so frontend can debug if needed
            response_payload.update({"raw": phonepe_resp})

    # Save order to DB. If DB write fails, still return checkout info but include warning.
    try:
        supabase.table("orders").insert({
            "merchant_order_id": merchant_order_id,
            "booking_id": req.booking_id,
            "user_id": user_id_str,
            "amount": amount_paise,
            "status": response_payload.get("state"),
            "phonepe_order_id": response_payload.get("order_id"),
            "created_at": datetime.utcnow().isoformat()
        }).execute()
    except Exception as e:
        logger.exception("Supabase insert orders failed")
        response_payload["warning"] = f"Saved to DB failed: {e}"

    return response_payload

@app.post("/payment/callback")
async def payment_callback(req: Request, x_phonepe_signature: str | None = Header(None)):
    """
    PhonePe server-to-server callback. PhonePe will POST details here.
    This route now verifies signature before trusting the payload.
    The example uses header 'X-PHONEPE-SIGNATURE' and HMAC-SHA256 hex digest.
    Replace with exact verification per PhonePe docs.
    """
    raw = await req.body()

    # Verify signature - important
    if not verify_phonepe_signature(raw, x_phonepe_signature):
        logger.warning("PhonePe callback signature verification failed")
        raise HTTPException(status_code=401, detail="Invalid signature")

    try:
        payload = await req.json()
    except Exception:
        payload = {"raw": raw.decode("utf-8", errors="ignore") if raw else ""}

    logger.info("PhonePe callback received (verified): %s", payload)

    # attempt to extract merchantOrderId / merchantTransactionId and status/state
    merchant_order_id = payload.get("merchantTransactionId") or payload.get("merchantOrderId") or payload.get("merchant_order_id")
    status = payload.get("status") or payload.get("state") or payload.get("payment_state")

    # also check nested data block
    data_block = payload.get("data") if isinstance(payload.get("data"), dict) else None
    if not merchant_order_id and data_block:
        merchant_order_id = data_block.get("merchantTransactionId") or data_block.get("merchantOrderId")
        status = status or data_block.get("state") or data_block.get("status")

    if merchant_order_id:
        try:
            supabase.table("orders").update({
                "status": status,
                "updated_at": datetime.utcnow().isoformat()
            }).eq("merchant_order_id", merchant_order_id).execute()
        except Exception as e:
            logger.exception("Failed updating order status in supabase")
            return JSONResponse({"message": "callback received; db update failed", "error": str(e)}, status_code=500)

        return {"message": "callback processed", "merchant_order_id": merchant_order_id, "status": status}
    else:
        logger.warning("Callback missing merchant_order_id: %s", payload)
        return {"message": "callback received but merchant id missing", "body": payload}


@app.get("/payment-success")
def payment_success():
    # Browser redirect target after payment — PhonePe will redirect user here.
    # Return a simple HTML page (middleware will attach required headers).
    html = """
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8"/>
        <title>Payment Completed</title>
        <meta name="viewport" content="width=device-width, initial-scale=1"/>
        <style>
          body { font-family: Arial, sans-serif; display:flex; height:100vh; align-items:center; justify-content:center; background:#f7fafc; margin:0; }
          .card { background:white; padding:24px; border-radius:8px; box-shadow:0 6px 18px rgba(0,0,0,0.08); max-width:420px; text-align:center;}
          button { background:#293C6E; color:white; border:none; padding:10px 16px; border-radius:6px; font-size:16px; cursor:pointer;}
        </style>
      </head>
      <body>
        <div class="card">
          <h2>Payment completed</h2>
          <p>You can safely close this window and return to the app.</p>
          <p>If your app needs to verify the payment, press "Return" to go back.</p>
          <div style="margin-top:16px;">
            <button id="closeBtn">Return</button>
          </div>
        </div>
        <script>
          document.getElementById('closeBtn').addEventListener('click', function(){
            try { window.close(); } catch (e) {}
            // fallback to about:blank
            location.href = 'about:blank';
          });
        </script>
      </body>
    </html>
    """
    return HTMLResponse(content=html, status_code=200)


@app.get("/order-status/{merchant_order_id}")
def order_status(merchant_order_id: str):
    res = supabase.table("orders").select("*").eq("merchant_order_id", merchant_order_id).execute()
    if not res.data:
        raise HTTPException(status_code=404, detail="Order not found")
    order = res.data[0]
    return {
        "merchant_order_id": order.get("merchant_order_id"),
        "status": order.get("status"),
        "transaction_id": order.get("phonepe_order_id"),
        "amount": order.get("amount")
    }

# --- Diagnostic endpoints (temporary) ---

DIAG_ENV_VAR = "DIAG_SECRET"  # set this env var on Render to a secret value

def _check_diag_key(x_diag: str | None):
    # simple header-based auth so only you can hit these endpoints
    import os
    expected = os.getenv(DIAG_ENV_VAR)
    if not expected:
        # if DIAG_SECRET is not set, refuse to run diagnostics
        raise HTTPException(status_code=403, detail="Diag disabled (no DIAG_SECRET set)")
    if x_diag != expected:
        raise HTTPException(status_code=401, detail="Invalid diag secret")
    return True

@app.get("/diag/packages")
def diag_packages(x_diag: str | None = Header(None)):
    _check_diag_key(x_diag)
    # report installed versions for key packages
    out = {}
    try:
        import pkg_resources
        for pkg in ("passlib", "bcrypt", "requests"):
            try:
                v = pkg_resources.get_distribution(pkg).version
            except Exception:
                v = None
            out[pkg] = v
    except Exception:
        out["error"] = "pkg_resources unavailable"
    return out

@app.get("/diag/bcrypt")
def diag_bcrypt(x_diag: str | None = Header(None)):
    _check_diag_key(x_diag)
    # attempt to import bcrypt and report the module file path (not the content)
    try:
        import bcrypt as _bcrypt
        path = getattr(_bcrypt, "__file__", None)
        return {"bcrypt_file": path}
    except Exception as e:
        return {"error": str(e)}

@app.get("/diag/phonepe-token-check")
def diag_phonepe_token(x_diag: str | None = Header(None)):
    _check_diag_key(x_diag)
    """
    Attempt a token fetch from PHONEPE_TOKEN_URL using configured env vars.
    DOES NOT return token values. Returns status code and keys present in JSON.
    """
    import os, requests
    token_url = os.getenv("PHONEPE_TOKEN_URL")
    client_id = os.getenv("PHONEPE_CLIENT_ID") or os.getenv("PHONEPE_MERCHANT_ID")
    client_secret = bool(os.getenv("PHONEPE_CLIENT_SECRET"))  # boolean only
    if not token_url:
        return {"error": "PHONEPE_TOKEN_URL not set in env"}
    if not client_id:
        return {"error": "PHONEPE_CLIENT_ID / PHONEPE_MERCHANT_ID missing"}
    # perform request, but do not include client_secret in log or return
    try:
        resp = requests.post(token_url, data={
            "client_id": client_id,
            "client_secret": os.getenv("PHONEPE_CLIENT_SECRET") or "",
            "client_version": os.getenv("PHONEPE_CLIENT_VERSION","1"),
            "grant_type": "client_credentials"
        }, timeout=15)
    except Exception as e:
        return {"error": f"token request failed: {str(e)}"}
    # parse body keys if JSON
    try:
        j = resp.json()
        keys = list(j.keys())
    except Exception:
        keys = None
    return {"status_code": resp.status_code, "json_keys": keys}
# --- end diagnostics ---




























































# # main.py
# from fastapi import FastAPI, HTTPException, Request, Query
# from fastapi.middleware.cors import CORSMiddleware
# from pydantic import BaseModel
# from supabase import create_client, Client
# from passlib.context import CryptContext
# from datetime import datetime
# from dotenv import load_dotenv
# import os

# load_dotenv()

# # -----------------------
# # Supabase client
# # -----------------------
# SUPABASE_URL = os.getenv("SUPABASE_URL")
# SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
# supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

# # -----------------------
# # Password hashing
# # -----------------------
# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# # -----------------------
# # FastAPI app
# # -----------------------
# app = FastAPI()
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# # ======================
# # Schemas
# # ======================
# class SendOTPRequest(BaseModel):
#     phone: str

# class VerifyOTPRequest(BaseModel):
#     name: str
#     phone: str
#     otp: str
#     password: str

# class UserLogin(BaseModel):
#     phone: str
#     password: str

# class AddVehicleRequest(BaseModel):
#     user_id: str
#     owner_name: str
#     car_brand: str
#     car_model: str
#     car_type: str
#     car_number: str

# class ParkingSlotBookRequest(BaseModel):
#     slot_id: int
#     vehicle_id: int
#     user_id: str

# class TokenPurchaseRequest(BaseModel):
#     service_type_id: int
#     user_id: str
#     token_count: int

# class ConsumeTokenRequest(BaseModel):
#     user_id: str
#     service_type_id: int
#     token_count: int
#     booking_date: str
#     slot_id: int | None = None

# class PaymentRequest(BaseModel):
#     booking_id: int
#     amount: int
#     user_id: str

# # ======================
# # Root
# # ======================
# @app.get("/")
# def root():
#     return {"message": "🚀 API Running"}

# # ======================
# # Auth APIs
# # ======================
# @app.post("/send-otp")
# def send_otp(data: SendOTPRequest):
#     # dummy OTP simulation
#     return {"message": f"OTP sent to +91{data.phone}", "otp": "1234"}

# @app.post("/signup")
# def signup(data: VerifyOTPRequest):
#     exists = supabase.table("users").select("*").eq("phone", data.phone).execute()
#     if exists.data:
#         raise HTTPException(status_code=400, detail="User already exists")
#     password_hash = pwd_context.hash(data.password)
#     res = supabase.table("users").insert({
#         "name": data.name,
#         "phone": data.phone,
#         "password_hash": password_hash,
#         "created_at": datetime.utcnow().isoformat()
#     }).execute()
#     user_id = res.data[0]["id"]
#     return {"message": "Signup successful", "user_id": user_id}

# @app.post("/login")
# def login(user: UserLogin):
#     res = supabase.table("users").select("*").eq("phone", user.phone).execute()
#     if not res.data:
#         raise HTTPException(status_code=401, detail="User not found")
#     db_user = res.data[0]
#     if not pwd_context.verify(user.password, db_user["password_hash"]):
#         raise HTTPException(status_code=401, detail="Incorrect password")
#     return {"message": f"Welcome {db_user['name']}", "user": db_user}

# # ======================
# # Vehicle APIs
# # ======================
# @app.post("/vehicles/add")
# def add_vehicle(data: AddVehicleRequest):
#     exists = supabase.table("vehicles").select("*").eq("car_number", data.car_number).execute()
#     if exists.data:
#         raise HTTPException(status_code=400, detail="Car number already registered")
#     res = supabase.table("vehicles").insert({
#         **data.model_dump(),
#         "created_at": datetime.utcnow().isoformat()
#     }).execute()
#     return {"message": "Vehicle added", "vehicle": res.data[0]}

# @app.get("/vehicles")
# def get_user_vehicles(user_id: str = Query(...)):
#     res = supabase.table("vehicles").select("*").eq("user_id", user_id).execute()
#     return res.data or []

# # ======================
# # Services & Tokens
# # ======================
# @app.get("/services")
# def get_services():
#     res = supabase.table("service_types").select("*").execute()
#     return res.data or []

# @app.post("/purchase-token")
# def purchase_token(data: TokenPurchaseRequest):
#     existing = supabase.table("purchased_tokens")\
#         .select("*")\
#         .eq("user_id", data.user_id)\
#         .eq("service_type_id", data.service_type_id)\
#         .execute()
#     if existing.data:
#         token_id = existing.data[0]["token_id"]
#         new_count = existing.data[0]["token_count"] + data.token_count
#         update_res = supabase.table("purchased_tokens")\
#             .update({"token_count": new_count, "updated_at": datetime.utcnow().isoformat()})\
#             .eq("token_id", token_id).execute()
#         return {"message": "Tokens updated successfully", "purchase": update_res.data[0]}
#     else:
#         insert_res = supabase.table("purchased_tokens").insert({
#             "user_id": data.user_id,
#             "service_type_id": data.service_type_id,
#             "token_count": data.token_count,
#             "created_at": datetime.utcnow().isoformat(),
#             "updated_at": datetime.utcnow().isoformat()
#         }).execute()
#         return {"message": "Purchase saved successfully", "purchase": insert_res.data[0]}

# @app.post("/consume-token")
# def consume_token(data: ConsumeTokenRequest):
#     purchased = supabase.table("purchased_tokens")\
#         .select("*")\
#         .eq("user_id", data.user_id)\
#         .eq("service_type_id", data.service_type_id)\
#         .order("created_at")\
#         .execute()
#     if not purchased.data:
#         raise HTTPException(status_code=404, detail="No tokens available")
#     remaining = data.token_count
#     for row in purchased.data:
#         available = row["token_count"]
#         use_count = min(available, remaining)
#         supabase.table("purchased_tokens").update({
#             "token_count": available - use_count,
#             "updated_at": datetime.utcnow().isoformat()
#         }).eq("token_id", row["token_id"]).execute()
#         remaining -= use_count
#         if remaining <= 0:
#             break
#     if remaining > 0:
#         raise HTTPException(status_code=400, detail="Insufficient tokens")
#     return {"message": "Token consumed successfully"}

# @app.get("/user-tokens")
# def get_user_tokens(user_id: str = Query(...), service_type_id: int = Query(...)):
#     response = supabase.table("purchased_tokens")\
#         .select("token_count")\
#         .eq("user_id", user_id)\
#         .eq("service_type_id", service_type_id)\
#         .execute()
#     total_tokens = sum(row.get("token_count", 0) for row in response.data or [])
#     return {"tokens": total_tokens}

# # ======================
# # Parking Slots
# # ======================
# @app.get("/parking-slots")
# def get_parking_slots(unit_id: int = Query(...)):
#     slots_data = supabase.table("parking_slots").select("*").eq("unit_id", unit_id).execute().data
#     total_slots = 30  # fallback, or fetch from DB
#     return {
#         "total_slots": total_slots,
#         "slots": slots_data or []
#     }

# @app.post("/parking-slots/book")
# def book_slot(data: ParkingSlotBookRequest):
#     slot = supabase.table("parking_slots").select("*")\
#         .eq("slot_id", data.slot_id).eq("status", "available").execute()
#     if not slot.data:
#         raise HTTPException(status_code=400, detail="Slot not available")
#     res = supabase.table("parking_slots").update({
#         "status": "occupied",
#         "current_vehicle_id": data.vehicle_id
#     }).eq("slot_id", data.slot_id).execute()
#     return {"message": "Slot booked", "slot": res.data[0]}

# # ======================
# # Dummy PhonePe Payment
# # ======================
# @app.post("/create-payment")
# def create_payment(data: PaymentRequest):
#     merchant_order_id = f"mock-{data.booking_id}-{int(datetime.utcnow().timestamp())}"
#     amount_paise = data.amount * 100
#     supabase.table("orders").insert({
#         "merchant_order_id": merchant_order_id,
#         "booking_id": data.booking_id,
#         "user_id": data.user_id,
#         "amount": amount_paise,
#         "status": "SUCCESS",
#         "phonepe_order_id": f"mock-{merchant_order_id}",
#         "created_at": datetime.utcnow().isoformat()
#     }).execute()
#     return {
#         "checkout_url": "https://example.com/mock-checkout",
#         "merchant_order_id": merchant_order_id,
#         "phonepe_order_id": f"mock-{merchant_order_id}",
#         "state": "SUCCESS"
#     }

# @app.post("/payment/callback")
# async def payment_callback(request: Request):
#     body = await request.json()
#     merchant_order_id = body.get("merchantTransactionId")
#     status = body.get("status")
#     supabase.table("orders").update({
#         "status": status,
#         "updated_at": datetime.utcnow().isoformat()
#     }).eq("merchant_order_id", merchant_order_id).execute()
#     return {"message": "Callback processed", "order_id": merchant_order_id, "status": status}

# @app.get("/payment-success")
# def payment_success():
#     return {"message": "✅ Payment successful. You may close this window."}

# @app.get("/order-status/{merchant_order_id}")
# def order_status(merchant_order_id: str):
#     res = supabase.table("orders").select("*").eq("merchant_order_id", merchant_order_id).execute()
#     if not res.data:
#         raise HTTPException(status_code=404, detail="Order not found")
#     order = res.data[0]
#     return {
#         "merchant_order_id": order["merchant_order_id"],
#         "status": order["status"],
#         "transaction_id": order.get("phonepe_order_id")
#     }



















# # main.py
# import os
# import re
# import json
# import logging
# from datetime import datetime
# from typing import Optional

# from fastapi import FastAPI, HTTPException, Request, Query
# from fastapi.middleware.cors import CORSMiddleware
# from pydantic import BaseModel
# from dotenv import load_dotenv
# from supabase import create_client, Client
# from passlib.context import CryptContext

# # local helper that calls PhonePe (must be present)
# from phonepe_client import create_checkout  # you already have this helper

# # Load environment
# load_dotenv()

# # -----------------------
# # Logging
# # -----------------------
# logger = logging.getLogger("uvicorn")
# logger.setLevel(logging.INFO)

# # -----------------------
# # Supabase client
# # -----------------------
# SUPABASE_URL = os.getenv("SUPABASE_URL")
# SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
# if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
#     raise RuntimeError("Set SUPABASE_URL and SUPABASE_SERVICE_KEY in environment")

# supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

# # -----------------------
# # Password hashing
# # -----------------------
# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# # -----------------------
# # FastAPI app
# # -----------------------
# app = FastAPI(title="Parkria Backend - PhonePe")
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],  # In production, replace with your frontend domain(s)
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# # -----------------------
# # Utilities
# # -----------------------
# def normalize_phone(p: Optional[str]) -> Optional[str]:
#     """Normalize phone: remove spaces, dashes, parentheses."""
#     if not p:
#         return p
#     s = p.strip()
#     s = re.sub(r"[ \-\(\)]", "", s)
#     return s

# def safe_supabase_data(resp):
#     """
#     Helper to get resp.data reliably from supabase-py responses.
#     The shape may vary by client versions.
#     """
#     if resp is None:
#         return None
#     # When using supabase-py, response object usually has .data
#     data = getattr(resp, "data", None)
#     if data is not None:
#         return data
#     # If dict-like
#     if isinstance(resp, dict) and "data" in resp:
#         return resp["data"]
#     return None

# # -----------------------
# # Schemas
# # -----------------------
# class SendOTPRequest(BaseModel):
#     phone: str

# class VerifyOTPRequest(BaseModel):
#     name: str
#     phone: str
#     otp: str
#     password: str

# class UserLogin(BaseModel):
#     phone: str
#     password: str

# class AddVehicleRequest(BaseModel):
#     user_id: str
#     owner_name: str
#     car_brand: str
#     car_model: str
#     car_type: str
#     car_number: str

# class ParkingSlotBookRequest(BaseModel):
#     slot_id: int
#     vehicle_id: int
#     user_id: str

# class TokenPurchaseRequest(BaseModel):
#     service_type_id: int
#     user_id: str
#     token_count: int

# class ConsumeTokenRequest(BaseModel):
#     user_id: str
#     service_type_id: int
#     token_count: int
#     booking_date: str
#     slot_id: Optional[int] = None

# class PaymentRequest(BaseModel):
#     booking_id: int
#     amount: int  # rupees as frontend sends
#     user_id: str

# # -----------------------
# # Root
# # -----------------------
# @app.get("/")
# def root():
#     return {"message": "🚀 Parkria API running"}

# # ======================
# # Auth APIs (signup/login) - improved + verbose
# # ======================
# @app.post("/send-otp")
# def send_otp(data: SendOTPRequest):
#     # Dummy OTP simulation — in production integrate SMS provider
#     phone = normalize_phone(data.phone)
#     logger.info("Send OTP requested for phone=%s", phone)
#     return {"message": f"OTP sent to +91{phone}", "otp": "1234"}

# @app.post("/signup")
# def signup(data: VerifyOTPRequest):
#     phone = normalize_phone(data.phone)
#     logger.info("Signup requested for phone=%s name=%s", phone, data.name)
#     if not phone:
#         raise HTTPException(status_code=400, detail="Phone is required")

#     # check existing user
#     try:
#         resp = supabase.table("users").select("*").eq("phone", phone).execute()
#         rows = safe_supabase_data(resp)
#         logger.info("Supabase signup select response: %s", str(rows))
#     except Exception as e:
#         logger.exception("Supabase select failed during signup")
#         raise HTTPException(status_code=500, detail=f"DB error: {e}")

#     if rows:
#         raise HTTPException(status_code=400, detail="User already exists")

#     # hash password and insert
#     try:
#         password_hash = pwd_context.hash(data.password)
#         insert = supabase.table("users").insert({
#             "name": data.name,
#             "phone": phone,
#             "password_hash": password_hash,
#             "created_at": datetime.utcnow().isoformat()
#         }).execute()
#         inserted = safe_supabase_data(insert)
#         logger.info("Supabase signup insert response: %s", str(inserted))
#     except Exception as e:
#         logger.exception("Supabase insert failed during signup")
#         raise HTTPException(status_code=500, detail=f"DB insert error: {e}")

#     # extract user id
#     try:
#         user_id = None
#         if isinstance(inserted, list) and len(inserted) > 0:
#             user_id = inserted[0].get("id")
#         elif isinstance(inserted, dict):
#             user_id = inserted.get("id")
#     except Exception:
#         user_id = None

#     return {"message": "Signup successful", "user_id": user_id}

# @app.post("/login")
# def login(user: UserLogin):
#     phone = normalize_phone(user.phone)
#     logger.info("Login attempt for phone=%s", phone)
#     if not phone or not user.password:
#         raise HTTPException(status_code=400, detail="Phone and password are required")

#     try:
#         resp = supabase.table("users").select("*").eq("phone", phone).execute()
#         rows = safe_supabase_data(resp)
#         logger.info("Supabase login select response: %s", str(rows))
#     except Exception as e:
#         logger.exception("Supabase select failed during login")
#         raise HTTPException(status_code=500, detail=f"DB error: {e}")

#     if not rows:
#         logger.warning("login failed - user not found for phone=%s", phone)
#         raise HTTPException(status_code=401, detail="User not found")

#     db_user = rows[0] if isinstance(rows, list) else rows
#     stored_hash = db_user.get("password_hash") or db_user.get("password")

#     if not stored_hash:
#         logger.error("login failed - no password_hash for user id=%s", db_user.get("id"))
#         raise HTTPException(status_code=500, detail="User record incomplete (no password hash)")

#     try:
#         verified = pwd_context.verify(user.password, stored_hash)
#     except Exception:
#         logger.exception("Error verifying password hash")
#         raise HTTPException(status_code=500, detail="Password verification error")

#     if not verified:
#         logger.warning("login failed - incorrect password for phone=%s", phone)
#         raise HTTPException(status_code=401, detail="Incorrect password")

#     safe_user = dict(db_user)
#     safe_user.pop("password_hash", None)
#     return {"message": f"Welcome {safe_user.get('name')}", "user": safe_user}

# # ======================
# # Vehicle APIs
# # ======================
# @app.post("/vehicles/add")
# def add_vehicle(data: AddVehicleRequest):
#     try:
#         exists_resp = supabase.table("vehicles").select("*").eq("car_number", data.car_number).execute()
#         exists = safe_supabase_data(exists_resp)
#     except Exception as e:
#         logger.exception("Supabase error checking vehicle exists")
#         raise HTTPException(status_code=500, detail=f"DB error: {e}")

#     if exists:
#         raise HTTPException(status_code=400, detail="Car number already registered")

#     try:
#         insert_resp = supabase.table("vehicles").insert({
#             "user_id": data.user_id,
#             "owner_name": data.owner_name,
#             "car_brand": data.car_brand,
#             "car_model": data.car_model,
#             "car_type": data.car_type,
#             "car_number": data.car_number,
#             "created_at": datetime.utcnow().isoformat()
#         }).execute()
#         inserted = safe_supabase_data(insert_resp)
#         return {"message": "Vehicle added", "vehicle": (inserted[0] if isinstance(inserted, list) else inserted)}
#     except Exception as e:
#         logger.exception("Supabase insert vehicle failed")
#         raise HTTPException(status_code=500, detail=f"DB error: {e}")

# @app.get("/vehicles")
# def get_user_vehicles(user_id: str = Query(...)):
#     try:
#         resp = supabase.table("vehicles").select("*").eq("user_id", user_id).order("vehicle_id").execute()
#         rows = safe_supabase_data(resp) or []
#         return rows
#     except Exception as e:
#         logger.exception("Supabase get vehicles failed")
#         raise HTTPException(status_code=500, detail=f"DB error: {e}")

# # ======================
# # Services & Tokens
# # ======================
# @app.get("/services")
# def get_services():
#     try:
#         resp = supabase.table("service_types").select("*").execute()
#         return safe_supabase_data(resp) or []
#     except Exception as e:
#         logger.exception("Supabase get services failed")
#         raise HTTPException(status_code=500, detail=f"DB error: {e}")

# @app.post("/purchase-token")
# def purchase_token(data: TokenPurchaseRequest):
#     try:
#         existing_resp = supabase.table("purchased_tokens")\
#             .select("*")\
#             .eq("user_id", data.user_id)\
#             .eq("service_type_id", data.service_type_id).execute()
#         existing = safe_supabase_data(existing_resp)
#     except Exception as e:
#         logger.exception("Supabase query failed")
#         raise HTTPException(status_code=500, detail=f"DB error: {e}")

#     try:
#         if existing:
#             token_id = existing[0]["token_id"]
#             new_count = existing[0]["token_count"] + data.token_count
#             update_resp = supabase.table("purchased_tokens")\
#                 .update({"token_count": new_count, "updated_at": datetime.utcnow().isoformat()})\
#                 .eq("token_id", token_id).execute()
#             return {"message": "Tokens updated successfully", "purchase": (safe_supabase_data(update_resp) or [])}
#         else:
#             insert_resp = supabase.table("purchased_tokens").insert({
#                 "user_id": data.user_id,
#                 "service_type_id": data.service_type_id,
#                 "token_count": data.token_count,
#                 "created_at": datetime.utcnow().isoformat(),
#                 "updated_at": datetime.utcnow().isoformat()
#             }).execute()
#             return {"message": "Purchase saved successfully", "purchase": (safe_supabase_data(insert_resp) or [])}
#     except Exception as e:
#         logger.exception("Supabase insert/update failed for purchased_tokens")
#         raise HTTPException(status_code=500, detail=f"DB error: {e}")

# @app.post("/consume-token")
# def consume_token(data: ConsumeTokenRequest):
#     try:
#         purchased_resp = supabase.table("purchased_tokens")\
#             .select("*")\
#             .eq("user_id", data.user_id)\
#             .eq("service_type_id", data.service_type_id)\
#             .order("created_at").execute()
#         purchased = safe_supabase_data(purchased_resp) or []
#     except Exception as e:
#         logger.exception("Supabase query failed for consume token")
#         raise HTTPException(status_code=500, detail=f"DB error: {e}")

#     if not purchased:
#         raise HTTPException(status_code=404, detail="No tokens available")

#     remaining = data.token_count
#     try:
#         for row in purchased:
#             available = row.get("token_count", 0)
#             use_count = min(available, remaining)
#             supabase.table("purchased_tokens").update({
#                 "token_count": available - use_count,
#                 "updated_at": datetime.utcnow().isoformat()
#             }).eq("token_id", row["token_id"]).execute()
#             remaining -= use_count
#             if remaining <= 0:
#                 break
#         if remaining > 0:
#             raise HTTPException(status_code=400, detail="Insufficient tokens")
#         return {"message": "Token consumed successfully"}
#     except HTTPException:
#         raise
#     except Exception as e:
#         logger.exception("Error while consuming tokens")
#         raise HTTPException(status_code=500, detail=f"DB error: {e}")

# @app.get("/user-tokens")
# def get_user_tokens(user_id: str = Query(...), service_type_id: int = Query(...)):
#     try:
#         response = supabase.table("purchased_tokens")\
#             .select("token_count")\
#             .eq("user_id", user_id)\
#             .eq("service_type_id", service_type_id).execute()
#         rows = safe_supabase_data(response) or []
#         total_tokens = sum(row.get("token_count", 0) for row in rows)
#         return {"tokens": total_tokens}
#     except Exception as e:
#         logger.exception("Supabase user-tokens query failed")
#         raise HTTPException(status_code=500, detail=f"DB error: {e}")

# # ======================
# # Parking Slots
# # ======================
# @app.get("/parking-slots")
# def get_parking_slots(unit_id: int = Query(...)):
#     try:
#         slots_resp = supabase.table("parking_slots").select("*").eq("unit_id", unit_id).execute()
#         slots_data = safe_supabase_data(slots_resp) or []
#     except Exception as e:
#         logger.exception("Supabase parking_slots query failed")
#         raise HTTPException(status_code=500, detail=f"DB error: {e}")

#     # fallback total_slots
#     total_slots = 30
#     try:
#         unit_resp = supabase.table("parking_units").select("no_of_slots").eq("unit_id", unit_id).maybe_single().execute()
#         unit_data = safe_supabase_data(unit_resp)
#         if unit_data:
#             if isinstance(unit_data, dict):
#                 total_slots = unit_data.get("no_of_slots", total_slots)
#             elif isinstance(unit_data, list) and len(unit_data) > 0:
#                 total_slots = unit_data[0].get("no_of_slots", total_slots)
#     except Exception:
#         # ignore; keep fallback
#         pass

#     return {"total_slots": total_slots, "slots": slots_data}

# @app.post("/parking-slots/book")
# def book_slot(data: ParkingSlotBookRequest):
#     try:
#         slot_resp = supabase.table("parking_slots").select("*")\
#             .eq("slot_id", data.slot_id).eq("status", "available").execute()
#         slot_rows = safe_supabase_data(slot_resp)
#     except Exception as e:
#         logger.exception("Supabase query failed for booking slot")
#         raise HTTPException(status_code=500, detail=f"DB error: {e}")

#     if not slot_rows:
#         raise HTTPException(status_code=400, detail="Slot not available")

#     try:
#         update_resp = supabase.table("parking_slots").update({
#             "status": "occupied",
#             "current_vehicle_id": data.vehicle_id,
#             "updated_at": datetime.utcnow().isoformat()
#         }).eq("slot_id", data.slot_id).execute()
#         updated = safe_supabase_data(update_resp)
#         return {"message": "Slot booked", "slot": (updated[0] if isinstance(updated, list) else updated)}
#     except Exception as e:
#         logger.exception("Supabase update failed for booking slot")
#         raise HTTPException(status_code=500, detail=f"DB error: {e}")

# # ======================
# # Payment / Orders (PhonePe)
# # ======================
# @app.post("/create-payment")
# def create_payment(req: PaymentRequest):
#     """
#     Called by Flutter app.
#     Steps:
#       - build merchant_order_id
#       - call PhonePe create checkout (via phonepe_client.create_checkout)
#       - save order row in supabase 'orders' table (merchant_order_id unique)
#       - return checkout_url & merchant_order_id to client
#     """
#     if req.amount <= 0:
#         raise HTTPException(status_code=400, detail="Invalid amount")

#     merchant_order_id = f"ord-{req.booking_id}-{int(datetime.utcnow().timestamp())}"
#     amount_paise = int(req.amount) * 100

#     try:
#         logger.info(f"Creating checkout: merchant_order_id={merchant_order_id} amount_paise={amount_paise}")
#         phonepe_resp = create_checkout(merchant_order_id=merchant_order_id,
#                                        amount_paise=amount_paise,
#                                        booking_id=req.booking_id,
#                                        user_id=req.user_id)
#         logger.info("PhonePe create_checkout response: %s", json.dumps(phonepe_resp))
#     except Exception as e:
#         logger.exception("PhonePe create_checkout failed")
#         raise HTTPException(status_code=500, detail=f"PhonePe error: {e}")

#     # PhonePe response may contain redirectUrl and orderId in different places
#     redirect_url = phonepe_resp.get("redirectUrl") or (phonepe_resp.get("data") or {}).get("redirectUrl")
#     phonepe_order_id = phonepe_resp.get("orderId") or (phonepe_resp.get("data") or {}).get("orderId")
#     state = phonepe_resp.get("state") or (phonepe_resp.get("data") or {}).get("state") or "PENDING"

#     # Persist order in Supabase
#     try:
#         supabase.table("orders").insert({
#             "merchant_order_id": merchant_order_id,
#             "booking_id": req.booking_id,
#             "user_id": req.user_id,
#             "amount": amount_paise,
#             "status": state,
#             "phonepe_order_id": phonepe_order_id,
#             "created_at": datetime.utcnow().isoformat()
#         }).execute()
#     except Exception as e:
#         logger.exception("Supabase insert orders failed")
#         # still return checkout_url so client can proceed — manual reconciliation may be needed
#         return {
#             "checkout_url": redirect_url,
#             "merchant_order_id": merchant_order_id,
#             "phonepe_order_id": phonepe_order_id,
#             "state": state,
#             "warning": f"Saved to DB failed: {e}"
#         }

#     return {
#         "checkout_url": redirect_url,
#         "merchant_order_id": merchant_order_id,
#         "phonepe_order_id": phonepe_order_id,
#         "state": state
#     }

# @app.post("/payment/callback")
# async def payment_callback(req: Request):
#     """
#     PhonePe server-to-server callback. PhonePe will POST details here.
#     IMPORTANT: In production, verify incoming signature/X-VERIFY per PhonePe docs.
#     """
#     raw = await req.body()
#     try:
#         payload = await req.json()
#     except Exception:
#         payload = {"raw": raw.decode("utf-8", errors="ignore") if raw else ""}

#     logger.info("PhonePe callback received: %s", str(payload))

#     # Attempt to extract merchant identifiers & status
#     merchant_order_id = payload.get("merchantTransactionId") or payload.get("merchantOrderId") or payload.get("merchant_order_id")
#     status = payload.get("status") or payload.get("state") or payload.get("payment_state")

#     # also check nested data block
#     data_block = payload.get("data") if isinstance(payload.get("data"), dict) else None
#     if not merchant_order_id and data_block:
#         merchant_order_id = data_block.get("merchantTransactionId") or data_block.get("merchantOrderId")
#         status = status or data_block.get("state") or data_block.get("status")

#     if merchant_order_id:
#         try:
#             supabase.table("orders").update({
#                 "status": status,
#                 "updated_at": datetime.utcnow().isoformat()
#             }).eq("merchant_order_id", merchant_order_id).execute()
#         except Exception as e:
#             logger.exception("Failed updating order status in supabase")
#             return {"message": "callback received; db update failed", "error": str(e)}

#         return {"message": "callback processed", "merchant_order_id": merchant_order_id, "status": status}
#     else:
#         logger.warning("Callback missing merchant_order_id: %s", str(payload))
#         return {"message": "callback received but merchant id missing", "body": payload}

# @app.get("/payment-success")
# def payment_success():
#     # Browser redirect target after payment — PhonePe will redirect user here.
#     return {"message": "Payment completed. You can safely close this window."}

# @app.get("/order-status/{merchant_order_id}")
# def order_status(merchant_order_id: str):
#     try:
#         res = supabase.table("orders").select("*").eq("merchant_order_id", merchant_order_id).execute()
#         rows = safe_supabase_data(res)
#     except Exception as e:
#         logger.exception("Supabase order-status query failed")
#         raise HTTPException(status_code=500, detail=f"DB error: {e}")

#     if not rows:
#         raise HTTPException(status_code=404, detail="Order not found")
#     order = rows[0] if isinstance(rows, list) else rows
#     return {
#         "merchant_order_id": order.get("merchant_order_id"),
#         "status": order.get("status"),
#         "transaction_id": order.get("phonepe_order_id"),
#         "amount": order.get("amount")
#     }














# # main.py
# import os
# from pathlib import Path
# import logging

# # load dotenv explicitly before importing modules that read env
# from dotenv import load_dotenv

# # ensure .env located next to this file is loaded (robust even if working dir differs)
# env_path = Path(__file__).resolve().parent / ".env"
# load_dotenv(env_path)

# # safe boolean checks only (DO NOT print secret values)
# logger = logging.getLogger("uvicorn.error")
# logger.setLevel(logging.INFO)
# logger.info("ENV CHECK - SUPABASE_URL present: %s", bool(os.getenv("SUPABASE_URL")))
# logger.info("ENV CHECK - SUPABASE_SERVICE_KEY present: %s", bool(os.getenv("SUPABASE_SERVICE_KEY")))
# logger.info("ENV CHECK - PHONEPE_MERCHANT_ID present: %s", bool(os.getenv("PHONEPE_MERCHANT_ID")))
# logger.info("ENV CHECK - PHONEPE_CLIENT_SECRET present: %s", bool(os.getenv("PHONEPE_CLIENT_SECRET")))
# logger.info("ENV CHECK - PHONEPE_ENV present: %s", bool(os.getenv("PHONEPE_ENV")))

# # now safe to import app dependencies that may read env
# from fastapi import FastAPI, HTTPException, Request, Query
# from fastapi import Response
# from fastapi.responses import HTMLResponse
# from fastapi.middleware.cors import CORSMiddleware
# from pydantic import BaseModel
# from datetime import datetime
# from supabase import create_client, Client

# # password hashing for signup/login
# from passlib.context import CryptContext

# # local phonepe helper (import after env loaded)
# # phonepe_client should implement token handling and environment selection (sandbox/prod)
# from phonepe_client import create_checkout  # ensure you replaced phonepe_client.py with the improved version

# # -----------------------
# # Supabase client
# # -----------------------
# SUPABASE_URL = os.getenv("SUPABASE_URL")
# SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
# if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
#     raise RuntimeError("Set SUPABASE_URL and SUPABASE_SERVICE_KEY in environment")

# supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

# # -----------------------
# # FastAPI
# # -----------------------
# app = FastAPI(title="Parkria Backend - PhonePe")
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],  # restrict in production
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# # -----------------------
# # Password hashing
# # -----------------------
# pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# # ======================
# # Schemas
# # ======================
# class SendOTPRequest(BaseModel):
#     phone: str

# class VerifyOTPRequest(BaseModel):
#     name: str
#     phone: str
#     otp: str
#     password: str

# class UserLogin(BaseModel):
#     phone: str
#     password: str

# class AddVehicleRequest(BaseModel):
#     user_id: str
#     owner_name: str
#     car_brand: str
#     car_model: str
#     car_type: str
#     car_number: str

# class ParkingSlotBookRequest(BaseModel):
#     slot_id: int
#     vehicle_id: int
#     user_id: str

# class TokenPurchaseRequest(BaseModel):
#     service_type_id: int
#     user_id: str
#     token_count: int

# class ConsumeTokenRequest(BaseModel):
#     user_id: str
#     service_type_id: int
#     token_count: int
#     booking_date: str
#     slot_id: int | None = None

# class PaymentRequest(BaseModel):
#     booking_id: int
#     amount: int
#     user_id: str



# @app.middleware("http")
# async def add_security_headers(request, call_next):
#     response: Response = await call_next(request)
#     response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
#     response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
#     return response

# # ======================
# # Root
# # ======================
# @app.get("/")
# def root():
#     return {"message": "🚀 API Running"}

# # ======================
# # Auth APIs
# # ======================
# @app.post("/send-otp")
# def send_otp(data: SendOTPRequest):
#     # dummy OTP simulation (replace with SMS provider in prod)
#     return {"message": f"OTP sent to +91{data.phone}", "otp": "1234"}

# @app.post("/signup")
# def signup(data: VerifyOTPRequest):
#     exists = supabase.table("users").select("*").eq("phone", data.phone).execute()
#     if exists.data:
#         raise HTTPException(status_code=400, detail="User already exists")
#     password_hash = pwd_context.hash(data.password)
#     res = supabase.table("users").insert({
#         "name": data.name,
#         "phone": data.phone,
#         "password_hash": password_hash,
#         "created_at": datetime.utcnow().isoformat()
#     }).execute()
#     user_id = res.data[0]["id"]
#     return {"message": "Signup successful", "user_id": user_id}

# @app.post("/login")
# def login(user: UserLogin):
#     res = supabase.table("users").select("*").eq("phone", user.phone).execute()
#     if not res.data:
#         raise HTTPException(status_code=401, detail="User not found")
#     db_user = res.data[0]
#     if not pwd_context.verify(user.password, db_user["password_hash"]):
#         raise HTTPException(status_code=401, detail="Incorrect password")
#     # return user info (careful with password_hash)
#     return {"message": f"Welcome {db_user.get('name')}", "user": {k:v for k,v in db_user.items() if k!="password_hash"}}

# # ======================
# # Vehicle APIs
# # ======================
# @app.post("/vehicles/add")
# def add_vehicle(data: AddVehicleRequest):
#     exists = supabase.table("vehicles").select("*").eq("car_number", data.car_number).execute()
#     if exists.data:
#         raise HTTPException(status_code=400, detail="Car number already registered")
#     res = supabase.table("vehicles").insert({
#         "user_id": data.user_id,
#         "owner_name": data.owner_name,
#         "car_brand": data.car_brand,
#         "car_model": data.car_model,
#         "car_type": data.car_type,
#         "car_number": data.car_number,
#         "created_at": datetime.utcnow().isoformat()
#     }).execute()
#     return {"message": "Vehicle added", "vehicle": res.data[0]}

# @app.get("/vehicles")
# def get_user_vehicles(user_id: str = Query(...)):
#     res = supabase.table("vehicles").select("vehicle_id, car_number").eq("user_id", user_id).order("vehicle_id").execute()
#     return res.data or []

# # ======================
# # Services & Tokens
# # ======================
# @app.get("/services")
# def get_services():
#     res = supabase.table("service_types").select("*").execute()
#     return res.data or []

# @app.post("/purchase-token")
# def purchase_token(data: TokenPurchaseRequest):
#     existing = supabase.table("purchased_tokens")\
#         .select("*")\
#         .eq("user_id", data.user_id)\
#         .eq("service_type_id", data.service_type_id)\
#         .execute()
#     if existing.data:
#         token_id = existing.data[0]["token_id"]
#         new_count = existing.data[0]["token_count"] + data.token_count
#         update_res = supabase.table("purchased_tokens")\
#             .update({"token_count": new_count, "updated_at": datetime.utcnow().isoformat()})\
#             .eq("token_id", token_id).execute()
#         return {"message": "Tokens updated successfully", "purchase": update_res.data[0]}
#     else:
#         insert_res = supabase.table("purchased_tokens").insert({
#             "user_id": data.user_id,
#             "service_type_id": data.service_type_id,
#             "token_count": data.token_count,
#             "created_at": datetime.utcnow().isoformat(),
#             "updated_at": datetime.utcnow().isoformat()
#         }).execute()
#         return {"message": "Purchase saved successfully", "purchase": insert_res.data[0]}

# @app.post("/consume-token")
# def consume_token(data: ConsumeTokenRequest):
#     purchased = supabase.table("purchased_tokens")\
#         .select("*")\
#         .eq("user_id", data.user_id)\
#         .eq("service_type_id", data.service_type_id)\
#         .order("created_at")\
#         .execute()
#     if not purchased.data:
#         raise HTTPException(status_code=404, detail="No tokens available")
#     remaining = data.token_count
#     for row in purchased.data:
#         available = row["token_count"]
#         use_count = min(available, remaining)
#         supabase.table("purchased_tokens").update({
#             "token_count": available - use_count,
#             "updated_at": datetime.utcnow().isoformat()
#         }).eq("token_id", row["token_id"]).execute()
#         remaining -= use_count
#         if remaining <= 0:
#             break
#     if remaining > 0:
#         raise HTTPException(status_code=400, detail="Insufficient tokens")
#     return {"message": "Token consumed successfully"}

# @app.get("/user-tokens")
# def get_user_tokens(user_id: str = Query(...), service_type_id: int = Query(...)):
#     response = supabase.table("purchased_tokens")\
#         .select("token_count")\
#         .eq("user_id", user_id)\
#         .eq("service_type_id", service_type_id)\
#         .execute()
#     total_tokens = sum(row.get("token_count", 0) for row in response.data or [])
#     return {"tokens": total_tokens}

# # ======================
# # Parking Slots
# # ======================
# @app.get("/parking-slots")
# def get_parking_slots(unit_id: int = Query(...)):
#     slots_data = supabase.table("parking_slots").select("*").eq("unit_id", unit_id).execute().data
#     total_slots = 30  # fallback, or fetch from DB
#     return {
#         "total_slots": total_slots,
#         "slots": slots_data or []
#     }

# @app.post("/parking-slots/book")
# def book_slot(data: ParkingSlotBookRequest):
#     slot = supabase.table("parking_slots").select("*")\
#         .eq("slot_id", data.slot_id).eq("status", "available").execute()
#     if not slot.data:
#         raise HTTPException(status_code=400, detail="Slot not available")
#     res = supabase.table("parking_slots").update({
#         "status": "occupied",
#         "current_vehicle_id": data.vehicle_id,
#         "updated_at": datetime.utcnow().isoformat()
#     }).eq("slot_id", data.slot_id).execute()
#     return {"message": "Slot booked", "slot": res.data[0]}

# # ======================
# # Orders / PhonePe integration
# # ======================
# @app.post("/create-payment")
# def create_payment(req: PaymentRequest):
#     # coerce + validate amount
#     try:
#         amount_val = float(req.amount)
#     except Exception:
#         raise HTTPException(status_code=422, detail="Invalid 'amount' — must be numeric")
#     if amount_val <= 0:
#         raise HTTPException(status_code=400, detail="Invalid amount; must be > 0")

#     # merchant_order_id must be unique per attempt - include timestamp
#     merchant_order_id = f"ord-{req.booking_id}-{int(datetime.utcnow().timestamp())}"
#     amount_paise = int(round(amount_val * 100))

#     # coerce user_id to string; if your DB expects UUID ensure frontend sends a proper UUID.
#     user_id_str = str(req.user_id)

#     # basic heuristic to detect obviously-bad user ids (avoid common DB insertion failures)
#     if len(user_id_str) < 6:
#         logger.warning("Received suspiciously short user_id; ensure frontend sends user UUID or valid id: %s", user_id_str)

#     logger.info("Creating checkout: merchant_order_id=%s amount_paise=%s user_id=%s", merchant_order_id, amount_paise, user_id_str)
#     try:
#         phonepe_resp = create_checkout(
#             merchant_order_id=merchant_order_id,
#             amount_paise=amount_paise,
#             booking_id=req.booking_id,
#             user_id=user_id_str,
#         )
#     except Exception as e:
#         logger.exception("PhonePe create_checkout failed")
#         # Return helpful message for frontend to display
#         raise HTTPException(status_code=502, detail=f"PhonePe error: {e}")

#     # PhonePe sometimes returns values at top level or under 'data'
#     redirect_url = None
#     phonepe_order_id = None
#     state = "PENDING"

#     if isinstance(phonepe_resp, dict):
#         redirect_url = phonepe_resp.get("redirectUrl") or (phonepe_resp.get("data") or {}).get("redirectUrl")
#         phonepe_order_id = phonepe_resp.get("orderId") or (phonepe_resp.get("data") or {}).get("orderId")
#         state = phonepe_resp.get("state") or (phonepe_resp.get("data") or {}).get("state") or state

#     logger.info("PhonePe response parsed redirect_url=%s order_id=%s state=%s", redirect_url, phonepe_order_id, state)

#     # Save order to DB. If DB write fails (e.g. invalid UUID) return checkout_url but include warning.
#     try:
#         supabase.table("orders").insert({
#             "merchant_order_id": merchant_order_id,
#             "booking_id": req.booking_id,
#             "user_id": user_id_str,
#             "amount": amount_paise,
#             "status": state,
#             "phonepe_order_id": phonepe_order_id,
#             "created_at": datetime.utcnow().isoformat()
#         }).execute()
#     except Exception as e:
#         # log and return successful response but with warning (so frontend can still open PayPage)
#         logger.exception("Supabase insert orders failed")
#         return {
#             "checkout_url": redirect_url,
#             "merchant_order_id": merchant_order_id,
#             "phonepe_order_id": phonepe_order_id,
#             "state": state,
#             "warning": f"Saved to DB failed: {e}"
#         }

#     return {
#         "checkout_url": redirect_url,
#         "merchant_order_id": merchant_order_id,
#         "phonepe_order_id": phonepe_order_id,
#         "state": state
#     }


# @app.post("/payment/callback")
# async def payment_callback(req: Request):
#     """
#     PhonePe server-to-server callback. PhonePe will POST details here.
#     IMPORTANT: For production, verify incoming signature/X-VERIFY per PhonePe docs.
#     """
#     raw = await req.body()
#     try:
#         payload = await req.json()
#     except Exception:
#         payload = {"raw": raw.decode("utf-8", errors="ignore") if raw else ""}

#     logger.info("PhonePe callback received: %s", payload)

#     # attempt to extract merchantOrderId / merchantTransactionId and status/state
#     merchant_order_id = payload.get("merchantTransactionId") or payload.get("merchantOrderId") or payload.get("merchant_order_id")
#     status = payload.get("status") or payload.get("state") or payload.get("payment_state")

#     # also check nested data block
#     data_block = payload.get("data") if isinstance(payload.get("data"), dict) else None
#     if not merchant_order_id and data_block:
#         merchant_order_id = data_block.get("merchantTransactionId") or data_block.get("merchantOrderId")
#         status = status or data_block.get("state") or data_block.get("status")

#     if merchant_order_id:
#         try:
#             supabase.table("orders").update({
#                 "status": status,
#                 "updated_at": datetime.utcnow().isoformat()
#             }).eq("merchant_order_id", merchant_order_id).execute()
#         except Exception as e:
#             logger.exception("Failed updating order status in supabase")
#             return {"message": "callback received; db update failed", "error": str(e)}

#         return {"message": "callback processed", "merchant_order_id": merchant_order_id, "status": status}
#     else:
#         logger.warning("Callback missing merchant_order_id: %s", payload)
#         return {"message": "callback received but merchant id missing", "body": payload}


# @app.get("/payment-success")
# def payment_success():
#     html = """
#     <!doctype html>
#     <html>
#       <head><meta charset="utf-8"/><title>Payment Completed</title></head>
#       <body style="font-family: Arial, sans-serif; display:flex;align-items:center;justify-content:center;height:100vh;background:#f7fafc;">
#         <div style="background:white;padding:24px;border-radius:8px;box-shadow:0 6px 18px rgba(0,0,0,0.08);max-width:480px;text-align:center;">
#           <h2>Payment completed</h2>
#           <p>You can safely close this window and return to the app.</p>
#           <p>If your app needs confirmation, tap the button to return.</p>
#           <button onclick="try{ window.close(); }catch(e){ location.href='about:blank'; }" style="margin-top:16px;padding:10px 16px;background:#293C6E;color:white;border:none;border-radius:6px;cursor:pointer;">Return</button>
#         </div>
#       </body>
#     </html>
#     """
#     return HTMLResponse(content=html, status_code=200)


# @app.get("/order-status/{merchant_order_id}")
# def order_status(merchant_order_id: str):
#     res = supabase.table("orders").select("*").eq("merchant_order_id", merchant_order_id).execute()
#     if not res.data:
#         raise HTTPException(status_code=404, detail="Order not found")
#     order = res.data[0]
#     return {
#         "merchant_order_id": order.get("merchant_order_id"),
#         "status": order.get("status"),
#         "transaction_id": order.get("phonepe_order_id"),
#         "amount": order.get("amount")
#     }

