import os
from pathlib import Path
import logging
import hmac
import hashlib
from datetime import datetime

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, Query, Header, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from supabase import create_client, Client
from passlib.context import CryptContext

import razorpay

if not RAZORPAY_KEY_ID or not RAZORPAY_KEY_SECRET:
    raise RuntimeError("Set RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET")

razorpay_client = razorpay.Client(
    auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET)
)


# from phonepe_client import create_order, order_status as phonepe_order_status, token_info as phonepe_token_info

env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(env_path)

logger = logging.getLogger("uvicorn.error")
logger.setLevel(logging.INFO)
logger.info("ENV CHECK - SUPABASE_URL present: %s", bool(os.getenv("SUPABASE_URL")))
logger.info("ENV CHECK - SUPABASE_SERVICE_KEY present: %s", bool(os.getenv("SUPABASE_SERVICE_KEY")))
RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET")
class VerifyPaymentRequest(BaseModel):
    razorpay_order_id: str
    razorpay_payment_id: str
    razorpay_signature: str


SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
    raise RuntimeError("Set SUPABASE_URL and SUPABASE_SERVICE_KEY in environment")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    return response

pwd_context = CryptContext(
    schemes=["bcrypt_sha256", "bcrypt"],  # support both, just in case
    deprecated="auto",
)

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

class VerifyPaymentRequest(BaseModel):
    razorpay_order_id: str
    razorpay_payment_id: str
    razorpay_signature: str


# def verify_phonepe_signature(raw_body: bytes, signature_header: str | None) -> bool:
#     secret = os.getenv("PHONEPE_CLIENT_SECRET")
#     if not secret:
#         logger.warning("PHONEPE_CLIENT_SECRET not configured; skipping signature verification (unsafe!).")
#         return False

#     if not signature_header:
#         logger.warning("No signature header present on callback")
#         return False

#     try:
#         computed = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
#         return hmac.compare_digest(computed.lower(), signature_header.lower())
#     except Exception as e:
#         logger.exception("Failed verifying signature: %s", e)
#         return False

@app.get("/")
def root():
    return {"message": "🚀 API Running"}

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
        # Don't leak which part is wrong; generic error is better
        raise HTTPException(status_code=401, detail="Invalid phone or password")

    db_user = res.data[0]
    stored_hash = db_user.get("password_hash")

    if not stored_hash:
        logger.warning("User %s has no password_hash stored", db_user.get("id"))
        raise HTTPException(status_code=401, detail="Invalid phone or password")

    try:
        is_valid = pwd_context.verify(user.password, stored_hash)
    except UnknownHashError:
        # Hash format in DB is invalid / unknown
        logger.warning(
            "Unknown password hash format for user_id=%s: %r",
            db_user.get("id"),
            stored_hash if isinstance(stored_hash, str) else type(stored_hash),
        )
        raise HTTPException(status_code=401, detail="Invalid phone or password")

    if not is_valid:
        raise HTTPException(status_code=401, detail="Invalid phone or password")

    sanitized_user = {k: v for k, v in db_user.items() if k != "password_hash"}
    return {"message": f"Welcome {db_user.get('name')}", "user": sanitized_user}


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
    total_slots = 30
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

@app.post("/create-payment")
def create_payment(req: PaymentRequest):
    order = razorpay_client.order.create({
        "amount": req.amount * 100,
        "currency": "INR",
        "receipt": f"booking_{req.booking_id}",
        "payment_capture": 1
    })

    merchant_order_id = f"rzp-{req.booking_id}-{int(datetime.utcnow().timestamp())}"

    supabase.table("orders").insert({
        "merchant_order_id": merchant_order_id,
        "booking_id": req.booking_id,
        "user_id": req.user_id,
        "amount": req.amount * 100,
        "status": "CREATED",
        "razorpay_order_id": order["id"]
    }).execute()

    return {
        "razorpay_key": RAZORPAY_KEY_ID,
        "order_id": order["id"],
        "merchant_order_id": merchant_order_id,
        "amount": req.amount * 100,
        "currency": "INR"
    }


@app.post("/verify-payment")
def verify_payment(req: VerifyPaymentRequest):
    body = f"{req.razorpay_order_id}|{req.razorpay_payment_id}"

    expected = hmac.new(
        RAZORPAY_KEY_SECRET.encode(),
        body.encode(),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected, req.razorpay_signature):
        raise HTTPException(400, "Invalid payment signature")

    supabase.table("orders").update({
        "status": "PAID",
        "updated_at": datetime.utcnow().isoformat()
    }).eq("razorpay_order_id", req.razorpay_order_id).execute()

    return {"status": "success"}




# @app.post("/payment/callback")
# async def payment_callback(req: Request, x_phonepe_signature: str | None = Header(None)):
#     raw = await req.body()

#     if not verify_phonepe_signature(raw, x_phonepe_signature):
#         logger.warning("PhonePe callback signature verification failed")
#         raise HTTPException(status_code=401, detail="Invalid signature")

#     try:
#         payload = await req.json()
#     except Exception:
#         payload = {"raw": raw.decode("utf-8", errors="ignore") if raw else ""}

#     logger.info("PhonePe callback received (verified): %s", payload)

#     merchant_order_id = payload.get("merchantTransactionId") or payload.get("merchantOrderId") or payload.get("merchant_order_id")
#     status = payload.get("status") or payload.get("state") or payload.get("payment_state")

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
#             return JSONResponse({"message": "callback received; db update failed", "error": str(e)}, status_code=500)

#         return {"message": "callback processed", "merchant_order_id": merchant_order_id, "status": status}
#     else:
#         logger.warning("Callback missing merchant_order_id: %s", payload)
#         return {"message": "callback received but merchant id missing", "body": payload}

@app.get("/payment-success")
def payment_success():
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
            location.href = 'about:blank';
          });
        </script>
      </body>
    </html>
    """
    return HTMLResponse(content=html, status_code=200)

@app.get("/order-status/{razorpay_order_id}")
def order_status(razorpay_order_id: str):
    res = supabase.table("orders").select("*").eq(
        "razorpay_order_id", razorpay_order_id
    ).execute()

    if not res.data:
        raise HTTPException(404, "Order not found")

    return res.data[0]

DIAG_ENV_VAR = "DIAG_SECRET"

def _check_diag_key(x_diag: str | None):
    expected = os.getenv(DIAG_ENV_VAR)
    if not expected:
        raise HTTPException(status_code=403, detail="Diag disabled (no DIAG_SECRET set)")
    if x_diag != expected:
        raise HTTPException(status_code=401, detail="Invalid diag secret")
    return True

@app.get("/diag/packages")
def diag_packages(x_diag: str | None = Header(None)):
    _check_diag_key(x_diag)
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
    try:
        import bcrypt as _bcrypt
        path = getattr(_bcrypt, "__file__", None)
        return {"bcrypt_file": path}
    except Exception as e:
        return {"error": str(e)}

# @app.get("/diag/phonepe-token-check")
# def diag_phonepe_token(x_diag: str | None = Header(None)):
#     _check_diag_key(x_diag)
#     try:
#         info = phonepe_token_info()
#     except Exception as e:
#         logger.exception("phonepe_token_info failed")
#         return {"error": str(e)}
#     return info


from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
# from payment_gateway import (
#     create_razorpay_order,
#     verify_razorpay_payment
# )

# app = FastAPI()

# -------------------------------
# REQUEST MODELS
# -------------------------------

# class CreateOrderRequest(BaseModel):
#     amount: int  # paise


# class VerifyPaymentRequest(BaseModel):
#     razorpay_order_id: str
#     razorpay_payment_id: str
#     razorpay_signature: str


# -------------------------------
# API ENDPOINTS
# -------------------------------

# @app.post("/payment/razorpay/create-order")
# def create_order(data: CreateOrderRequest):
#     return create_razorpay_order(data.amount)


# @app.post("/payment/razorpay/verify")
# def verify_payment(data: VerifyPaymentRequest):
#     valid = verify_razorpay_payment(
#         data.razorpay_order_id,
#         data.razorpay_payment_id,
#         data.razorpay_signature
#     )

#     if not valid:
#         raise HTTPException(status_code=400, detail="Invalid payment")

#     # ✅ Save booking + payment here

#     return {"status": "success"}









































































# import os
# from pathlib import Path
# import logging
# import hmac
# import hashlib
# from datetime import datetime

# from dotenv import load_dotenv
# from fastapi import FastAPI, HTTPException, Request, Query, Header, Response
# from fastapi.middleware.cors import CORSMiddleware
# from fastapi.responses import HTMLResponse, JSONResponse
# from pydantic import BaseModel
# from supabase import create_client, Client
# from passlib.context import CryptContext
# import razorpay

# # =====================================================
# # ENV
# # =====================================================
# env_path = Path(__file__).resolve().parent / ".env"
# load_dotenv(env_path)

# SUPABASE_URL = os.getenv("SUPABASE_URL")
# SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
# RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID")
# RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET")

# if not all([SUPABASE_URL, SUPABASE_SERVICE_KEY, RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET]):
#     raise RuntimeError("Missing required environment variables")

# # =====================================================
# # LOGGING
# # =====================================================
# logger = logging.getLogger("uvicorn.error")
# logger.setLevel(logging.INFO)

# # =====================================================
# # CLIENTS
# # =====================================================
# supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
# razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

# pwd_context = CryptContext(
#     schemes=["bcrypt_sha256", "bcrypt"],
#     deprecated="auto",
# )

# # =====================================================
# # FASTAPI
# # =====================================================
# app = FastAPI(title="Parkria Backend – Razorpay")

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# @app.middleware("http")
# async def add_security_headers(request: Request, call_next):
#     response: Response = await call_next(request)
#     response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
#     response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
#     return response

# # =====================================================
# # MODELS
# # =====================================================
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

# class VerifyPaymentRequest(BaseModel):
#     razorpay_order_id: str
#     razorpay_payment_id: str
#     razorpay_signature: str

# # =====================================================
# # ROOT
# # =====================================================
# @app.get("/")
# def root():
#     return {"message": "🚀 API Running"}

# # =====================================================
# # AUTH
# # =====================================================
# @app.post("/send-otp")
# def send_otp(data: SendOTPRequest):
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

#     return {"message": "Signup successful", "user_id": res.data[0]["id"]}

# @app.post("/login")
# def login(user: UserLogin):
#     res = supabase.table("users").select("*").eq("phone", user.phone).execute()
#     if not res.data:
#         raise HTTPException(status_code=401, detail="Invalid phone or password")

#     db_user = res.data[0]
#     if not pwd_context.verify(user.password, db_user["password_hash"]):
#         raise HTTPException(status_code=401, detail="Invalid phone or password")

#     db_user.pop("password_hash", None)
#     return {"user": db_user}

# # =====================================================
# # VEHICLES
# # =====================================================
# @app.post("/vehicles/add")
# def add_vehicle(data: AddVehicleRequest):
#     exists = supabase.table("vehicles").select("*").eq("car_number", data.car_number).execute()
#     if exists.data:
#         raise HTTPException(status_code=400, detail="Car number already registered")

#     res = supabase.table("vehicles").insert({
#         **data.dict(),
#         "created_at": datetime.utcnow().isoformat()
#     }).execute()

#     return {"vehicle": res.data[0]}

# @app.get("/vehicles")
# def get_user_vehicles(user_id: str = Query(...)):
#     return supabase.table("vehicles") \
#         .select("vehicle_id, car_number") \
#         .eq("user_id", user_id) \
#         .order("vehicle_id") \
#         .execute().data or []

# # =====================================================
# # SERVICES / TOKENS
# # =====================================================
# @app.get("/services")
# def get_services():
#     return supabase.table("service_types").select("*").execute().data or []

# @app.post("/purchase-token")
# def purchase_token(data: TokenPurchaseRequest):
#     existing = supabase.table("purchased_tokens") \
#         .select("*") \
#         .eq("user_id", data.user_id) \
#         .eq("service_type_id", data.service_type_id) \
#         .execute()

#     if existing.data:
#         token_id = existing.data[0]["token_id"]
#         new_count = existing.data[0]["token_count"] + data.token_count

#         res = supabase.table("purchased_tokens") \
#             .update({"token_count": new_count, "updated_at": datetime.utcnow().isoformat()}) \
#             .eq("token_id", token_id) \
#             .execute()

#         return {"message": "Tokens updated", "purchase": res.data[0]}

#     res = supabase.table("purchased_tokens").insert({
#         "user_id": data.user_id,
#         "service_type_id": data.service_type_id,
#         "token_count": data.token_count,
#         "created_at": datetime.utcnow().isoformat(),
#         "updated_at": datetime.utcnow().isoformat()
#     }).execute()

#     return {"message": "Purchase saved", "purchase": res.data[0]}

# @app.post("/consume-token")
# def consume_token(data: ConsumeTokenRequest):
#     purchased = supabase.table("purchased_tokens") \
#         .select("*") \
#         .eq("user_id", data.user_id) \
#         .eq("service_type_id", data.service_type_id) \
#         .execute()

#     if not purchased.data:
#         raise HTTPException(status_code=404, detail="No tokens available")

#     remaining = data.token_count
#     for row in purchased.data:
#         use = min(row["token_count"], remaining)
#         supabase.table("purchased_tokens").update({
#             "token_count": row["token_count"] - use,
#             "updated_at": datetime.utcnow().isoformat()
#         }).eq("token_id", row["token_id"]).execute()

#         remaining -= use
#         if remaining <= 0:
#             break

#     if remaining > 0:
#         raise HTTPException(status_code=400, detail="Insufficient tokens")

#     return {"message": "Token consumed"}

# # =====================================================
# # PARKING SLOTS
# # =====================================================
# @app.get("/parking-slots")
# def get_parking_slots(unit_id: int = Query(...)):
#     return {
#         "total_slots": 30,
#         "slots": supabase.table("parking_slots")
#             .select("*")
#             .eq("unit_id", unit_id)
#             .execute().data or []
#     }

# @app.post("/parking-slots/book")
# def book_slot(data: ParkingSlotBookRequest):
#     slot = supabase.table("parking_slots") \
#         .select("*") \
#         .eq("slot_id", data.slot_id) \
#         .eq("status", "available") \
#         .execute()

#     if not slot.data:
#         raise HTTPException(status_code=400, detail="Slot not available")

#     res = supabase.table("parking_slots").update({
#         "status": "occupied",
#         "current_vehicle_id": data.vehicle_id,
#         "updated_at": datetime.utcnow().isoformat()
#     }).eq("slot_id", data.slot_id).execute()

#     return {"slot": res.data[0]}

# # =====================================================
# # RAZORPAY PAYMENTS
# # =====================================================
# @app.post("/create-payment")
# def create_payment(req: PaymentRequest):
#     order = razorpay_client.order.create({
#         "amount": req.amount * 100,
#         "currency": "INR",
#         "receipt": f"booking_{req.booking_id}",
#         "payment_capture": 1
#     })

#     merchant_order_id = f"rzp-{req.booking_id}-{int(datetime.utcnow().timestamp())}"

#     supabase.table("orders").insert({
#         "merchant_order_id": merchant_order_id,
#         "booking_id": req.booking_id,
#         "user_id": req.user_id,
#         "amount": req.amount * 100,
#         "status": "CREATED",
#         "razorpay_order_id": order["id"],
#         "created_at": datetime.utcnow().isoformat()
#     }).execute()

#     return {
#         "razorpay_key": RAZORPAY_KEY_ID,
#         "order_id": order["id"],
#         "merchant_order_id": merchant_order_id,
#         "amount": req.amount * 100,
#         "currency": "INR"
#     }

# @app.post("/verify-payment")
# def verify_payment(data: VerifyPaymentRequest):
#     body = f"{data.razorpay_order_id}|{data.razorpay_payment_id}"
#     expected = hmac.new(
#         RAZORPAY_KEY_SECRET.encode(),
#         body.encode(),
#         hashlib.sha256
#     ).hexdigest()

#     if not hmac.compare_digest(expected, data.razorpay_signature):
#         raise HTTPException(status_code=400, detail="Invalid payment signature")

#     supabase.table("orders").update({
#         "status": "PAID",
#         "updated_at": datetime.utcnow().isoformat()
#     }).eq("razorpay_order_id", data.razorpay_order_id).execute()

#     return {"status": "success"}

# @app.get("/order-status/{razorpay_order_id}")
# def order_status(razorpay_order_id: str):
#     res = supabase.table("orders").select("*").eq("razorpay_order_id", razorpay_order_id).execute()
#     if not res.data:
#         raise HTTPException(status_code=404, detail="Order not found")
#     return res.data[0]

# @app.get("/payment-success")
# def payment_success():
#     return HTMLResponse("<h2>✅ Payment Successful</h2>")
