from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from supabase import create_client, Client
import bcrypt, logging, requests, os
from dotenv import load_dotenv

# ========================
# Load Environment
# ========================
load_dotenv()
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
router = APIRouter(prefix="/auth", tags=["Auth"])

# ========================
# Logger Setup
# ========================
logger = logging.getLogger("auth")
logging.basicConfig(level=logging.INFO)

# ========================
# Utility Functions
# ========================
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))

# ========================
# Request Models
# ========================
class PasswordChangeRequest(BaseModel):
    phone: str
    old_password: str
    new_password: str
    confirm_password: str

class OTPRequest(BaseModel):
    phone: str

class OTPVerify(BaseModel):
    phone: str
    otp: str
    new_password: str
    confirm_password: str

# ========================
# Change Password (Logged In)
# ========================
@router.post("/change-password")
async def change_password(data: PasswordChangeRequest):
    try:
        logger.info(f"🔑 Change password request: {data.dict()}")

        response = supabase.table("users").select("*").eq("phone", data.phone).execute()
        if not response.data:
            raise HTTPException(status_code=404, detail="User not found")

        user = response.data[0]
        if not verify_password(data.old_password, user["password_hash"]):
            raise HTTPException(status_code=422, detail="Old password is incorrect")

        if data.new_password != data.confirm_password:
            raise HTTPException(status_code=422, detail="New password and confirm password do not match")

        new_hashed = hash_password(data.new_password)
        supabase.table("users").update({"password_hash": new_hashed}).eq("id", user["id"]).execute()

        logger.info("✅ Password updated successfully")
        return {"message": "Password updated successfully"}

    except Exception as e:
        logger.error(f"❌ Error changing password: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# ========================
# Send OTP (for reset)
# ========================
@router.post("/send-otp")
async def send_otp(req: OTPRequest):
    try:
        logger.info(f"📲 Send OTP request: {req.dict()}")

        response = supabase.table("users").select("id, phone").eq("phone", req.phone).execute()
        if not response.data:
            raise HTTPException(status_code=404, detail="User not found")

        url = f"{SUPABASE_URL}/auth/v1/otp"
        headers = {"apikey": SUPABASE_SERVICE_KEY, "Content-Type": "application/json"}
        body = {"phone": f"+91{req.phone}", "create_user": False}

        r = requests.post(url, json=body, headers=headers)
        if r.status_code != 200:
            raise HTTPException(status_code=400, detail=f"Failed to send OTP: {r.text}")

        logger.info(f"✅ OTP sent successfully to {req.phone}")
        return {"message": "OTP sent via SMS"}

    except Exception as e:
        logger.error(f"❌ OTP send error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# ========================
# Verify OTP & Reset Password
# ========================
@router.post("/verify-otp")
async def verify_otp(data: OTPVerify):
    try:
        logger.info(f"🔐 Verify OTP request: {data.dict()}")

        url = f"{SUPABASE_URL}/auth/v1/verify"
        headers = {"apikey": SUPABASE_SERVICE_KEY, "Content-Type": "application/json"}
        body = {"phone": f"+91{data.phone}", "token": data.otp, "type": "sms"}

        r = requests.post(url, json=body, headers=headers)
        if r.status_code != 200:
            raise HTTPException(status_code=422, detail=f"Invalid OTP: {r.text}")

        response = supabase.table("users").select("id, phone").eq("phone", data.phone).execute()
        if not response.data:
            raise HTTPException(status_code=404, detail="User not found")

        user = response.data[0]
        if data.new_password != data.confirm_password:
            raise HTTPException(status_code=422, detail="Passwords do not match")

        new_hashed = hash_password(data.new_password)
        supabase.table("users").update({"password_hash": new_hashed}).eq("id", user["id"]).execute()

        logger.info(f"✅ Password reset successful for {data.phone}")
        return {"message": "Password reset successful"}

    except Exception as e:
        logger.error(f"❌ OTP verify error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
