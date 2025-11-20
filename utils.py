import hashlib
import base64
import json
from phonepe_config import PHONEPE_SALT_KEY

def generate_phonepe_checksum(payload: dict) -> str:
    payload_str = json.dumps(payload, separators=(',', ':'))
    payload_base64 = base64.b64encode(payload_str.encode()).decode()
    to_sign = payload_base64 + "/pg/v1/pay" + PHONEPE_SALT_KEY
    sha256_hash = hashlib.sha256(to_sign.encode()).hexdigest()
    return f"{sha256_hash}###1", payload_base64
