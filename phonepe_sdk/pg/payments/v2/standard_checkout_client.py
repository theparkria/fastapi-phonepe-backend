# phonepe_sdk/pg/payments/v2/standard_checkout_client.py

from phonepe_sdk.pg.common.models.request.meta_info import MetaInfo
from phonepe_sdk.pg.common.exceptions import PhonePeException

class StandardCheckoutPayRequest:
    @staticmethod
    def build_request(merchant_order_id, amount, redirect_url, meta_info: MetaInfo):
        # minimal structure
        return {
            "merchant_order_id": merchant_order_id,
            "amount": amount,
            "redirect_url": redirect_url,
            "meta_info": meta_info.__dict__
        }

class StandardCheckoutResponse:
    def __init__(self, order_id, redirect_url, state):
        self.order_id = order_id
        self.redirect_url = redirect_url
        self.state = state

class StandardCheckoutClient:
    _instance = None

    @classmethod
    def get_instance(cls, client_id, client_secret, client_version, env):
        if not cls._instance:
            cls._instance = cls(client_id, client_secret, client_version, env)
        return cls._instance

    def __init__(self, client_id, client_secret, client_version, env):
        self.client_id = client_id
        self.client_secret = client_secret
        self.client_version = client_version
        self.env = env

    def pay(self, request_payload):
        # In a real SDK, you would call PhonePe API here.
        # For testing, we mock a successful response:
        order_id = f"PP-{request_payload['merchant_order_id']}"
        redirect_url = request_payload["redirect_url"] + f"?order_id={order_id}"
        state = "PENDING"
        return StandardCheckoutResponse(order_id, redirect_url, state)

