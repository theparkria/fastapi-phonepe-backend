# phonepe_sdk/pg/common/exceptions.py

class PhonePeException(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)
