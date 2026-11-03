import hashlib


def fingerprint(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()
