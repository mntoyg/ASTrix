import hashlib


def fingerprint(payload: bytes) -> str:
    return hashlib.md5(payload).hexdigest()
