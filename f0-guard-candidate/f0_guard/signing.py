"""HMAC-SHA256 signatures with domain separation.

LIMITATION: HMAC is symmetric. Whoever holds the verifying keyring can also
forge. The keyring MUST live on the trusted side, outside author control.
Production use should replace this with asymmetric/attestation-based signing.
"""
import hashlib
import hmac

from .canon import canonical

DOMAIN = b"F0-GUARD-V1|"


def sign(secret, kind, obj):
    body = {k: v for k, v in obj.items() if k != "signature"}
    return hmac.new(secret, DOMAIN + kind.encode("ascii") + b"|" + canonical(body),
                    hashlib.sha256).hexdigest()


def verify(keyring, kind, obj, role, principal):
    entry = keyring.get(obj.get("key_id"))
    if entry is None or entry["role"] != role or entry["principal"] != principal:
        return False
    expected = sign(bytes.fromhex(entry["secret_hex"]), kind, obj)
    return hmac.compare_digest(expected, obj.get("signature", ""))
