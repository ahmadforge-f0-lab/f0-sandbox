"""Canonical JSON and hashing. Floats are rejected so output is byte-stable."""
import hashlib
import json


def _check(obj):
    if obj is None or isinstance(obj, (str, bool, int)):
        return
    if isinstance(obj, (list, tuple)):
        for item in obj:
            _check(item)
        return
    if isinstance(obj, dict):
        for key, value in obj.items():
            if not isinstance(key, str):
                raise TypeError("non-string key")
            _check(value)
        return
    raise TypeError("non-canonical type %s" % type(obj).__name__)


def canonical(obj):
    _check(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def digest_of(obj):
    return sha256_hex(canonical(obj))
