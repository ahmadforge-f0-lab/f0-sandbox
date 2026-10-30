"""Strict, minimal schema validators. Unknown fields are rejected."""
import re


class SchemaError(ValueError):
    pass


def _fail(path, msg):
    raise SchemaError("%s: %s" % (path, msg))


def string(max_len=256, pattern=None):
    rx = re.compile(pattern) if pattern else None

    def check(value, path):
        if not isinstance(value, str):
            _fail(path, "expected string")
        if len(value) > max_len:
            _fail(path, "too long")
        if rx is not None and not rx.fullmatch(value):
            _fail(path, "pattern mismatch")
    return check


def integer(lo=0, hi=10 ** 12):
    def check(value, path):
        if isinstance(value, bool) or not isinstance(value, int):
            _fail(path, "expected integer")
        if value < lo or value > hi:
            _fail(path, "out of range")
    return check


def hexstr(length):
    return string(length, "[0-9a-f]{%d}" % length)


def enum(*values):
    def check(value, path):
        if not isinstance(value, str) or value not in values:
            _fail(path, "not an allowed value")
    return check


def listof(item, max_len=256):
    def check(value, path):
        if not isinstance(value, list):
            _fail(path, "expected list")
        if len(value) > max_len:
            _fail(path, "too many items")
        for i, element in enumerate(value):
            item(element, "%s[%d]" % (path, i))
    return check


def dictof(key_check, value_check, max_len=256):
    def check(value, path):
        if not isinstance(value, dict):
            _fail(path, "expected object")
        if len(value) > max_len:
            _fail(path, "too many entries")
        for k, v in value.items():
            key_check(k, path + ".<key>")
            value_check(v, "%s.%s" % (path, k))
    return check


def obj(required, optional=None):
    optional = optional or {}

    def check(value, path):
        if not isinstance(value, dict):
            _fail(path, "expected object")
        for name in value:
            if name not in required and name not in optional:
                _fail(path, "unknown field %r" % name)
        for name, sub in required.items():
            if name not in value:
                _fail(path, "missing field %r" % name)
            sub(value[name], "%s.%s" % (path, name))
        for name, sub in optional.items():
            if name in value:
                sub(value[name], "%s.%s" % (path, name))
    return check


def validate(checker, value):
    checker(value, "$")
