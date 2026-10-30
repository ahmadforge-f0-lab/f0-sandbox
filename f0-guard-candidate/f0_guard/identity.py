"""Content identity of guard/oracle files. Run by the TRUSTED runner, never by the author."""
import hashlib
import os

from .canon import digest_of


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def compute_file_map(root, rel_paths):
    root = os.path.realpath(root)
    result = {}
    for rel in sorted(rel_paths):
        full = os.path.join(root, rel)
        if os.path.islink(full):
            raise ValueError("symlink not allowed: %s" % rel)
        real = os.path.realpath(full)
        if os.path.commonpath([root, real]) != root:
            raise ValueError("path escapes root: %s" % rel)
        result[rel] = file_sha256(real)
    return result


def compute_identity_digest(root, rel_paths):
    return digest_of(compute_file_map(root, rel_paths))
