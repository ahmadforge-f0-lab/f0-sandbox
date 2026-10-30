"""Local CLI. No network, no GitHub access, no credentials beyond a synthetic keyring file.

Exit codes: 0 = ALLOW, 2 = DENY, 3 = internal/IO error (treated as DENY by callers).
"""
import argparse
import fcntl
import json
import os
import sys

from .canon import canonical
from .guard import TrustedContext, evaluate, process
from .ledger import Ledger


def _load(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="f0_guard")
    ap.add_argument("--trusted", required=True, help="trusted context JSON (policy, keyring, observed, ...)")
    ap.add_argument("--envelope", help="owner-signed task envelope JSON")
    ap.add_argument("--request", required=True)
    ap.add_argument("--ledger", required=True, help="JSONL ledger path (created if absent)")
    ap.add_argument("--now", type=int, required=True)
    ap.add_argument("--apply", action="store_true", help="append resulting events to the ledger")
    args = ap.parse_args(argv)
    try:
        t = _load(args.trusted)
        trusted = TrustedContext(
            policy=t["policy"], expected_policy_sha256=t["expected_policy_sha256"],
            keyring=t["keyring"], observed=t["observed"],
            expected_tip=t.get("expected_tip"), revocations=t.get("revocations"))
        envelope = _load(args.envelope) if args.envelope else None
        request = _load(args.request)
        lock_fd = os.open(args.ledger + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            text = open(args.ledger, encoding="utf-8").read() if os.path.exists(args.ledger) else ""
            ledger = Ledger.from_jsonl(text)
            if args.apply:
                outcome = process(trusted, envelope, request, ledger, args.now)
                decision = outcome.decision
                if outcome.applied:
                    tmp = args.ledger + ".tmp"
                    with open(tmp, "w", encoding="utf-8") as fh:
                        fh.write(ledger.to_jsonl())
                        fh.flush()
                        os.fsync(fh.fileno())
                    os.replace(tmp, args.ledger)
            else:
                decision = evaluate(trusted, envelope, request, ledger, args.now)
        finally:
            os.close(lock_fd)
    except Exception as exc:  # noqa: BLE001 - fail closed
        sys.stdout.write(json.dumps({"allow": False, "reasons": ["CLI_ERROR"],
                                     "error_type": type(exc).__name__}) + "\n")
        return 3
    out = decision.to_dict()
    out["decision_digest"] = decision.digest
    sys.stdout.write(canonical(out).decode("ascii") + "\n")
    return 0 if decision.allow else 2
