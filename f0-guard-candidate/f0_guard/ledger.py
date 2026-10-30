"""Append-only hash-chained event ledger with compare-and-swap append.

The chain detects in-place edits and truncation only if its tip is anchored in
a trusted store (expected_tip). The ledger alone is not a trust anchor.
"""
import json
import threading

from .canon import canonical, digest_of

GENESIS = "0" * 64
KINDS = frozenset({
    "TASK_REGISTERED", "ATTEMPT_STARTED", "ATTEMPT_COMPLETED",
    "ATTEMPT_INTERRUPTED", "BUDGET_STOP", "TASK_EXPIRED", "TASK_REVOKED",
    "RESUMED", "ACCEPTED",
})


class LedgerConflict(Exception):
    pass


def event_hash(event):
    body = {k: v for k, v in event.items() if k != "hash"}
    return digest_of(body)


class Ledger:
    def __init__(self, events=()):
        self.events = [dict(e) for e in events]
        self._lock = threading.Lock()

    @property
    def tip(self):
        return self.events[-1]["hash"] if self.events else GENESIS

    def verify(self):
        problems = []
        prev = GENESIS
        for index, event in enumerate(self.events):
            try:
                if event["seq"] != index:
                    problems.append("seq mismatch at %d" % index)
                if event["prev"] != prev:
                    problems.append("prev mismatch at %d" % index)
                if event["kind"] not in KINDS:
                    problems.append("unknown kind at %d" % index)
                if event_hash(event) != event["hash"]:
                    problems.append("hash mismatch at %d" % index)
                prev = event["hash"]
            except (KeyError, TypeError):
                problems.append("malformed event at %d" % index)
                break
        return problems

    def append(self, specs, expected_tip, now):
        with self._lock:
            if self.tip != expected_tip:
                raise LedgerConflict("tip moved: expected %s, found %s"
                                     % (expected_tip, self.tip))
            added = []
            prev = self.tip
            seq = len(self.events)
            for spec in specs:
                event = {
                    "seq": seq, "prev": prev, "ts": now,
                    "kind": spec["kind"], "task_id": spec["task_id"],
                    "payload": spec["payload"],
                    "event_key": spec.get("event_key"),
                    "delivery_id": spec.get("delivery_id"),
                }
                event["hash"] = event_hash(event)
                added.append(event)
                prev = event["hash"]
                seq += 1
            self.events.extend(added)
            return added

    def to_jsonl(self):
        return "".join(canonical(e).decode("ascii") + "\n" for e in self.events)

    @classmethod
    def from_jsonl(cls, text):
        return cls([json.loads(line) for line in text.splitlines() if line.strip()])
