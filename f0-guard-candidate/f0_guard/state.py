"""Deterministic reducer: ledger events -> task state. No clock, no I/O."""
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class TaskState:
    registered: bool = False
    envelope_digest: Optional[str] = None
    terms: Optional[dict] = None
    attempts_started: int = 0
    in_flight: Optional[dict] = None
    spent: int = 0
    started_heads: dict = field(default_factory=dict)
    completed: dict = field(default_factory=dict)
    last_attempt: Optional[dict] = None
    budget_stopped: bool = False
    revoked: bool = False
    expired: bool = False
    accepted_head: Optional[str] = None
    needs_resume: Optional[dict] = None
    seen_keys: set = field(default_factory=set)
    nonces: set = field(default_factory=set)
    deliveries: set = field(default_factory=set)

    def snapshot(self):
        data = asdict(self)
        for name in ("seen_keys", "nonces", "deliveries"):
            data[name] = sorted(data[name])
        return data


def reduce_events(events, task_id):
    st = TaskState()
    for ev in events:
        if ev.get("delivery_id"):
            st.deliveries.add(ev["delivery_id"])
        if ev["kind"] == "TASK_REGISTERED":
            st.nonces.add(ev["payload"]["nonce"])
        if ev["task_id"] != task_id:
            continue
        kind, p = ev["kind"], ev["payload"]
        if ev.get("event_key"):
            st.seen_keys.add(ev["event_key"])
        if kind == "TASK_REGISTERED":
            st.registered = True
            st.envelope_digest = p["envelope_digest"]
            st.terms = p["terms"]
        elif kind == "ATTEMPT_STARTED":
            st.attempts_started += 1
            st.in_flight = {"attempt_no": p["attempt_no"], "head_sha": p["head_sha"],
                            "started_at": p["started_at"], "reserve_units": p["reserve_units"]}
            st.started_heads[p["head_sha"]] = {"attempt_no": p["attempt_no"],
                                               "paths_digest": p["paths_digest"]}
            st.last_attempt = {"attempt_no": p["attempt_no"], "head_sha": p["head_sha"],
                               "outcome": None, "event_hash": ev["hash"]}
        elif kind == "ATTEMPT_COMPLETED":
            st.in_flight = None
            st.spent += p["cost_charged"]
            st.completed[p["head_sha"]] = {"outcome": p["outcome"], "completed_at": p["completed_at"],
                                           "evidence_sha256": p["evidence_sha256"]}
            st.last_attempt["outcome"] = p["outcome"]
            st.last_attempt["event_hash"] = ev["hash"]
        elif kind == "ATTEMPT_INTERRUPTED":
            st.in_flight = None
            st.spent += p["cost_charged"]
            st.last_attempt["outcome"] = "interrupted"
            st.needs_resume = {"attempt_no": p["attempt_no"], "head_sha": p["head_sha"],
                               "event_hash": ev["hash"]}
        elif kind == "RESUMED":
            st.needs_resume = None
        elif kind == "BUDGET_STOP":
            st.budget_stopped = True
        elif kind == "TASK_EXPIRED":
            st.expired = True
        elif kind == "TASK_REVOKED":
            st.revoked = True
        elif kind == "ACCEPTED":
            st.accepted_head = p["head_sha"]
    return st
