"""Deterministic guard decision engine.

Trust classes of inputs:
  TRUSTED (supplied by the protected runner, never by the author):
      policy + its pinned sha256, keyring, revocation list, observed facts
      (repo/branch/head/paths/author identity/guard+oracle digests), the
      anchored ledger tip and the clock value `now`.
  SIGNED (authority proven by signature): owner envelope, evidence, verdict.
  UNTRUSTED: the request itself (only names an action and carries payloads).

The author cannot self-certify: acceptance exists only as a ledger event the
guard itself emits after validating an independently signed verdict.
Every check is a module-level function so negative controls can defeat it.
"""
import posixpath
import re
import unicodedata
from dataclasses import dataclass, field, replace

from .canon import digest_of
from .ledger import LedgerConflict
from .schema import (SchemaError, dictof, enum, hexstr, integer, listof, obj,
                     string, validate)
from .signing import verify
from .state import reduce_events

ACTIONS = ("REGISTER", "START_ATTEMPT", "COMPLETE_ATTEMPT", "ACCEPT", "RESUME", "RECONCILE")

_ID = string(64, r"[A-Za-z0-9._-]+")
_SHA = hexstr(40)
_SHA256 = hexstr(64)
_GLOB_BASE = string(200)
MAX_WILDCARDS = 6


def _glob(value, path):
    _GLOB_BASE(value, path)
    if value.count("*") + value.count("?") > MAX_WILDCARDS:
        raise SchemaError("%s: too many wildcards" % path)


_GLOB = _glob
_TS = integer(0, 4102444800)
_UNITS = integer(0, 10 ** 9)

POLICY_SCHEMA = obj({
    "policy_version": _ID,
    "repo": string(100, r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+"),
    "default_branch": _ID,
    "protected_branches": listof(_ID, 16),
    "work_branch_prefix": string(32, r"[a-z]+/"),
    "owners": listof(_ID, 16),
    "principals": dictof(_ID, obj({
        "kind": enum("author_agent", "reviewer", "owner", "evidence_producer"),
        "conflict_group": _ID}), 64),
    "qualified_reviewers": listof(_ID, 16),
    "allowed_reviewer_kinds": listof(enum("human", "independent_model"), 4),
    "trusted_evidence_producers": listof(_ID, 16),
    "protected_paths": listof(_GLOB, 64),
    "guard_files": listof(string(200), 64),
    "guard_digest": _SHA256,
    "oracle_digests": dictof(string(200), _SHA256, 64),
    "max_attempts_cap": integer(1, 100),
    "budget_cap_units": _UNITS,
    "attempt_reserve_units": _UNITS,
    "min_attempt_charge_units": _UNITS,
    "max_task_ttl_seconds": integer(1, 10 ** 7),
    "attempt_lease_seconds": integer(1, 10 ** 6),
    "verdict_ttl_seconds": integer(1, 10 ** 6),
    "revocation_max_age_seconds": integer(1, 10 ** 6),
})

KEYRING_SCHEMA = dictof(_ID, obj({
    "role": enum("owner", "reviewer", "evidence_producer"),
    "principal": _ID, "secret_hex": hexstr(64)}), 64)

OBSERVED_SCHEMA = obj({
    "repo": string(100), "branch": string(200), "head_sha": _SHA, "base_sha": _SHA,
    "author_id": _ID, "author_session_id": _ID,
    "guard_digest": _SHA256, "oracle_digests": dictof(string(200), _SHA256, 64),
    "changed_paths": listof(string(512), 2000)})

ENVELOPE_SCHEMA = obj({
    "task_id": _ID, "owner_id": _ID, "key_id": _ID, "repo": string(100),
    "base_branch": _ID, "base_sha": _SHA, "work_branch": string(200),
    "allowed_paths": listof(_GLOB, 64), "max_attempts": integer(1, 100),
    "budget_ceiling_units": _UNITS, "issued_at": _TS, "expires_at": _TS,
    "nonce": hexstr(32), "policy_sha256": _SHA256, "signature": _SHA256})

EVIDENCE_SCHEMA = obj({
    "evidence_id": _ID, "task_id": _ID, "head_sha": _SHA,
    "outcome": enum("candidate_ready", "failed"), "cost_units": _UNITS,
    "artifact_sha256": _SHA256, "producer_id": _ID, "key_id": _ID,
    "issued_at": _TS, "signature": _SHA256})

VERDICT_SCHEMA = obj({
    "verdict_id": _ID, "task_id": _ID, "repo": string(100), "reviewed_sha": _SHA,
    "outcome": enum("PASS", "FAIL"), "reviewer_id": _ID,
    "reviewer_kind": enum("human", "independent_model"),
    "reviewer_session_id": _ID, "declared_conflicts": listof(string(200), 16),
    "guard_digest": _SHA256, "oracle_set_digest": _SHA256,
    "issued_at": _TS, "key_id": _ID, "signature": _SHA256})

RESUME_SCHEMA = obj({
    "last_attempt_no": integer(1, 100), "last_head_sha": _SHA,
    "envelope_digest": _SHA256, "interruption_event_hash": _SHA256})

REVOCATION_SCHEMA = obj({
    "task_ids": listof(_ID, 256), "issued_at": _TS, "owner_id": _ID,
    "key_id": _ID, "signature": _SHA256})

REQUEST_SCHEMA = obj(
    {"action": enum(*ACTIONS), "task_id": _ID, "delivery_id": string(128, r"[A-Za-z0-9._:-]+")},
    {"evidence": EVIDENCE_SCHEMA, "verdict": VERDICT_SCHEMA, "resume": RESUME_SCHEMA})

PAYLOAD_FOR = {"COMPLETE_ATTEMPT": "evidence", "ACCEPT": "verdict", "RESUME": "resume"}


@dataclass
class TrustedContext:
    policy: dict
    expected_policy_sha256: str
    keyring: dict
    observed: dict
    expected_tip: object          # str, or None = unanchored (always denied)
    revocations: object = None    # signed revocation list, or None = unavailable


@dataclass(frozen=True)
class Decision:
    allow: bool
    action: str
    task_id: str
    reasons: tuple
    events: tuple
    provenance: dict = field(default_factory=dict)

    def to_dict(self):
        return {"allow": self.allow, "action": self.action, "task_id": self.task_id,
                "reasons": list(self.reasons), "events": list(self.events),
                "provenance": self.provenance}

    @property
    def digest(self):
        return digest_of(self.to_dict())


@dataclass
class Outcome:
    decision: Decision
    applied: bool


class Ctx:
    def __init__(self, trusted, envelope, request, ledger, now):
        self.trusted, self.envelope, self.request = trusted, envelope, request
        self.ledger, self.now = ledger, now
        self.policy = None
        self.state = None
        self.terms = None
        self.envelope_digest = None
        self.revoked_by_list = False
        self.reasons = set()
        self.events = []
        self.fatal = False
        self._delivery_used = False

    def deny(self, code, fatal=False):
        self.reasons.add(code)
        self.fatal = self.fatal or fatal

    @property
    def action(self):
        return self.request["action"]

    @property
    def task_id(self):
        return self.request["task_id"]

    def emit(self, kind, payload, key=None):
        delivery = None
        if not self._delivery_used:
            delivery, self._delivery_used = self.request["delivery_id"], True
        self.events.append({"kind": kind, "task_id": self.task_id, "payload": payload,
                            "event_key": key, "delivery_id": delivery})


def event_key(task_id, action, discriminator):
    return digest_of([task_id, action, discriminator])


def _safe_str(container, key):
    try:
        value = container[key]
        return value if isinstance(value, str) else ""
    except (KeyError, TypeError, IndexError):
        return ""


# ---------------------------------------------------------------- input checks

def check_policy_pin(c):
    t = c.trusted
    try:
        validate(POLICY_SCHEMA, t.policy)
        validate(hexstr(64), t.expected_policy_sha256)
    except SchemaError:
        c.deny("POLICY_INVALID", fatal=True)
        return
    if digest_of(t.policy) != t.expected_policy_sha256:
        c.deny("POLICY_DIGEST_MISMATCH", fatal=True)
        return
    c.policy = t.policy


def check_inputs(c):
    try:
        validate(REQUEST_SCHEMA, c.request)
        validate(KEYRING_SCHEMA, c.trusted.keyring)
        validate(OBSERVED_SCHEMA, c.trusted.observed)
        if c.request["action"] != "RECONCILE":
            validate(ENVELOPE_SCHEMA, c.envelope)
            if c.envelope["task_id"] != c.request["task_id"]:
                c.deny("TASK_ID_MISMATCH", fatal=True)
        wanted = PAYLOAD_FOR.get(c.request["action"])
        for name in ("evidence", "verdict", "resume"):
            if (name in c.request) != (name == wanted):
                c.deny("PAYLOAD_NOT_ALLOWED", fatal=True)
    except (SchemaError, TypeError, KeyError):
        c.deny("INPUT_INVALID", fatal=True)


def check_guard_identity(c):
    if c.trusted.observed["guard_digest"] != c.policy["guard_digest"]:
        c.deny("GUARD_IDENTITY_MISMATCH")


def check_oracle_identity(c):
    if c.trusted.observed["oracle_digests"] != c.policy["oracle_digests"]:
        c.deny("ORACLE_IDENTITY_MISMATCH")


def check_ledger_integrity(c):
    if c.ledger.verify():
        c.deny("LEDGER_CORRUPT", fatal=True)


def check_ledger_anchor(c):
    tip = c.trusted.expected_tip
    if tip is None:
        c.deny("LEDGER_UNANCHORED")
    elif tip != c.ledger.tip:
        c.deny("LEDGER_TIP_MISMATCH", fatal=True)


# ------------------------------------------------------------ envelope checks

def check_owner_auth(c):
    env, policy = c.envelope, c.policy
    if env["policy_sha256"] != c.trusted.expected_policy_sha256:
        c.deny("ENVELOPE_POLICY_MISMATCH")
    if env["owner_id"] not in policy["owners"]:
        c.deny("OWNER_NOT_AUTHORIZED", fatal=True)
        return
    if not verify(c.trusted.keyring, "envelope", env, "owner", env["owner_id"]):
        c.deny("OWNER_AUTH_INVALID", fatal=True)


def check_repo_scope(c):
    if c.envelope["repo"] != c.policy["repo"] or c.trusted.observed["repo"] != c.envelope["repo"]:
        c.deny("REPO_SCOPE_VIOLATION")


def check_branch_scope(c):
    env, obs, policy = c.envelope, c.trusted.observed, c.policy
    branch = env["work_branch"]
    shape = re.escape(policy["work_branch_prefix"]) + r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*"
    if (env["base_branch"] != policy["default_branch"] or not re.fullmatch(shape, branch)
            or ".." in branch or branch in policy["protected_branches"]
            or obs["branch"] != branch):
        c.deny("BRANCH_SCOPE_VIOLATION")
    if obs["base_sha"] != env["base_sha"]:
        c.deny("BASE_SHA_MISMATCH")


def check_limits(c):
    env, policy = c.envelope, c.policy
    if (env["max_attempts"] > policy["max_attempts_cap"]
            or env["budget_ceiling_units"] > policy["budget_cap_units"]
            or env["expires_at"] <= env["issued_at"]
            or env["expires_at"] - env["issued_at"] > policy["max_task_ttl_seconds"]):
        c.deny("ENVELOPE_LIMITS_EXCEED_POLICY")


def check_time_window(c):
    if c.now < c.envelope["issued_at"]:
        c.deny("TASK_NOT_YET_VALID")


def check_envelope_binding(c):
    c.envelope_digest = digest_of(c.envelope)
    st, env = c.state, c.envelope
    if c.action == "REGISTER":
        c.terms = {"repo": env["repo"], "work_branch": env["work_branch"],
                   "base_sha": env["base_sha"], "allowed_paths": env["allowed_paths"],
                   "max_attempts": env["max_attempts"],
                   "budget_ceiling_units": env["budget_ceiling_units"],
                   "expires_at": env["expires_at"]}
        return
    if not st.registered:
        c.deny("TASK_NOT_REGISTERED", fatal=True)
        return
    if st.envelope_digest != c.envelope_digest:
        c.deny("ENVELOPE_DIGEST_MISMATCH", fatal=True)
        return
    c.terms = st.terms


def check_revocation(c):
    """Revocation status must be fresh, owner-signed and available, else fail closed.

    RECONCILE is the recovery path: an unusable list is ignored there (never a
    denial), so a forged or stale list cannot block recovery bookkeeping.
    """
    strict = c.action != "RECONCILE"
    rv = c.trusted.revocations
    if rv is None:
        if strict:
            c.deny("REVOCATION_STATUS_UNAVAILABLE")
        return
    try:
        validate(REVOCATION_SCHEMA, rv)
        signed_ok = (rv["owner_id"] in c.policy["owners"]
                     and verify(c.trusted.keyring, "revocation", rv, "owner", rv["owner_id"]))
        fresh = 0 <= c.now - rv["issued_at"] <= c.policy["revocation_max_age_seconds"]
    except (SchemaError, TypeError, KeyError):
        signed_ok, fresh = False, False
    if not signed_ok:
        if strict:
            c.deny("REVOCATION_LIST_INVALID")
        return
    if not fresh:
        if strict:
            c.deny("REVOCATION_LIST_STALE")
        return
    if c.task_id in rv["task_ids"]:
        c.revoked_by_list = True
        if strict:
            c.deny("TASK_REVOKED")


def check_task_active(c):
    st = c.state
    if c.now >= c.terms["expires_at"] or st.expired:
        c.deny("TASK_EXPIRED")
    if st.revoked:
        c.deny("TASK_REVOKED")
    if st.budget_stopped:
        c.deny("BUDGET_STOPPED")


# ------------------------------------------------------------ attempt checks

def check_dedupe(c, key):
    if key in c.state.seen_keys:
        c.deny("DUPLICATE_EVENT")
    if c.request["delivery_id"] in c.state.deliveries:
        c.deny("DUPLICATE_DELIVERY")


def check_inflight(c):
    fl = c.state.in_flight
    if fl is not None:
        c.deny("ATTEMPT_IN_FLIGHT")
        if c.now >= fl["started_at"] + c.policy["attempt_lease_seconds"]:
            c.deny("RECONCILE_REQUIRED")


def check_retry_limit(c):
    if c.state.attempts_started >= c.terms["max_attempts"]:
        c.deny("RETRY_EXHAUSTED")


def check_resume_required(c):
    if c.state.needs_resume is not None:
        c.deny("RESUME_REQUIRED")


def check_budget(c):
    if c.state.spent + c.policy["attempt_reserve_units"] > c.terms["budget_ceiling_units"]:
        c.deny("BUDGET_EXCEEDED")


def check_author(c):
    author = c.trusted.observed["author_id"]
    principal = c.policy["principals"].get(author)
    if (principal is None or principal["kind"] != "author_agent"
            or author in c.policy["owners"] or author in c.policy["qualified_reviewers"]):
        c.deny("AUTHOR_NOT_AUTHORIZED")


def _fold(path):
    return unicodedata.normalize("NFKC", path).casefold()


def _glob_regex(glob):
    out, i = [], 0
    while i < len(glob):
        ch = glob[i]
        if glob.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
            continue
        if glob.startswith("**", i):
            out.append(".*")
            i += 2
            continue
        out.append("[^/]*" if ch == "*" else "[^/]" if ch == "?" else re.escape(ch))
        i += 1
    return re.compile("".join(out))


def _matches(globs, path):
    folded = _fold(path)
    return any(_glob_regex(_fold(g)).fullmatch(folded) for g in globs)


def _well_formed(path):
    return (path and not path.startswith("/") and "\\" not in path and "\x00" not in path
            and posixpath.normpath(path) == path and not path.endswith("/")
            and all(seg not in ("", ".", "..") for seg in path.split("/")))


def paths_digest(paths):
    return digest_of(sorted(paths))


def check_paths(c):
    paths = c.trusted.observed["changed_paths"]
    protected = (list(c.policy["protected_paths"]) + list(c.policy["oracle_digests"])
                 + list(c.policy["guard_files"]))
    for path in paths:
        if not _well_formed(path):
            c.deny("PATH_MALFORMED")
        elif _matches(protected, path):
            c.deny("PROTECTED_PATH_TOUCHED")
        elif not _matches(c.terms["allowed_paths"], path):
            c.deny("PATH_OUTSIDE_ENVELOPE")


def interruption_charge(in_flight):
    return in_flight["reserve_units"]


def completion_charge(policy, evidence):
    return max(evidence["cost_units"], policy["min_attempt_charge_units"])


# ------------------------------------------------------------- review checks

def check_verdict_binding(c, v):
    obs, policy = c.trusted.observed, c.policy
    if v["task_id"] != c.task_id or v["repo"] != policy["repo"]:
        c.deny("VERDICT_BINDING_MISMATCH")
    if (v["guard_digest"] != policy["guard_digest"]
            or v["oracle_set_digest"] != digest_of(policy["oracle_digests"])):
        c.deny("VERDICT_BINDING_MISMATCH")
    if v["outcome"] != "PASS":
        c.deny("VERDICT_NOT_PASS")


def check_verdict_sha(c, v):
    if v["reviewed_sha"] != c.trusted.observed["head_sha"]:
        c.deny("REVIEW_STALE")


def check_verdict_freshness(c, v):
    done = c.state.completed.get(c.trusted.observed["head_sha"])
    if (v["issued_at"] > c.now or c.now - v["issued_at"] > c.policy["verdict_ttl_seconds"]
            or done is None or v["issued_at"] < done["completed_at"]):
        c.deny("REVIEW_STALE")


def check_reviewer_qualified(c, v):
    policy = c.policy
    principal = policy["principals"].get(v["reviewer_id"])
    if (v["reviewer_id"] not in policy["qualified_reviewers"] or principal is None
            or principal["kind"] != "reviewer"
            or v["reviewer_kind"] not in policy["allowed_reviewer_kinds"]):
        c.deny("REVIEWER_NOT_QUALIFIED")


def check_verdict_signature(c, v):
    if not verify(c.trusted.keyring, "verdict", v, "reviewer", v["reviewer_id"]):
        c.deny("VERDICT_SIGNATURE_INVALID")


def check_reviewer_conflict(c, v):
    obs, policy = c.trusted.observed, c.policy
    author = policy["principals"].get(obs["author_id"])
    reviewer = policy["principals"].get(v["reviewer_id"])
    if (v["reviewer_id"] == obs["author_id"] or v["declared_conflicts"]
            or v["reviewer_session_id"] == obs["author_session_id"]
            or author is None or reviewer is None
            or author["conflict_group"] == reviewer["conflict_group"]):
        c.deny("REVIEWER_CONFLICT")


def check_evidence(c, ev):
    obs, policy, fl = c.trusted.observed, c.policy, c.state.in_flight
    if ev["task_id"] != c.task_id or ev["head_sha"] != fl["head_sha"] or ev["head_sha"] != obs["head_sha"]:
        c.deny("HEAD_MISMATCH")
    if (ev["producer_id"] not in policy["trusted_evidence_producers"]
            or not verify(c.trusted.keyring, "evidence", ev, "evidence_producer", ev["producer_id"])):
        c.deny("EVIDENCE_PROVENANCE")
    if ev["issued_at"] > c.now or ev["issued_at"] < fl["started_at"]:
        c.deny("EVIDENCE_INVALID")


# --------------------------------------------------------------- action logic

def act_register(c):
    key = event_key(c.task_id, "REGISTER", "")
    check_dedupe(c, key)
    if c.state.registered:
        c.deny("TASK_ALREADY_REGISTERED")
    if c.envelope["nonce"] in c.state.nonces:
        c.deny("ENVELOPE_REPLAY")
    c.emit("TASK_REGISTERED", {"envelope_digest": c.envelope_digest,
                               "nonce": c.envelope["nonce"], "terms": c.terms}, key)


def act_start(c):
    obs = c.trusted.observed
    key = event_key(c.task_id, "START_ATTEMPT", obs["head_sha"])
    check_dedupe(c, key)
    if c.state.accepted_head is not None:
        c.deny("ALREADY_ACCEPTED")
    check_inflight(c)
    check_resume_required(c)
    check_retry_limit(c)
    check_budget(c)
    check_author(c)
    check_paths(c)
    c.emit("ATTEMPT_STARTED", {
        "attempt_no": c.state.attempts_started + 1, "head_sha": obs["head_sha"],
        "paths_digest": paths_digest(obs["changed_paths"]), "started_at": c.now,
        "reserve_units": c.policy["attempt_reserve_units"]}, key)


def act_complete(c):
    st = c.state
    ev = c.request["evidence"]
    key = event_key(c.task_id, "COMPLETE_ATTEMPT", ev["head_sha"])
    check_dedupe(c, key)
    if st.in_flight is None:
        c.deny("NO_IN_FLIGHT_ATTEMPT")
        return
    if c.now >= st.in_flight["started_at"] + c.policy["attempt_lease_seconds"]:
        c.deny("RECONCILE_REQUIRED")
    check_evidence(c, ev)
    charge = completion_charge(c.policy, ev)
    c.emit("ATTEMPT_COMPLETED", {
        "attempt_no": st.in_flight["attempt_no"], "head_sha": ev["head_sha"],
        "outcome": ev["outcome"], "cost_charged": charge, "completed_at": c.now,
        "evidence_sha256": digest_of(ev), "evidence_id": ev["evidence_id"]}, key)
    if st.spent + charge > c.terms["budget_ceiling_units"]:
        c.emit("BUDGET_STOP", {"spent": st.spent + charge,
                               "ceiling": c.terms["budget_ceiling_units"]})


def act_accept(c):
    st, obs, v = c.state, c.trusted.observed, c.request["verdict"]
    head = obs["head_sha"]
    key = event_key(c.task_id, "ACCEPT", head)
    check_dedupe(c, key)
    if st.accepted_head is not None:
        c.deny("ALREADY_ACCEPTED")
    check_inflight(c)
    last = st.last_attempt
    if last is None or last["head_sha"] != head:
        c.deny("HEAD_MISMATCH")
    done = st.completed.get(head)
    if done is None or done["outcome"] != "candidate_ready":
        c.deny("NOT_CANDIDATE_READY")
    started = st.started_heads.get(head)
    if started is None or started["paths_digest"] != paths_digest(obs["changed_paths"]):
        c.deny("PATHS_CHANGED_SINCE_START")
    check_author(c)
    check_paths(c)
    check_verdict_binding(c, v)
    check_verdict_sha(c, v)
    check_verdict_freshness(c, v)
    check_reviewer_qualified(c, v)
    check_verdict_signature(c, v)
    check_reviewer_conflict(c, v)
    c.emit("ACCEPTED", {"head_sha": head, "verdict_id": v["verdict_id"],
                        "verdict_digest": digest_of(v), "review_issued_at": v["issued_at"]}, key)


def act_resume(c):
    st, r = c.state, c.request["resume"]
    pending = st.needs_resume
    if pending is None:
        c.deny("RESUME_MISMATCH")
        return
    key = event_key(c.task_id, "RESUME", pending["event_hash"])
    check_dedupe(c, key)
    check_inflight(c)
    if (r["last_attempt_no"] != pending["attempt_no"] or r["last_head_sha"] != pending["head_sha"]
            or r["interruption_event_hash"] != pending["event_hash"]
            or r["envelope_digest"] != c.envelope_digest):
        c.deny("RESUME_MISMATCH")
    c.emit("RESUMED", {"last_attempt_no": pending["attempt_no"]}, key)


def act_reconcile(c):
    st = c.state
    if not st.registered:
        c.deny("TASK_NOT_REGISTERED")
        return
    if c.request["delivery_id"] in st.deliveries:
        c.deny("DUPLICATE_DELIVERY")
    terms = st.terms
    expired_now = c.now >= terms["expires_at"]
    terminated = expired_now or c.revoked_by_list or st.revoked or st.expired
    spent = st.spent
    fl = st.in_flight
    if fl is not None and (terminated or c.now >= fl["started_at"] + c.policy["attempt_lease_seconds"]):
        charge = interruption_charge(fl)
        c.emit("ATTEMPT_INTERRUPTED", {
            "attempt_no": fl["attempt_no"], "head_sha": fl["head_sha"],
            "cost_charged": charge, "reason": "terminated" if terminated else "lease_expired"})
        spent += charge
    if spent > terms["budget_ceiling_units"] and not st.budget_stopped:
        c.emit("BUDGET_STOP", {"spent": spent, "ceiling": terms["budget_ceiling_units"]})
    if c.revoked_by_list and not st.revoked:
        c.emit("TASK_REVOKED", {})
    if expired_now and not st.expired:
        c.emit("TASK_EXPIRED", {})


# --------------------------------------------------------------------- driver

def _internal_error_decision(request, exc):
    return Decision(False, _safe_str(request, "action"), _safe_str(request, "task_id"),
                    ("INTERNAL_ERROR",), (), {"error_type": type(exc).__name__})


def _finish(c):
    allow = not c.reasons
    prov = {"schema": "f0-guard/1", "now": c.now, "ledger_tip": c.ledger.tip,
            "policy_sha256": c.trusted.expected_policy_sha256 if isinstance(
                c.trusted.expected_policy_sha256, str) else "",
            "envelope_digest": c.envelope_digest or ""}
    if c.policy is not None and isinstance(c.trusted.observed, dict):
        prov["guard_digest"] = c.policy["guard_digest"]
        prov["head_sha"] = _safe_str(c.trusted.observed, "head_sha")
    return Decision(allow, _safe_str(c.request, "action"), _safe_str(c.request, "task_id"),
                    tuple(sorted(c.reasons)), tuple(c.events) if allow else (), prov)


def _evaluate(trusted, envelope, request, ledger, now):
    c = Ctx(trusted, envelope, request, ledger, now)
    if isinstance(now, bool) or not isinstance(now, int) or now < 0:
        c.deny("INPUT_INVALID", fatal=True)
        return _finish(c)
    check_policy_pin(c)
    if c.fatal:
        return _finish(c)
    check_inputs(c)
    if c.fatal:
        return _finish(c)
    check_guard_identity(c)
    check_oracle_identity(c)
    check_ledger_integrity(c)
    if c.fatal:
        return _finish(c)
    check_ledger_anchor(c)
    if c.fatal:
        return _finish(c)
    c.state = reduce_events(ledger.events, c.task_id)
    if c.action == "RECONCILE":
        check_revocation(c)
        act_reconcile(c)
        return _finish(c)
    check_owner_auth(c)
    if c.fatal:
        return _finish(c)
    check_repo_scope(c)
    check_branch_scope(c)
    check_limits(c)
    check_time_window(c)
    check_envelope_binding(c)
    if c.fatal:
        return _finish(c)
    check_revocation(c)
    check_task_active(c)
    if c.action == "REGISTER":
        act_register(c)
    elif c.action == "START_ATTEMPT":
        act_start(c)
    elif c.action == "COMPLETE_ATTEMPT":
        act_complete(c)
    elif c.action == "ACCEPT":
        act_accept(c)
    elif c.action == "RESUME":
        act_resume(c)
    return _finish(c)


def evaluate(trusted, envelope, request, ledger, now):
    """Pure decision. Fails closed: any unexpected exception becomes a DENY."""
    try:
        return _evaluate(trusted, envelope, request, ledger, now)
    except Exception as exc:  # noqa: BLE001 - fail closed by design
        return _internal_error_decision(request, exc)


def process(trusted, envelope, request, ledger, now):
    """Evaluate, then append atomically (compare-and-swap on the anchored tip)."""
    decision = evaluate(trusted, envelope, request, ledger, now)
    if not decision.allow or not decision.events:
        return Outcome(decision, False)
    try:
        ledger.append(decision.events, trusted.expected_tip, now)
    except LedgerConflict:
        return Outcome(replace(decision, allow=False, reasons=("LEDGER_CONFLICT",), events=()), False)
    return Outcome(decision, True)
