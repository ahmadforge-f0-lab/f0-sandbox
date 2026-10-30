"""Synthetic fixtures. All keys/ids/SHAs are fake, derived from fixed labels."""
import copy
import hashlib

from f0_guard.canon import digest_of
from f0_guard.guard import Outcome, TrustedContext, evaluate, process
from f0_guard.ledger import Ledger
from f0_guard.signing import sign

REPO = "ahmadforge-f0-lab/f0-sandbox"
NOW0 = 1_800_000_000
BASE = "d0f6e147e9e52ec911331b18c9f61091b7594edd"
HEADS = ["%040x" % (0xa1 + i) for i in range(8)]
H1, H2, H3, H4 = HEADS[:4]
ORACLE = {"oracle/expected.json": hashlib.sha256(b"oracle-v1").hexdigest()}
GUARD_DIGEST = hashlib.sha256(b"guard-v1").hexdigest()


def secret(label):
    return hashlib.sha256(("synthetic-secret|" + label).encode()).digest()


def make_policy():
    return {
        "policy_version": "p1", "repo": REPO, "default_branch": "main",
        "protected_branches": ["main"], "work_branch_prefix": "claude/",
        "owners": ["owner-1"],
        "principals": {
            "owner-1": {"kind": "owner", "conflict_group": "g-owner"},
            "author-1": {"kind": "author_agent", "conflict_group": "g-claude"},
            "reviewer-1": {"kind": "reviewer", "conflict_group": "g-other"},
            "reviewer-claude": {"kind": "reviewer", "conflict_group": "g-claude"},
            "rogue-1": {"kind": "reviewer", "conflict_group": "g-rogue"},
            "meter-1": {"kind": "evidence_producer", "conflict_group": "g-meter"},
        },
        "qualified_reviewers": ["reviewer-1", "reviewer-claude"],
        "allowed_reviewer_kinds": ["human", "independent_model"],
        "trusted_evidence_producers": ["meter-1"],
        "protected_paths": [".github/**", "policy/**", "**/secrets/**"],
        "guard_files": ["f0-guard-candidate/f0_guard/guard.py"],
        "guard_digest": GUARD_DIGEST, "oracle_digests": dict(ORACLE),
        "max_attempts_cap": 5, "budget_cap_units": 1000,
        "attempt_reserve_units": 100, "min_attempt_charge_units": 10,
        "max_task_ttl_seconds": 86400, "attempt_lease_seconds": 600,
        "verdict_ttl_seconds": 3600,
        "revocation_max_age_seconds": 7200,
    }


KEYS = {  # key_id -> (role, principal)
    "k-owner": ("owner", "owner-1"),
    "k-rev": ("reviewer", "reviewer-1"),
    "k-rev-claude": ("reviewer", "reviewer-claude"),
    "k-rogue": ("reviewer", "rogue-1"),
    "k-ev": ("evidence_producer", "meter-1"),
}


def make_keyring():
    return {kid: {"role": role, "principal": who, "secret_hex": secret(kid).hex()}
            for kid, (role, who) in KEYS.items()}


def signed(kind, body, key_id, secret_override=None):
    body = dict(body, key_id=key_id)
    sec = secret_override if secret_override is not None else secret(key_id)
    body["signature"] = sign(sec, kind, body)
    return body


class World:
    def __init__(self, **policy_over):
        self.policy = make_policy()
        self.policy.update(policy_over)
        self.policy_sha = digest_of(self.policy)
        self.keyring = make_keyring()
        self.ledger = Ledger()
        self.task_id = "task-001"
        self.envelope = self.make_envelope()
        self.observed = self.make_observed()
        self.revocations = self.make_revocations([])
        self.n = 0

    # -- builders
    def make_envelope(self, key_id="k-owner", secret_override=None, **over):
        body = {
            "task_id": self.task_id, "owner_id": "owner-1", "repo": REPO,
            "base_branch": "main", "base_sha": BASE, "work_branch": "claude/task-001",
            "allowed_paths": ["src/**", "docs/*.md"], "max_attempts": 3,
            "budget_ceiling_units": 500, "issued_at": NOW0,
            "expires_at": NOW0 + 3600, "nonce": "%032x" % 0xabc,
            "policy_sha256": self.policy_sha}
        body.update(over)
        return signed("envelope", body, key_id, secret_override)

    def make_observed(self, **over):
        o = {"repo": REPO, "branch": "claude/task-001", "head_sha": H1, "base_sha": BASE,
             "author_id": "author-1", "author_session_id": "sess-author",
             "guard_digest": GUARD_DIGEST, "oracle_digests": dict(ORACLE),
             "changed_paths": ["src/a.py", "docs/x.md"]}
        o.update(over)
        return o

    def make_revocations(self, task_ids, key_id="k-owner", secret_override=None, issued_at=NOW0):
        body = {"task_ids": task_ids, "issued_at": issued_at, "owner_id": "owner-1"}
        return signed("revocation", body, key_id, secret_override)

    def evidence(self, head=H1, outcome="candidate_ready", cost=50, issued_at=None,
                 key="k-ev", producer="meter-1", secret_override=None, task_id=None):
        body = {"evidence_id": "ev-%s" % head[-4:], "task_id": task_id or self.task_id,
                "head_sha": head, "outcome": outcome, "cost_units": cost,
                "artifact_sha256": hashlib.sha256(head.encode()).hexdigest(),
                "producer_id": producer, "issued_at": NOW0 + 20 if issued_at is None else issued_at}
        return signed("evidence", body, key, secret_override)

    def verdict(self, head=H1, key="k-rev", reviewer="reviewer-1", issued_at=None, outcome="PASS",
                kind="independent_model", session="sess-reviewer", conflicts=(), task_id=None,
                secret_override=None, oracle_digest=None, guard_digest=None):
        body = {"verdict_id": "vd-%s" % head[-4:], "task_id": task_id or self.task_id,
                "repo": REPO, "reviewed_sha": head, "outcome": outcome,
                "reviewer_id": reviewer, "reviewer_kind": kind, "reviewer_session_id": session,
                "declared_conflicts": list(conflicts),
                "guard_digest": guard_digest or GUARD_DIGEST,
                "oracle_set_digest": oracle_digest or digest_of(ORACLE),
                "issued_at": NOW0 + 30 if issued_at is None else issued_at}
        return signed("verdict", body, key, secret_override)

    # -- driving
    def trusted(self, tip="auto", revocations="auto", observed=None, keyring=None, policy=None,
                policy_sha=None):
        return TrustedContext(
            policy=policy or self.policy,
            expected_policy_sha256=policy_sha or self.policy_sha,
            keyring=keyring or self.keyring,
            observed=observed or self.observed,
            expected_tip=self.ledger.tip if tip == "auto" else tip,
            revocations=self.revocations if revocations == "auto" else revocations,
            caller_id="owner-1")

    def request(self, action, **payload):
        self.n += 1
        req = {"action": action, "task_id": self.task_id, "delivery_id": "d-%03d" % self.n}
        req.update(payload)
        return req

    def run(self, action, now, envelope="auto", trusted=None, apply=True, request=None, **payload):
        env = self.envelope if envelope == "auto" and action != "RECONCILE" else (
            None if envelope == "auto" else envelope)
        req = request or self.request(action, **payload)
        self.last = (action, req, env)
        if apply:
            return process(trusted or self.trusted(), env, req, self.ledger, now)
        return Outcome(evaluate(trusted or self.trusted(), env, req, self.ledger, now), False)

    # -- flows
    def register(self, now=NOW0 + 1):
        return self.run("REGISTER", now)

    def start(self, head=H1, now=NOW0 + 10, paths=None):
        self.observed = self.make_observed(head_sha=head, **({"changed_paths": paths} if paths else {}))
        return self.run("START_ATTEMPT", now)

    def complete(self, head=H1, outcome="candidate_ready", cost=50, now=NOW0 + 20, **kw):
        self.observed = self.make_observed(head_sha=head)
        return self.run("COMPLETE_ATTEMPT", now,
                        evidence=self.evidence(head, outcome, cost, issued_at=now, **kw))

    def accept(self, head=H1, now=NOW0 + 40, verdict=None):
        self.observed = self.make_observed(head_sha=head)
        return self.run("ACCEPT", now, verdict=verdict or self.verdict(head))

    def to_ready(self, head=H1):
        assert self.register().decision.allow
        assert self.start(head).decision.allow
        assert self.complete(head).decision.allow

    def fail_attempt(self, head, t):
        out = self.start(head, now=t)
        assert out.decision.allow, out.decision.reasons
        out = self.complete(head, outcome="failed", cost=10, now=t + 5)
        assert out.decision.allow, out.decision.reasons

    def types(self):
        return [e["kind"] for e in self.ledger.events]


def snapshot_ledger(w):
    return copy.deepcopy(w.ledger.events)
