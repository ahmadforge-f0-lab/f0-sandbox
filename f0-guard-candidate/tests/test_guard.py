"""Deterministic local tests. No network, no credentials, no services."""
import ast
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from dataclasses import replace

from f0_guard import guard as G
from f0_guard.canon import canonical, digest_of
from f0_guard.identity import compute_identity_digest
from f0_guard.ledger import Ledger, LedgerConflict
from f0_guard.state import reduce_events
from tests.support import (BASE, GUARD_DIGEST, H1, H2, H3, H4, NOW0, ORACLE, REPO, World,
                           secret)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(path):
    with open(path) as fh:
        return fh.read()


class Base(unittest.TestCase):
    def deny(self, out, *codes):
        self.assertFalse(out.decision.allow, out.decision.reasons)
        self.assertFalse(out.applied)
        self.assertEqual(out.decision.events, ())
        for code in codes:
            self.assertIn(code, out.decision.reasons)

    def allow(self, out):
        self.assertTrue(out.decision.allow, out.decision.reasons)


class T01_ValidTask(Base):
    def test_full_flow_allowed_and_chain_valid(self):
        w = World()
        self.allow(w.register())
        self.allow(w.start())
        self.allow(w.complete())
        self.allow(w.accept())
        self.assertEqual(w.types(), ["TASK_REGISTERED", "ATTEMPT_STARTED", "ATTEMPT_COMPLETED", "ACCEPTED"])
        self.assertEqual(w.ledger.verify(), [])
        self.assertEqual(reduce_events(w.ledger.events, w.task_id).accepted_head, H1)

    def test_decisions_are_deterministic(self):
        digests = []
        for _ in range(2):
            w = World()
            run = [w.register(), w.start(), w.complete(), w.accept()]
            digests.append([o.decision.digest for o in run] + [w.ledger.tip])
        self.assertEqual(digests[0], digests[1])

    def test_evaluate_is_pure(self):
        w = World()
        before = w.ledger.tip
        d = w.run("REGISTER", NOW0 + 1, apply=False).decision
        self.assertTrue(d.allow)
        self.assertEqual(w.ledger.tip, before)


class T02_Scope(Base):
    def setUp(self):
        self.w = World()
        self.assertTrue(self.w.register().decision.allow)

    def test_wrong_repo_in_observed(self):
        self.w.observed = self.w.make_observed(repo="ahmadforge/f0-sandbox")
        self.deny(self.w.run("START_ATTEMPT", NOW0 + 5), "REPO_SCOPE_VIOLATION")

    def test_wrong_repo_in_signed_envelope(self):
        w = World()
        w.envelope = w.make_envelope(repo="someone/else")
        self.deny(w.register(), "REPO_SCOPE_VIOLATION")

    def test_protected_paths(self):
        for path in (".github/workflows/x.yml", "policy/rules.json", "src/secrets/k.txt",
                     "oracle/expected.json", "f0-guard-candidate/f0_guard/guard.py",
                     ".GitHub/Workflows/x.yml", "．github/workflows/x.yml"):
            with self.subTest(path=path):
                w = World()
                w.register()
                self.deny(w.start(paths=["src/a.py", path]), "PROTECTED_PATH_TOUCHED")

    def test_path_outside_envelope_and_malformed(self):
        for path, code in (("other/file.py", "PATH_OUTSIDE_ENVELOPE"), ("src/../.github/a", "PATH_MALFORMED"),
                           ("/etc/passwd", "PATH_MALFORMED"), ("src\\a.py", "PATH_MALFORMED"),
                           ("src//a.py", "PATH_MALFORMED"), ("docs/sub/x.md", "PATH_OUTSIDE_ENVELOPE")):
            with self.subTest(path=path):
                w = World()
                w.register()
                self.deny(w.start(paths=[path]), code)

    def test_protected_branch_as_work_branch(self):
        w = World()
        w.envelope = w.make_envelope(work_branch="main")
        w.observed = w.make_observed(branch="main")
        self.deny(w.register(), "BRANCH_SCOPE_VIOLATION")

    def test_wrong_base_sha_and_branch(self):
        self.w.observed = self.w.make_observed(base_sha="b" * 40)
        self.deny(self.w.run("START_ATTEMPT", NOW0 + 5), "BASE_SHA_MISMATCH")
        self.w.observed = self.w.make_observed(branch="claude/other")
        self.deny(self.w.run("START_ATTEMPT", NOW0 + 5), "BRANCH_SCOPE_VIOLATION")

    def test_unauthorized_author(self):
        for author in ("owner-1", "reviewer-1", "nobody"):
            with self.subTest(author=author):
                self.w.observed = self.w.make_observed(author_id=author)
                self.deny(self.w.run("START_ATTEMPT", NOW0 + 5), "AUTHOR_NOT_AUTHORIZED")


class T03_ForgedOwner(Base):
    def test_forged_envelope_variants(self):
        cases = {
            "wrong_secret": lambda w: w.make_envelope(secret_override=secret("attacker")),
            "reviewer_key_as_owner": lambda w: w.make_envelope(key_id="k-rev"),
            "unknown_key": lambda w: w.make_envelope(key_id="k-nope"),
        }
        for name, build in cases.items():
            with self.subTest(case=name):
                w = World()
                w.envelope = build(w)
                self.deny(w.register(), "OWNER_AUTH_INVALID")

    def test_tampered_after_signing(self):
        w = World()
        w.envelope["budget_ceiling_units"] = 900
        self.deny(w.register(), "OWNER_AUTH_INVALID")
        w = World()
        w.envelope["allowed_paths"] = ["**"]
        self.deny(w.register(), "OWNER_AUTH_INVALID")

    def test_owner_not_in_policy_and_policy_binding(self):
        w = World()
        w.envelope = w.make_envelope(owner_id="rogue-1")
        self.deny(w.register(), "OWNER_NOT_AUTHORIZED")
        w = World()
        w.envelope = w.make_envelope(policy_sha256="f" * 64)
        self.deny(w.register(), "ENVELOPE_POLICY_MISMATCH")

    def test_author_cannot_self_certify_through_request_fields(self):
        w = World()
        w.register()
        w.start()
        for extra in ({"accepted": True}, {"owner_approved": True}, {"verdict_override": "PASS"}):
            with self.subTest(extra=extra):
                req = dict(w.request("START_ATTEMPT"), **extra)
                self.deny(w.run("START_ATTEMPT", NOW0 + 50, request=req), "INPUT_INVALID")

    def test_envelope_replaced_after_registration(self):
        w = World()
        w.register()
        w.envelope = w.make_envelope(budget_ceiling_units=999)
        self.deny(w.start(), "ENVELOPE_DIGEST_MISMATCH")

    def test_envelope_exceeding_policy_caps(self):
        for over in ({"max_attempts": 50}, {"budget_ceiling_units": 5000},
                     {"expires_at": NOW0 + 10 ** 6}):
            with self.subTest(over=over):
                w = World()
                w.envelope = w.make_envelope(**over)
                self.deny(w.register(), "ENVELOPE_LIMITS_EXCEED_POLICY")


class T04_ForgedReviewer(Base):
    def setUp(self):
        self.w = World()
        self.w.to_ready()

    def test_valid_review_accepts(self):
        self.allow(self.w.accept())

    def test_self_appointed_reviewer(self):
        v = self.w.verdict(key="k-rogue", reviewer="rogue-1")
        self.deny(self.w.accept(verdict=v), "REVIEWER_NOT_QUALIFIED")

    def test_forged_signature(self):
        v = self.w.verdict(secret_override=secret("attacker"))
        self.deny(self.w.accept(verdict=v), "VERDICT_SIGNATURE_INVALID")
        v = self.w.verdict()
        v["outcome"] = "PASS"
        v["reviewer_session_id"] = "other"
        self.deny(self.w.accept(verdict=v), "VERDICT_SIGNATURE_INVALID")

    def test_verdict_signed_with_other_reviewers_key(self):
        v = self.w.verdict(key="k-rev-claude", reviewer="reviewer-1")
        self.deny(self.w.accept(verdict=v), "VERDICT_SIGNATURE_INVALID")

    def test_author_conflict_variants(self):
        cases = {
            "same_conflict_group": self.w.verdict(key="k-rev-claude", reviewer="reviewer-claude"),
            "same_session": self.w.verdict(session="sess-author"),
            "declared_conflict": self.w.verdict(conflicts=["shares-org-with-author"]),
        }
        for name, v in cases.items():
            with self.subTest(case=name):
                self.deny(self.w.accept(verdict=v), "REVIEWER_CONFLICT")

    def test_disallowed_kind_fail_verdict_and_wrong_task(self):
        w = World(allowed_reviewer_kinds=["human"])
        w.to_ready()
        self.deny(w.accept(), "REVIEWER_NOT_QUALIFIED")
        self.deny(self.w.accept(verdict=self.w.verdict(outcome="FAIL")), "VERDICT_NOT_PASS")
        self.deny(self.w.accept(verdict=self.w.verdict(task_id="task-999")), "VERDICT_BINDING_MISMATCH")

    def test_acceptance_requires_candidate_ready(self):
        w = World()
        w.register()
        w.start()
        w.complete(outcome="failed")
        self.deny(w.accept(), "NOT_CANDIDATE_READY")


class T05_StaleVerdict(Base):
    def test_old_head_verdict_reused_on_new_sha(self):
        w = World()
        w.register()
        w.start(H1)
        w.complete(H1, outcome="failed", now=NOW0 + 20)
        w.start(H2, now=NOW0 + 30)
        w.complete(H2, now=NOW0 + 40)
        old = w.verdict(H1, issued_at=NOW0 + 45)
        self.deny(w.accept(H2, now=NOW0 + 50, verdict=old), "REVIEW_STALE")
        self.allow(w.accept(H2, now=NOW0 + 50, verdict=w.verdict(H2, issued_at=NOW0 + 45)))

    def test_verdict_freshness_window(self):
        w = World()
        w.to_ready()
        self.deny(w.accept(verdict=w.verdict(issued_at=NOW0 + 19)), "REVIEW_STALE")       # before completion
        self.deny(w.accept(verdict=w.verdict(issued_at=NOW0 + 100), now=NOW0 + 40), "REVIEW_STALE")  # future
        self.deny(w.accept(verdict=w.verdict(issued_at=NOW0 + 30), now=NOW0 + 30 + 3601), "REVIEW_STALE")

    def test_verdict_bound_to_guard_and_oracle_identity(self):
        w = World()
        w.to_ready()
        self.deny(w.accept(verdict=w.verdict(oracle_digest="0" * 64)), "VERDICT_BINDING_MISMATCH")
        self.deny(w.accept(verdict=w.verdict(guard_digest="1" * 64)), "VERDICT_BINDING_MISMATCH")

    def test_head_changed_after_completion(self):
        w = World()
        w.to_ready()
        v = w.verdict(H1)
        w.observed = w.make_observed(head_sha=H3)
        self.deny(w.run("ACCEPT", NOW0 + 40, verdict=v), "HEAD_MISMATCH", "REVIEW_STALE")

    def test_paths_changed_after_start(self):
        w = World()
        w.to_ready()
        w.observed = w.make_observed(head_sha=H1, changed_paths=["src/a.py"])
        self.deny(w.run("ACCEPT", NOW0 + 40, verdict=w.verdict()), "PATHS_CHANGED_SINCE_START")


class T06_Identity(Base):
    def test_altered_oracle_identity(self):
        w = World()
        w.observed = w.make_observed(oracle_digests={"oracle/expected.json": "9" * 64})
        self.deny(w.run("REGISTER", NOW0 + 1), "ORACLE_IDENTITY_MISMATCH")

    def test_altered_guard_identity(self):
        w = World()
        w.observed = w.make_observed(guard_digest="8" * 64)
        self.deny(w.run("REGISTER", NOW0 + 1), "GUARD_IDENTITY_MISMATCH")

    def test_identity_digest_detects_file_change_and_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "guard.py")
            with open(path, "w") as fh:
                fh.write("print('v1')\n")
            before = compute_identity_digest(tmp, ["guard.py"])
            self.assertEqual(before, compute_identity_digest(tmp, ["guard.py"]))
            with open(path, "w") as fh:
                fh.write("print('v2')\n")
            self.assertNotEqual(before, compute_identity_digest(tmp, ["guard.py"]))
            os.symlink(path, os.path.join(tmp, "link.py"))
            with self.assertRaises(ValueError):
                compute_identity_digest(tmp, ["link.py"])
            with self.assertRaises(ValueError):
                compute_identity_digest(tmp, ["../x"])

    def test_policy_tampering_rejected_by_pin(self):
        w = World()
        evil = dict(w.policy, qualified_reviewers=["author-1"])
        self.deny(w.run("REGISTER", NOW0 + 1, trusted=w.trusted(policy=evil)), "POLICY_DIGEST_MISMATCH")
        self.deny(w.run("REGISTER", NOW0 + 1, trusted=w.trusted(policy={"x": 1})), "POLICY_INVALID")


class T02b_GlobLimits(Base):
    def test_wildcard_cap_applies_to_envelope_and_policy(self):
        w = World()
        w.envelope = w.make_envelope(allowed_paths=["*/*/*/*/*/*/*/x"])
        self.deny(w.register(), "INPUT_INVALID")
        evil = dict(w.policy, protected_paths=["*a*a*a*a*a*a*b"])
        self.deny(w.run("REGISTER", NOW0 + 1, trusted=w.trusted(policy=evil, policy_sha=digest_of(evil))),
                  "POLICY_INVALID")


class T07_Duplicates(Base):
    def test_same_head_distinct_delivery_ids(self):
        w = World()
        w.register()
        w.start()
        w.complete(outcome="failed")
        out = w.start(H1, now=NOW0 + 60)
        self.deny(out, "DUPLICATE_EVENT")
        self.assertEqual(w.types().count("ATTEMPT_STARTED"), 1)

    def test_replayed_delivery_id(self):
        w = World()
        w.register()
        first = w.request("START_ATTEMPT")
        w.observed = w.make_observed(head_sha=H1)
        self.allow(w.run("START_ATTEMPT", NOW0 + 10, request=first))
        w.complete(outcome="failed")
        w.observed = w.make_observed(head_sha=H2)
        self.deny(w.run("START_ATTEMPT", NOW0 + 60, request=first), "DUPLICATE_DELIVERY")

    def test_duplicate_accept_and_register(self):
        w = World()
        w.to_ready()
        self.allow(w.accept())
        self.deny(w.accept(now=NOW0 + 41), "ALREADY_ACCEPTED", "DUPLICATE_EVENT")
        self.assertEqual(w.types().count("ACCEPTED"), 1)
        self.deny(w.register(NOW0 + 50), "TASK_ALREADY_REGISTERED", "DUPLICATE_EVENT")

    def test_envelope_nonce_replay_for_new_task(self):
        w = World()
        w.register()
        w.task_id = "task-002"
        w.envelope = w.make_envelope(task_id="task-002")
        self.deny(w.register(NOW0 + 5), "ENVELOPE_REPLAY")


class T08_Concurrency(Base):
    def test_second_start_while_in_flight(self):
        w = World()
        w.register()
        w.start(H1)
        self.deny(w.start(H2, now=NOW0 + 15), "ATTEMPT_IN_FLIGHT")

    def test_cas_two_decisions_same_snapshot_only_one_applies(self):
        w = World()
        w.register()
        tip = w.ledger.tip
        decisions = []
        for head in (H1, H2):
            w.observed = w.make_observed(head_sha=head)
            d = w.run("START_ATTEMPT", NOW0 + 10, apply=False).decision
            self.assertTrue(d.allow)
            decisions.append(d)
        w.ledger.append(decisions[0].events, tip, NOW0 + 10)
        with self.assertRaises(LedgerConflict):
            w.ledger.append(decisions[1].events, tip, NOW0 + 10)
        self.assertEqual(w.types().count("ATTEMPT_STARTED"), 1)

    def test_threaded_race_yields_single_effect(self):
        w = World()
        w.register()
        tip = w.ledger.tip
        decisions = []
        for head in HEADS_FOR_RACE:
            w.observed = w.make_observed(head_sha=head)
            decisions.append(w.run("START_ATTEMPT", NOW0 + 10, apply=False).decision)
        barrier = threading.Barrier(len(decisions))
        results = []

        def attempt(d):
            barrier.wait()
            try:
                w.ledger.append(d.events, tip, NOW0 + 10)
                results.append("ok")
            except LedgerConflict:
                results.append("conflict")
        threads = [threading.Thread(target=attempt, args=(d,)) for d in decisions]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(sorted(results), ["conflict"] * (len(decisions) - 1) + ["ok"])
        self.assertEqual(w.types().count("ATTEMPT_STARTED"), 1)
        self.assertEqual(w.ledger.verify(), [])

    def test_process_reports_ledger_conflict(self):
        w = World()
        w.register()
        barrier = threading.Barrier(2)

        class Racing(Ledger):
            def append(self, specs, expected_tip, now):
                barrier.wait()
                return super().append(specs, expected_tip, now)
        w.ledger = Racing(w.ledger.events)
        outs = {}

        def worker(head):
            observed = w.make_observed(head_sha=head)
            req = w.request("START_ATTEMPT")
            outs[head] = G.process(w.trusted(observed=observed), w.envelope, req, w.ledger, NOW0 + 10)
        threads = [threading.Thread(target=worker, args=(h,)) for h in (H1, H2)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        applied = [o for o in outs.values() if o.applied]
        lost = [o for o in outs.values() if not o.applied]
        self.assertEqual((len(applied), len(lost)), (1, 1))
        self.assertEqual(lost[0].decision.reasons, ("LEDGER_CONFLICT",))
        self.assertEqual(w.types().count("ATTEMPT_STARTED"), 1)

    def test_stale_or_missing_anchor(self):
        w = World()
        w.register()
        self.deny(w.start_with_tip("f" * 64), "LEDGER_TIP_MISMATCH")
        self.deny(w.start_with_tip(None), "LEDGER_UNANCHORED")


HEADS_FOR_RACE = [H1, H2, H3, H4]


def _start_with_tip(self, tip):
    self.observed = self.make_observed(head_sha=H1)
    return self.run("START_ATTEMPT", NOW0 + 10, trusted=self.trusted(tip=tip))


World.start_with_tip = _start_with_tip


class T09_Retries(Base):
    def test_retry_exhaustion(self):
        w = World()
        w.register()
        w.fail_attempt(H1, NOW0 + 10)
        w.fail_attempt(H2, NOW0 + 40)
        w.fail_attempt(H3, NOW0 + 70)
        self.deny(w.start(H4, now=NOW0 + 100), "RETRY_EXHAUSTED")
        self.assertEqual(w.types().count("ATTEMPT_STARTED"), 3)

    def test_interrupted_attempts_count_toward_retries(self):
        w = World()
        w.register()
        t = NOW0 + 10
        for head in (H1, H2, H3):
            self.allow(w.start(head, now=t))
            t += 601
            self.allow(w.run("RECONCILE", t))
            self.allow(w.resume(t))
            t += 1
        self.deny(w.start(H4, now=t), "RETRY_EXHAUSTED")


class T10_ExpiryRevocation(Base):
    def test_expired_task(self):
        w = World()
        w.register()
        self.allow(w.start(now=NOW0 + 3599))
        w2 = World()
        w2.register()
        self.deny(w2.start(now=NOW0 + 3600), "TASK_EXPIRED")
        w3 = World()
        self.deny(w3.register(now=NOW0 + 4000), "TASK_EXPIRED")
        self.deny(World().register(now=NOW0 - 1), "TASK_NOT_YET_VALID")

    def test_complete_and_accept_denied_after_expiry(self):
        w = World()
        w.register()
        w.start()
        self.deny(w.complete(now=NOW0 + 3700), "TASK_EXPIRED")
        w2 = World()
        w2.to_ready()
        self.deny(w2.accept(now=NOW0 + 3700, verdict=w2.verdict(issued_at=NOW0 + 3690)), "TASK_EXPIRED")

    def test_revoked_by_signed_list(self):
        w = World()
        w.register()
        w.revocations = w.make_revocations([w.task_id])
        self.deny(w.start(), "TASK_REVOKED")

    def test_forged_or_missing_revocation_status_fails_closed(self):
        w = World()
        w.register()
        w.revocations = w.make_revocations([], secret_override=secret("attacker"))
        self.deny(w.start(), "REVOCATION_LIST_INVALID")
        w.revocations = None
        self.deny(w.start(), "REVOCATION_STATUS_UNAVAILABLE")

    def test_stale_revocation_list_replay_fails_closed(self):
        w = World()
        w.envelope = w.make_envelope(expires_at=NOW0 + 80000)
        w.register()
        w.revocations = w.make_revocations([], issued_at=NOW0)          # old "not revoked" list
        self.allow(w.start(H1, now=NOW0 + 7200))
        w.complete(H1, outcome="failed", now=NOW0 + 7210)
        self.deny(w.start(H2, now=NOW0 + 7201 + 100), "REVOCATION_LIST_STALE")

    def test_unusable_revocation_list_never_blocks_reconcile(self):
        w = World()
        w.register()
        w.start()
        w.revocations = w.make_revocations([w.task_id], secret_override=secret("attacker"))
        out = w.run("RECONCILE", NOW0 + 700)
        self.allow(out)
        self.assertNotIn("TASK_REVOKED", w.types())          # forged list is ignored, not obeyed
        self.assertIn("ATTEMPT_INTERRUPTED", w.types())      # recovery still proceeds
        w.revocations = None
        self.allow(w.run("RECONCILE", NOW0 + 701))

    def test_revocation_is_sticky_once_recorded(self):
        w = World()
        w.register()
        w.start()
        w.revocations = w.make_revocations([w.task_id])
        self.allow(w.run("RECONCILE", NOW0 + 15))
        self.assertIn("TASK_REVOKED", w.types())
        self.assertIn("ATTEMPT_INTERRUPTED", w.types())
        w.revocations = w.make_revocations([])
        self.deny(w.start(H2, now=NOW0 + 20), "TASK_REVOKED")

    def test_reconcile_records_expiry_and_closes_in_flight(self):
        w = World()
        w.register()
        w.start()
        self.allow(w.run("RECONCILE", NOW0 + 3601))
        self.assertEqual(w.types()[-2:], ["ATTEMPT_INTERRUPTED", "TASK_EXPIRED"])


class T11_Budget(Base):
    def test_reserve_exceeds_remaining_budget(self):
        w = World()
        w.envelope = w.make_envelope(budget_ceiling_units=150)
        w.register()
        w.start(H1)
        w.complete(H1, outcome="failed", cost=60)
        self.deny(w.start(H2, now=NOW0 + 30), "BUDGET_EXCEEDED")

    def test_budget_stop_after_overrun(self):
        w = World()
        w.envelope = w.make_envelope(budget_ceiling_units=300)
        w.register()
        w.start(H1)
        self.allow(w.complete(H1, outcome="failed", cost=150))
        w.start(H2, now=NOW0 + 30)
        self.allow(w.complete(H2, outcome="candidate_ready", cost=400, now=NOW0 + 40))
        self.assertEqual(w.types()[-2:], ["ATTEMPT_COMPLETED", "BUDGET_STOP"])
        self.deny(w.start(H3, now=NOW0 + 50), "BUDGET_STOPPED")
        self.deny(w.accept(H2, now=NOW0 + 60, verdict=w.verdict(H2, issued_at=NOW0 + 55)), "BUDGET_STOPPED")

    def test_fail_closed_on_internal_error(self):
        w = World()
        original = G.check_budget
        G.check_budget = lambda c: (_ for _ in ()).throw(RuntimeError("boom"))
        try:
            w.register()
            out = w.start()
        finally:
            G.check_budget = original
        self.deny(out, "INTERNAL_ERROR")

    def test_fail_closed_on_malformed_inputs(self):
        w = World()
        w.register()
        cases = [
            ("none_envelope", dict(envelope=None)),
            ("garbage_request", dict(request={"action": "START_ATTEMPT"})),
            ("bad_action", dict(request=dict(w.request("START_ATTEMPT"), action="MERGE"))),
        ]
        for name, kw in cases:
            with self.subTest(case=name):
                self.deny(w.run("START_ATTEMPT", NOW0 + 10, **kw))
        for bad_now in (-1, True, 1.5, "x", None):
            with self.subTest(now=bad_now):
                self.deny(w.run("START_ATTEMPT", bad_now), "INPUT_INVALID")

    def test_malformed_evidence_cost_rejected(self):
        w = World()
        w.register()
        w.start()
        for cost in (-5, 1.5, "10", True):
            with self.subTest(cost=cost):
                ev = dict(w.evidence(), cost_units=cost, signature="0" * 64)
                self.deny(w.run("COMPLETE_ATTEMPT", NOW0 + 20, evidence=ev), "INPUT_INVALID")

    def test_forged_evidence_rejected(self):
        w = World()
        w.register()
        w.start()
        self.deny(w.run("COMPLETE_ATTEMPT", NOW0 + 20, evidence=w.evidence(secret_override=secret("x"))),
                  "EVIDENCE_PROVENANCE")
        self.deny(w.run("COMPLETE_ATTEMPT", NOW0 + 20, evidence=w.evidence(head=H2)), "HEAD_MISMATCH")
        self.deny(w.run("COMPLETE_ATTEMPT", NOW0 + 20, evidence=w.evidence(issued_at=NOW0 + 1)),
                  "EVIDENCE_INVALID")

    def test_min_charge_applies(self):
        w = World()
        w.register()
        w.start()
        w.complete(cost=0)
        st = reduce_events(w.ledger.events, w.task_id)
        self.assertEqual(st.spent, w.policy["min_attempt_charge_units"])


def _resume(self, now):
    st = reduce_events(self.ledger.events, self.task_id)
    pending = st.needs_resume
    return self.run("RESUME", now, resume={
        "last_attempt_no": pending["attempt_no"], "last_head_sha": pending["head_sha"],
        "envelope_digest": digest_of(self.envelope), "interruption_event_hash": pending["event_hash"]})


World.resume = _resume


class T12_Recovery(Base):
    def interrupted(self):
        w = World()
        w.register()
        w.start(H1, now=NOW0 + 10)
        return w

    def test_reconcile_before_lease_is_noop_after_lease_interrupts_once(self):
        w = self.interrupted()
        out = w.run("RECONCILE", NOW0 + 10 + 599)
        self.allow(out)
        self.assertEqual(out.decision.events, ())
        out = w.run("RECONCILE", NOW0 + 10 + 600)
        self.allow(out)
        self.assertEqual([e["kind"] for e in out.decision.events], ["ATTEMPT_INTERRUPTED"])
        self.assertEqual(out.decision.events[0]["payload"]["cost_charged"], 100)
        again = w.run("RECONCILE", NOW0 + 700)
        self.assertEqual(again.decision.events, ())
        self.assertEqual(w.types().count("ATTEMPT_INTERRUPTED"), 1)

    def test_no_progress_until_resume_with_reconstructed_identity(self):
        w = self.interrupted()
        self.deny(w.start(H2, now=NOW0 + 20), "ATTEMPT_IN_FLIGHT")
        self.deny(w.start(H2, now=NOW0 + 700), "ATTEMPT_IN_FLIGHT", "RECONCILE_REQUIRED")
        w.run("RECONCILE", NOW0 + 700)
        self.deny(w.start(H2, now=NOW0 + 701), "RESUME_REQUIRED")
        st = reduce_events(w.ledger.events, w.task_id)
        good = {"last_attempt_no": 1, "last_head_sha": H1, "envelope_digest": digest_of(w.envelope),
                "interruption_event_hash": st.needs_resume["event_hash"]}
        for field, bad in (("last_attempt_no", 2), ("last_head_sha", H3), ("envelope_digest", "0" * 64),
                           ("interruption_event_hash", "1" * 64)):
            with self.subTest(field=field):
                self.deny(w.run("RESUME", NOW0 + 702, resume=dict(good, **{field: bad})), "RESUME_MISMATCH")
        self.allow(w.run("RESUME", NOW0 + 702, resume=good))
        self.allow(w.start(H2, now=NOW0 + 703))
        self.assertEqual(reduce_events(w.ledger.events, w.task_id).spent, 100)

    def test_resume_without_pending_interruption_denied(self):
        w = World()
        w.register()
        resume = {"last_attempt_no": 1, "last_head_sha": H1, "envelope_digest": digest_of(w.envelope),
                  "interruption_event_hash": "2" * 64}
        self.deny(w.run("RESUME", NOW0 + 5, resume=resume), "RESUME_MISMATCH")

    def test_late_completion_after_lease_requires_reconcile(self):
        w = self.interrupted()
        self.deny(w.complete(H1, now=NOW0 + 10 + 601), "RECONCILE_REQUIRED")

    def test_state_reconstructed_from_persisted_ledger_matches(self):
        w = self.interrupted()
        w.run("RECONCILE", NOW0 + 700)
        reloaded = Ledger.from_jsonl(w.ledger.to_jsonl())
        self.assertEqual(reloaded.tip, w.ledger.tip)
        self.assertEqual(reloaded.verify(), [])
        self.assertEqual(reduce_events(reloaded.events, w.task_id).snapshot(),
                         reduce_events(w.ledger.events, w.task_id).snapshot())
        w.ledger = reloaded
        self.deny(w.start(H2, now=NOW0 + 701), "RESUME_REQUIRED")

    def test_tampered_and_truncated_ledger(self):
        w = World()
        w.to_ready()
        w.ledger.events[2]["payload"]["cost_charged"] = 0
        self.deny(w.run("RECONCILE", NOW0 + 50, trusted=w.trusted(tip=w.ledger.tip)), "LEDGER_CORRUPT")
        w = World()
        w.to_ready()
        anchored = w.ledger.tip
        w.ledger = Ledger(w.ledger.events[:-1])
        self.deny(w.run("RECONCILE", NOW0 + 50, trusted=w.trusted(tip=anchored)), "LEDGER_TIP_MISMATCH")

    def test_reconcile_unknown_task_denied(self):
        w = World()
        self.deny(w.run("RECONCILE", NOW0 + 5), "TASK_NOT_REGISTERED")


class T14_Invariants(Base):
    """Seeded random action sequences; global safety invariants must always hold."""

    def check_invariants(self, w, max_attempts):
        events = w.ledger.events
        self.assertEqual(w.ledger.verify(), [])
        kinds = [e["kind"] for e in events]
        self.assertLessEqual(kinds.count("ACCEPTED"), 1)
        self.assertLessEqual(kinds.count("ATTEMPT_STARTED"), max_attempts)
        self.assertLessEqual(kinds.count("TASK_REGISTERED"), 1)
        keys = [e["event_key"] for e in events if e["event_key"]]
        self.assertEqual(len(keys), len(set(keys)))
        deliveries = [e["delivery_id"] for e in events if e["delivery_id"]]
        self.assertEqual(len(deliveries), len(set(deliveries)))
        stopped = False
        open_attempt = False
        for e in events:
            if stopped:
                self.assertNotIn(e["kind"], ("ATTEMPT_STARTED", "ACCEPTED", "RESUMED"))
            if e["kind"] in ("BUDGET_STOP", "TASK_EXPIRED", "TASK_REVOKED"):
                stopped = True
            if e["kind"] == "ATTEMPT_STARTED":
                self.assertFalse(open_attempt)
                open_attempt = True
            elif e["kind"] in ("ATTEMPT_COMPLETED", "ATTEMPT_INTERRUPTED"):
                self.assertTrue(open_attempt)
                open_attempt = False
        st = reduce_events(events, w.task_id)
        charged = sum(e["payload"].get("cost_charged", 0) for e in events
                      if e["kind"] in ("ATTEMPT_COMPLETED", "ATTEMPT_INTERRUPTED"))
        self.assertEqual(st.spent, charged)
        if st.accepted_head:
            self.assertEqual(st.completed[st.accepted_head]["outcome"], "candidate_ready")

    def test_random_sequences(self):
        import random
        from tests.support import HEADS
        seen = set()
        for seed in range(200):
            rng = random.Random(seed)
            w = World()
            w.envelope = w.make_envelope(max_attempts=rng.randint(1, 4), expires_at=NOW0 + 20000,
                                         budget_ceiling_units=rng.choice([150, 300, 500]))
            t = NOW0 + 1
            used = []
            for _ in range(40):
                t += rng.choice([1, 2, 5, 20, 100, 650, 5000])
                st = reduce_events(w.ledger.events, w.task_id)
                unused = [h for h in HEADS if h not in used]
                head = (st.last_attempt or {}).get("head_sha") if rng.random() < 0.7 else rng.choice(HEADS)
                head = head or HEADS[0]
                roll = rng.random()
                if roll < 0.12 and getattr(w, "last", None):                     # exact redelivery
                    action, req, env = w.last
                    w.run(action, t, envelope=env, request=req)
                elif roll < 0.25:
                    w.run("RECONCILE", t)
                elif not st.registered:
                    w.register(t)
                elif st.needs_resume:
                    w.resume(t)
                elif st.in_flight:
                    w.complete(st.in_flight["head_sha"], outcome=rng.choice(["candidate_ready", "failed"]),
                               cost=rng.choice([0, 20, 90, 300]), now=t)
                elif st.last_attempt and st.last_attempt["outcome"] == "candidate_ready" and roll < 0.8:
                    w.accept(st.last_attempt["head_sha"], now=t, verdict=w.verdict(st.last_attempt["head_sha"], issued_at=t))
                elif unused:
                    used.append(unused[0])
                    w.start(unused[0], now=t)
                else:
                    w.accept(head, now=t, verdict=w.verdict(head, issued_at=t))
                if rng.random() < 0.01:
                    w.revocations = w.make_revocations([w.task_id], issued_at=t)
                self.check_invariants(w, w.envelope["max_attempts"])
            seen.update(e["kind"] for e in w.ledger.events)
        # the walk must actually reach the interesting states, otherwise the invariants are vacuous
        self.assertGreaterEqual(seen, {"ACCEPTED", "BUDGET_STOP", "ATTEMPT_INTERRUPTED", "RESUMED",
                                       "TASK_EXPIRED", "TASK_REVOKED", "ATTEMPT_COMPLETED"})


class T13_Hygiene(Base):
    def test_no_network_or_process_imports(self):
        banned = {"socket", "urllib", "http", "requests", "subprocess", "ssl", "ftplib", "smtplib",
                  "asyncio", "multiprocessing", "ctypes"}
        pkg = os.path.join(ROOT, "f0_guard")
        for name in sorted(os.listdir(pkg)):
            if not name.endswith(".py"):
                continue
            with open(os.path.join(pkg, name)) as fh:
                tree = ast.parse(fh.read())
            for node in ast.walk(tree):
                mods = []
                if isinstance(node, ast.Import):
                    mods = [a.name.split(".")[0] for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    mods = [(node.module or "").split(".")[0]]
                self.assertFalse(set(mods) & banned, "%s imports %s" % (name, mods))

    def test_no_workflow_files_anywhere_in_repo(self):
        repo = os.path.dirname(ROOT)
        self.assertFalse(os.path.exists(os.path.join(repo, ".github", "workflows")))

    def test_cli_exit_codes_and_hashseed_independence(self):
        import json
        w = World()
        with tempfile.TemporaryDirectory() as tmp:
            def dump(name, obj):
                p = os.path.join(tmp, name)
                with open(p, "w") as fh:
                    fh.write(json.dumps(obj))
                return p
            trusted = dump("t.json", {"policy": w.policy, "expected_policy_sha256": w.policy_sha,
                                      "keyring": w.keyring, "observed": w.observed,
                                      "expected_tip": w.ledger.tip, "revocations": w.revocations})
            env = dump("e.json", w.envelope)
            req = dump("r.json", w.request("REGISTER"))
            ledger = os.path.join(tmp, "l.jsonl")

            def run(seed, *extra):
                e = dict(os.environ, PYTHONHASHSEED=str(seed))
                return subprocess.run([sys.executable, "-m", "f0_guard", "--trusted", trusted, "--envelope", env,
                                       "--request", req, "--ledger", ledger, "--now", str(NOW0 + 1), *extra],
                                      cwd=ROOT, env=e, capture_output=True, text=True)
            a, b = run(1), run(2)
            self.assertEqual((a.returncode, b.returncode), (0, 0))
            self.assertEqual(a.stdout, b.stdout)
            self.assertFalse(os.path.exists(ledger))          # dry run writes nothing
            applied = run(3, "--apply")
            self.assertEqual(applied.returncode, 0)
            self.assertEqual(len(Ledger.from_jsonl(_read(ledger)).events), 1)
            # ledger tip moved but trusted anchor is stale -> deny, exit 2, no write
            again = run(4, "--apply")
            self.assertEqual(again.returncode, 2)
            self.assertIn("LEDGER_TIP_MISMATCH", again.stdout)
            self.assertEqual(len(Ledger.from_jsonl(_read(ledger)).events), 1)
            bad = subprocess.run([sys.executable, "-m", "f0_guard", "--trusted", "/nonexistent",
                                  "--request", req, "--ledger", ledger, "--now", "1"],
                                 cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(bad.returncode, 3)


if __name__ == "__main__":
    unittest.main()
