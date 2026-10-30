"""Negative controls: deliberately defective guard variants (mutants).

For each mutant a specific control is defeated in-process; the unchanged test
suite MUST then fail in at least one of the named tests. A surviving mutant
means the suite cannot detect that class of defect.
Usage: python3 -m tests.negative_controls [--json out.json]
"""
import io
import json
import sys
import unittest
from unittest import mock

from f0_guard import guard as G
from f0_guard.ledger import Ledger, LedgerConflict, GENESIS  # noqa: F401
from f0_guard.guard import Decision

T = "tests.test_guard."


def noop(*_a, **_k):
    return None


def owner_auth_without_signature(c):
    env = c.envelope
    if env["policy_sha256"] != c.trusted.expected_policy_sha256:
        c.deny("ENVELOPE_POLICY_MISMATCH")
    if env["owner_id"] not in c.policy["owners"]:
        c.deny("OWNER_NOT_AUTHORIZED", fatal=True)


def paths_without_protected(c):
    for path in c.trusted.observed["changed_paths"]:
        if not G._well_formed(path):
            c.deny("PATH_MALFORMED")
        elif not G._matches(c.terms["allowed_paths"], path):
            c.deny("PATH_OUTSIDE_ENVELOPE")


def policy_pin_without_digest(c):
    c.policy = c.trusted.policy


def task_active_without_expiry(c):
    if c.state.revoked:
        c.deny("TASK_REVOKED")
    if c.state.budget_stopped:
        c.deny("BUDGET_STOPPED")


def task_active_without_budget_stop(c):
    if c.now >= c.terms["expires_at"] or c.state.expired:
        c.deny("TASK_EXPIRED")
    if c.state.revoked:
        c.deny("TASK_REVOKED")


def revocation_ignores_age(c):
    rv = c.trusted.revocations
    if rv is not None and c.now - rv["issued_at"] > c.policy["revocation_max_age_seconds"]:
        if c.action != "RECONCILE":
            return  # accepts a stale list as if fresh and "not revoked"
    return ORIGINAL["check_revocation"](c)


def revocation_invalid_blocks_reconcile(c):
    rv = c.trusted.revocations
    if c.action == "RECONCILE" and rv is not None and not G.verify(
            c.trusted.keyring, "revocation", rv, "owner", rv["owner_id"]):
        c.deny("REVOCATION_LIST_INVALID")
        return
    return ORIGINAL["check_revocation"](c)


def revocation_fail_open(c):
    if c.trusted.revocations is None:
        return
    return ORIGINAL["check_revocation"](c)


def envelope_binding_without_digest_compare(c):
    c.envelope_digest = G.digest_of(c.envelope)
    c.terms = c.state.terms if c.state.registered else {
        "repo": c.envelope["repo"], "work_branch": c.envelope["work_branch"],
        "base_sha": c.envelope["base_sha"], "allowed_paths": c.envelope["allowed_paths"],
        "max_attempts": c.envelope["max_attempts"],
        "budget_ceiling_units": c.envelope["budget_ceiling_units"],
        "expires_at": c.envelope["expires_at"]}


def append_without_cas(self, specs, expected_tip, now):
    with self._lock:
        added, prev, seq = [], self.tip, len(self.events)
        for spec in specs:
            from f0_guard.ledger import event_hash
            event = {"seq": seq, "prev": prev, "ts": now, "kind": spec["kind"],
                     "task_id": spec["task_id"], "payload": spec["payload"],
                     "event_key": spec.get("event_key"), "delivery_id": spec.get("delivery_id")}
            event["hash"] = event_hash(event)
            added.append(event)
            prev, seq = event["hash"], seq + 1
        self.events.extend(added)
        return added


def internal_error_fail_open(request, exc):
    return Decision(True, "", "", (), (), {})


def retry_off_by_one(c):
    if c.state.attempts_started > c.terms["max_attempts"]:
        c.deny("RETRY_EXHAUSTED")


ORIGINAL = {name: getattr(G, name) for name in dir(G) if name.startswith(("check_", "act_"))}

MUTANTS = [
    ("owner_signature_not_verified", [(G, "check_owner_auth", owner_auth_without_signature)],
     [T + "T03_ForgedOwner.test_forged_envelope_variants", T + "T03_ForgedOwner.test_tampered_after_signing"]),
    ("repo_scope_removed", [(G, "check_repo_scope", noop)],
     [T + "T02_Scope.test_wrong_repo_in_observed", T + "T02_Scope.test_wrong_repo_in_signed_envelope"]),
    ("branch_scope_removed", [(G, "check_branch_scope", noop)],
     [T + "T02_Scope.test_protected_branch_as_work_branch", T + "T02_Scope.test_wrong_base_sha_and_branch"]),
    ("protected_paths_not_enforced", [(G, "check_paths", paths_without_protected)],
     [T + "T02_Scope.test_protected_paths"]),
    ("path_case_unicode_folding_removed", [(G, "_fold", lambda p: p)],
     [T + "T02_Scope.test_protected_paths"]),
    ("author_check_removed", [(G, "check_author", noop)], [T + "T02_Scope.test_unauthorized_author"]),
    ("request_schema_permissive_self_certify", [(G, "REQUEST_SCHEMA", noop)],
     [T + "T03_ForgedOwner.test_author_cannot_self_certify_through_request_fields"]),
    ("envelope_swap_after_registration", [(G, "check_envelope_binding", envelope_binding_without_digest_compare)],
     [T + "T03_ForgedOwner.test_envelope_replaced_after_registration"]),
    ("envelope_limits_unchecked", [(G, "check_limits", noop)],
     [T + "T03_ForgedOwner.test_envelope_exceeding_policy_caps"]),
    ("reviewer_roster_ignored", [(G, "check_reviewer_qualified", noop)],
     [T + "T04_ForgedReviewer.test_self_appointed_reviewer"]),
    ("reviewer_signature_not_verified", [(G, "check_verdict_signature", noop)],
     [T + "T04_ForgedReviewer.test_forged_signature"]),
    ("reviewer_conflict_ignored", [(G, "check_reviewer_conflict", noop)],
     [T + "T04_ForgedReviewer.test_author_conflict_variants"]),
    ("verdict_binding_ignored", [(G, "check_verdict_binding", noop)],
     [T + "T05_StaleVerdict.test_verdict_bound_to_guard_and_oracle_identity"]),
    ("old_head_verdict_accepted", [(G, "check_verdict_sha", noop)],
     [T + "T05_StaleVerdict.test_old_head_verdict_reused_on_new_sha"]),
    ("verdict_freshness_ignored", [(G, "check_verdict_freshness", noop)],
     [T + "T05_StaleVerdict.test_verdict_freshness_window"]),
    ("oracle_identity_ignored", [(G, "check_oracle_identity", noop)],
     [T + "T06_Identity.test_altered_oracle_identity"]),
    ("guard_identity_ignored", [(G, "check_guard_identity", noop)],
     [T + "T06_Identity.test_altered_guard_identity"]),
    ("policy_pin_ignored", [(G, "check_policy_pin", policy_pin_without_digest)],
     [T + "T06_Identity.test_policy_tampering_rejected_by_pin"]),
    ("duplicate_detection_disabled", [(G, "check_dedupe", noop)],
     [T + "T07_Duplicates.test_same_head_distinct_delivery_ids", T + "T07_Duplicates.test_replayed_delivery_id"]),
    ("in_flight_guard_removed", [(G, "check_inflight", noop)],
     [T + "T08_Concurrency.test_second_start_while_in_flight"]),
    ("ledger_cas_disabled", [(Ledger, "append", append_without_cas)],
     [T + "T08_Concurrency.test_cas_two_decisions_same_snapshot_only_one_applies",
      T + "T08_Concurrency.test_threaded_race_yields_single_effect"]),
    ("ledger_anchor_ignored", [(G, "check_ledger_anchor", noop)],
     [T + "T08_Concurrency.test_stale_or_missing_anchor", T + "T12_Recovery.test_tampered_and_truncated_ledger"]),
    ("ledger_integrity_ignored", [(G, "check_ledger_integrity", noop)],
     [T + "T12_Recovery.test_tampered_and_truncated_ledger"]),
    ("retry_limit_removed", [(G, "check_retry_limit", noop)], [T + "T09_Retries.test_retry_exhaustion"]),
    ("retry_limit_off_by_one", [(G, "check_retry_limit", retry_off_by_one)],
     [T + "T09_Retries.test_retry_exhaustion"]),
    ("expiry_not_enforced", [(G, "check_task_active", task_active_without_expiry)],
     [T + "T10_ExpiryRevocation.test_expired_task"]),
    ("not_yet_valid_ignored", [(G, "check_time_window", noop)], [T + "T10_ExpiryRevocation.test_expired_task"]),
    ("revocation_ignored", [(G, "check_revocation", noop)],
     [T + "T10_ExpiryRevocation.test_revoked_by_signed_list"]),
    ("revocation_unavailable_fail_open", [(G, "check_revocation", revocation_fail_open)],
     [T + "T10_ExpiryRevocation.test_forged_or_missing_revocation_status_fails_closed"]),
    ("stale_revocation_list_accepted", [(G, "check_revocation", revocation_ignores_age)],
     [T + "T10_ExpiryRevocation.test_stale_revocation_list_replay_fails_closed"]),
    ("forged_revocation_list_blocks_recovery", [(G, "check_revocation", revocation_invalid_blocks_reconcile)],
     [T + "T10_ExpiryRevocation.test_unusable_revocation_list_never_blocks_reconcile"]),
    ("glob_wildcard_cap_removed", [(G, "MAX_WILDCARDS", 10 ** 6)],
     [T + "T02b_GlobLimits.test_wildcard_cap_applies_to_envelope_and_policy"]),
    ("budget_reserve_unchecked", [(G, "check_budget", noop)],
     [T + "T11_Budget.test_reserve_exceeds_remaining_budget"]),
    ("budget_stop_not_enforced", [(G, "check_task_active", task_active_without_budget_stop)],
     [T + "T11_Budget.test_budget_stop_after_overrun"]),
    ("fail_open_on_internal_error", [(G, "_internal_error_decision", internal_error_fail_open)],
     [T + "T11_Budget.test_fail_closed_on_internal_error"]),
    ("evidence_provenance_ignored", [(G, "check_evidence", noop)],
     [T + "T11_Budget.test_forged_evidence_rejected"]),
    ("min_charge_removed", [(G, "completion_charge", lambda policy, ev: ev["cost_units"])],
     [T + "T11_Budget.test_min_charge_applies"]),
    ("interruption_not_charged", [(G, "interruption_charge", lambda fl: 0)],
     [T + "T12_Recovery.test_reconcile_before_lease_is_noop_after_lease_interrupts_once",
      T + "T12_Recovery.test_no_progress_until_resume_with_reconstructed_identity"]),
    ("resume_not_required", [(G, "check_resume_required", noop)],
     [T + "T12_Recovery.test_no_progress_until_resume_with_reconstructed_identity",
      T + "T12_Recovery.test_state_reconstructed_from_persisted_ledger_matches"]),
]


def run_suite():
    stream = io.StringIO()
    suite = unittest.defaultTestLoader.loadTestsFromName("tests.test_guard")
    result = unittest.TextTestRunner(stream=stream, verbosity=0).run(suite)
    failed = sorted({t.id() for t, _ in result.failures + result.errors})
    return result.testsRun, failed


def main(argv):
    total, base_failed = run_suite()
    report = {"baseline": {"tests_run": total, "failures": base_failed}, "mutants": []}
    print("baseline: %d tests, %d failing" % (total, len(base_failed)))
    if base_failed:
        print("ABORT: baseline must pass before negative controls are meaningful")
        return 1
    survivors = 0
    for name, patches, expected in MUTANTS:
        patchers = [mock.patch.object(target, attr, value) for target, attr, value in patches]
        for p in patchers:
            p.start()
        try:
            _, failed = run_suite()
        finally:
            for p in reversed(patchers):
                p.stop()
        hit = [t for t in expected if any(f == t or f.startswith(t + " ") for f in failed)]
        killed = bool(hit)
        survivors += 0 if killed else 1
        report["mutants"].append({"mutant": name, "killed": killed, "failing_tests": len(failed),
                                  "expected_detectors": expected, "detected_by": hit})
        print("%-42s %-8s (%d failing tests; expected detector hit: %d/%d)"
              % (name, "KILLED" if killed else "SURVIVED", len(failed), len(hit), len(expected)))
    after_total, after_failed = run_suite()
    report["post_run_baseline"] = {"tests_run": after_total, "failures": after_failed}
    report["summary"] = {"mutants": len(MUTANTS), "killed": len(MUTANTS) - survivors, "survived": survivors}
    print("summary: %d mutants, %d killed, %d survived; post-run baseline failures: %d"
          % (len(MUTANTS), len(MUTANTS) - survivors, survivors, len(after_failed)))
    if "--json" in argv:
        with open(argv[argv.index("--json") + 1], "w") as fh:
            json.dump(report, fh, indent=2, sort_keys=True)
            fh.write("\n")
    return 0 if survivors == 0 and not after_failed else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
