# Independent-review handoff — F0-INTEGRATION-01

**Author:** Claude (implementation author). **No acceptance verdict is issued here.**
This document is a request for an independent review. It is not a review, not an approval, and
no reviewer has been appointed, contacted or triggered.

Formal state: `F0_NOT_RUN` · `AUTONOMY_NOT_PROVEN` · `TRUSTED_GUARD_NOT_INSTALLED` · `FIX02_INDEPENDENT_ACCEPTANCE_OPEN`

## 1. Pinned identities

| Item | Value |
|---|---|
| Repository | `ahmadforge-f0-lab/f0-sandbox` |
| Implementation commit (**review this exact content**) | `54fcc7537c9a53f1b47bb832645c46facc98bb5d` |
| Implementation parent | `28ca1b1c20da5eaed546de0c0e91bf7fdc823e63` (boundary sentinel; its parent is main) |
| Baseline `main` | `d0f6e147e9e52ec911331b18c9f61091b7594edd` (unchanged) |
| Implementation tree | see `evidence/ENVIRONMENT.txt` |
| Per-file identities (git blob sha1 + sha256) | `evidence/MANIFEST_AT_IMPL.txt` |
| Handoff/evidence commit | the commit that adds this file; docs and evidence only (verify: `git diff --stat 54fcc75..<head>` touches only `f0-guard-candidate/docs/REVIEW_HANDOFF.md` and `f0-guard-candidate/evidence/`) |
| Earlier sentinel | `boundary-tests/F0_POST_TRANSFER_SENTINEL.txt` untouched |
| Factory contract `e66a8017…` and Prime Forge Issue #3 | **not read** — outside this session's repository scope; the reviewer must compare the candidate against them |

## 2. Commands, outputs, exit codes
Executed on a clean `git archive` export of the implementation commit (no `.git`, no working-tree drift), Python 3.13, offline.

| Command | Exit | Output files |
|---|---|---|
| `PYTHONHASHSEED=0 python3 -W error::ResourceWarning -m unittest discover -s tests -t . -v` | 0 (70 tests OK) | `evidence/unittest_seed0.{stdout,stderr,exit}` |
| same with `PYTHONHASHSEED=12345` | 0 (70 tests OK) | `evidence/unittest_seed12345.*` |
| `python3 -m tests.negative_controls --json …` | 0 (39/39 mutants killed, 0 survived, baseline clean before and after) | `evidence/negative_controls.{stdout,stderr,exit,json}` |

The unit-test output is on **stderr** (unittest convention); stdout is empty. Read-only GitHub facts: `evidence/PLATFORM_READONLY.txt`.

## 3. Required scenario → test mapping

| # | Scenario | Tests |
|---|---|---|
| 1 | valid task | `T01_ValidTask.*` |
| 2 | unauthorized repo / protected path | `T02_Scope.*`, `T02b_GlobLimits.*` |
| 3 | forged owner approval | `T03_ForgedOwner.*` |
| 4 | forged / self-appointed reviewer | `T04_ForgedReviewer.*` |
| 5 | old-head verdict reused | `T05_StaleVerdict.*` |
| 6 | altered oracle/guard identity | `T06_Identity.*` |
| 7 | duplicate event, distinct delivery ids | `T07_Duplicates.*` |
| 8 | concurrent / repeated operations | `T08_Concurrency.*` |
| 9 | retry exhaustion | `T09_Retries.*` |
| 10 | expired / revoked task | `T10_ExpiryRevocation.*` |
| 11 | budget exhaustion, fail-closed | `T11_Budget.*` |
| 12 | interruption + deterministic reconciliation | `T12_Recovery.*`, `T14_Invariants.*` |

## 4. Negative-control outcomes (39 mutants)
Each mutant defeats one control in-process; the unchanged suite must then fail in a named detector test.

| Mutant | Outcome | Failing tests |
|---|---|---|
| owner_signature_not_verified | KILLED | 4 |
| repo_scope_removed | KILLED | 2 |
| branch_scope_removed | KILLED | 2 |
| protected_paths_not_enforced | KILLED | 7 |
| path_case_unicode_folding_removed | KILLED | 2 |
| author_check_removed | KILLED | 3 |
| request_schema_permissive_self_certify | KILLED | 8 |
| envelope_swap_after_registration | KILLED | 1 |
| envelope_limits_unchecked | KILLED | 3 |
| reviewer_roster_ignored | KILLED | 2 |
| reviewer_signature_not_verified | KILLED | 2 |
| reviewer_conflict_ignored | KILLED | 3 |
| verdict_binding_ignored | KILLED | 2 |
| old_head_verdict_accepted | KILLED | 1 |
| verdict_freshness_ignored | KILLED | 1 |
| oracle_identity_ignored | KILLED | 1 |
| guard_identity_ignored | KILLED | 1 |
| policy_pin_ignored | KILLED | 2 |
| duplicate_detection_disabled | KILLED | 3 |
| in_flight_guard_removed | KILLED | 2 |
| ledger_cas_disabled | KILLED | 3 |
| ledger_anchor_ignored | KILLED | 2 |
| ledger_integrity_ignored | KILLED | 1 |
| retry_limit_removed | KILLED | 3 |
| retry_limit_off_by_one | KILLED | 3 |
| expiry_not_enforced | KILLED | 2 |
| not_yet_valid_ignored | KILLED | 1 |
| revocation_ignored | KILLED | 5 |
| revocation_unavailable_fail_open | KILLED | 1 |
| stale_revocation_list_accepted | KILLED | 1 |
| forged_revocation_list_blocks_recovery | KILLED | 1 |
| glob_wildcard_cap_removed | KILLED | 1 |
| budget_reserve_unchecked | KILLED | 1 |
| budget_stop_not_enforced | KILLED | 2 |
| fail_open_on_internal_error | KILLED | 1 |
| evidence_provenance_ignored | KILLED | 1 |
| min_charge_removed | KILLED | 1 |
| interruption_not_charged | KILLED | 2 |
| resume_not_required | KILLED | 2 |

Limit of this evidence: mutants are hand-written by the author. They show the suite catches *these* defects,
not that no other defect exists. Surviving-mutant count 0 is not a proof of correctness.

## 5. Observed limitations
See `docs/STATUS_AND_LIMITATIONS.md` (10 items; the most important: symmetric HMAC, trusted-input
dependence on a runner that does not exist, ledger anchor custody, injected clock). Defects found and fixed
during the batch are listed there; one repair cycle each.

## 6. Conflict-of-interest declaration
The implementation, tests, fixtures, mutants and this handoff were all written by the same agent (Claude, one session).
The tests encode the author's understanding of the requirements; shared blind spots are likely.
The author ran the tests, chose the mutants, and fixed defects it found itself. No other agent or human
reviewed any part. No subagent was used. The author has no independent standing.

## 7. Reviewer-owned probes still necessary (not run by the author)
1. Compare every required behavior against the factory contract `e66a8017…` and Issue #3 scenarios.
2. Independently write mutants and adversarial tests; do not reuse the author's `tests/support.py` assumptions.
3. Attempt to forge each signed object using only the information an author-controlled session has.
4. Path model: renames, deletions, mode changes, symlinks, submodules, case-colliding names, NTFS trailing dots/spaces,
   >2000 paths (currently fail-closed `INPUT_INVALID`), Unicode edge cases beyond NFKC.
5. Cross-process concurrency and crash points between ledger write and anchor update (only single-host `flock` exists).
6. Clock skew/rollback and revocation freshness windows.
7. Whether `ACCEPT` conditions are sufficient and minimal for the contract's merge-gate definition.
8. Resource-exhaustion inputs (large JSON, deep nesting) against the real invocation path.
9. Whether HMAC is acceptable at all for the intended key custody.

## 8. Trusted-base installation prerequisites
`docs/INSTALL_PREREQUISITES.md` (8 items, none performed). Recorded blocker: under ruleset `F0-BASE-GUARD`
(PR + 1 approval, no bypass) the author cannot install or activate the guard, and must not.

## 9. Exact-head review and re-review
- A verdict is valid only for one full 40-hex head SHA and must name it. Reviewing `54fcc75…` says nothing about any later head.
- Any new commit touching `f0-guard-candidate/f0_guard/**` or `f0-guard-candidate/tests/**` invalidates the review; re-review is required.
- Docs/evidence-only follow-ups must be diff-verified by the reviewer, not assumed.
- Review comments are not GitHub `APPROVED` reviews and must never be treated as such.

## 10. Mandatory reviewer qualification criteria (all must hold; none is asserted by the author)
1. Different principal from the author: separate account, credentials, session and model/provider family, or a human;
   recorded as a distinct `conflict_group` in the pinned policy.
2. No access to the author's session context beyond this handoff and the repository.
3. Demonstrated ability: finds a seeded defect in a held-out mutant of the guard and reproduces the author's
   test results independently, before judging.
4. Verdict bound to exact head SHA, task id, guard digest and oracle-set digest, signed with a roster key.
5. Written declaration of conflicts (empty list or itemized).
6. Appointment made by the owner, not by the author or any subagent.

## 11. Remaining cost and platform gates
- Provider spending limits, Actions minutes/overage, model usage budget: **UNKNOWN** (not verifiable read-only here;
  the Actions permissions endpoint returned HTTP 403 via the proxy and was not circumvented).
- No billable test was run. No paid service used. No workflow exists (`workflows: 0`).
- Gates: owner appoints a qualified reviewer; protected installation path and trusted status source; key custody;
  runner for observed facts; ledger anchor store; cost ceilings confirmed by an owner-visible source.
