# Status and limitations

Formal state (unchanged by this batch):
`F0_NOT_RUN` · `AUTONOMY_NOT_PROVEN` · `TRUSTED_GUARD_NOT_INSTALLED` · `FIX02_INDEPENDENT_ACCEPTANCE_OPEN`

## Four evidence levels — never conflate them

| Level | What it covers | Source |
|---|---|---|
| **Logic verified in local tests** | Guard decision logic, ledger/CAS, reducer, recovery and budget transitions, fail-closed paths, determinism (same output under different `PYTHONHASHSEED`), no-network imports, invariants over 200 seeded random walks, 39 mutants detected | `tests/`, `evidence/` |
| **Platform enforcement already demonstrated** (earlier batch, not repeated) | GitHub rejected a direct non-force push to `main` with GH013 (PR required); working-branch push succeeded; ruleset `F0-BASE-GUARD` (26168998) active, bypass list empty | prior report; main `d0f6e147…`, branch `28ca1b1c…` |
| **Runtime behavior not yet tested** | Guard execution inside any real GitHub event/Actions/App context; trusted status source; required-check wiring; anchor store atomicity; real clock source; real keys; real reviewer; MCP/REST write paths | nothing executed |
| **Autonomous behavior still unproven** | Any unattended review/repair loop, event-triggered recovery, Auto-fix | nothing executed |

Mock inputs in tests are **not** evidence of provider or GitHub enforcement.

## Known limitations of the candidate

1. **Symmetric signatures.** HMAC-SHA256 (stdlib only). Anyone holding the verifying keyring can forge
   envelopes, evidence and verdicts. Keyring custody outside author control is a hard prerequisite;
   production should use asymmetric/attestation signing (a deliberate non-goal here: no new dependency).
2. **Clock.** `now` is an input. The guard cannot detect a lying clock.
3. **Observed facts.** Head/base/paths/author/guard+oracle digests are trusted *inputs* from the runner;
   the guard cannot verify the runner measured them honestly. A runner implementation does not exist yet.
4. **Ledger anchor.** Tamper/truncation detection exists only if `expected_tip` lives in a store the
   author cannot write. Atomic update of anchor + ledger is unspecified; `flock` in the CLI is
   single-host only.
5. **Single author identity per head.** Multi-author commits, co-authors and rebase/force-push
   history rewriting are not modeled (a rewritten head is simply a new head).
6. **Reviewer qualification** is a policy-roster check plus signature; it does **not** establish that
   a reviewer is actually capable or independent. See `REVIEW_HANDOFF.md` criteria.
7. **Retries need a new head SHA**; identical-head retry is denied by design.
8. **Revocation freshness** relies on `revocation_max_age_seconds`; between list refreshes a revocation
   is not visible. Recorded revocations (via `RECONCILE`) are sticky.
9. Glob matching: `*`/`?` do not cross `/`, `**` does, NFKC+casefold on both sides, ≤ 6 wildcards per
   glob. Not a full gitignore implementation. Path *rename* semantics (old+new path) must be expanded by
   the runner into `changed_paths`.
10. Denials are not written to the ledger (avoids log flooding); the runner must retain `Decision` JSON.

## Defects found during this batch (and fixed)

| Defect | Found by | Fix |
|---|---|---|
| Stale (replayed) revocation list could un-revoke a task whose revocation was not yet recorded | own adversarial review of the first green run | `revocation_max_age_seconds`, `REVOCATION_LIST_STALE` fail-closed |
| Forged/stale revocation list could block `RECONCILE` (recovery DoS) | same | `RECONCILE` ignores unusable lists, never denies on them |
| Unbounded glob wildcards (regex backtracking) | same | schema cap `MAX_WILDCARDS = 6` |
| Test-harness defects (Outcome wrapper, float in signed fixture, unclosed files) | first test runs | fixed in tests; no guard behavior change |

Repair cycles used per defect: 1 (limit 2). No security-critical defect remains known and open.
