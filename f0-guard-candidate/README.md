# F0 Trusted Guard — CANDIDATE (F0-INTEGRATION-01)

Stdlib-only (Python 3), deterministic, fail-closed decision engine for a future,
separately authorized F0 autonomy pilot.

**Status: candidate source. `TRUSTED_GUARD_NOT_INSTALLED`.** Nothing here is
installed, enforced on `main`, wired to GitHub, or independently reviewed.
No workflow YAML exists in this repository and none is authorized.

## What it decides

`evaluate(trusted, envelope, request, ledger, now) -> Decision` is a pure function.
`process(...)` additionally appends the resulting events with compare-and-swap on the
anchored ledger tip. Actions: `REGISTER`, `START_ATTEMPT`, `COMPLETE_ATTEMPT`, `ACCEPT`,
`RESUME`, `RECONCILE`. Any exception, malformed input, missing status source or
unanchored ledger yields DENY (`INTERNAL_ERROR` / `INPUT_INVALID` / ...), never ALLOW.

`ACCEPT` means only "all acceptance conditions hold for this exact head"; it does not merge.

## Trust classes (policy authority is separate from implementation)

| Class | Inputs | Who must control it |
|---|---|---|
| TRUSTED | policy + pinned sha256, keyring, revocation list, observed facts (repo, branch, head, base, changed paths, author identity, guard/oracle digests), anchored ledger tip, `now` | protected runner, **outside author control** |
| SIGNED | owner task envelope, evidence, reviewer verdict, revocation list | owner / metering producer / qualified reviewer keys |
| UNTRUSTED | the request (action name + payload only; unknown fields rejected) | anyone |

The author can neither mint owner authorization, nor appoint a reviewer, nor emit
`ACCEPTED`; that event exists only as output of a passing `ACCEPT` decision.

## Layout

```
f0_guard/   canon, schema, signing, identity, ledger, state, guard, cli
tests/      support (synthetic fixtures), test_guard (70 tests), negative_controls (mutants)
docs/       STATUS_AND_LIMITATIONS, RECOVERY_AND_COST, INSTALL_PREREQUISITES, REVIEW_HANDOFF
evidence/   recorded command output pinned to the implementation commit
```

## Run (no services, credentials or network needed)

```bash
cd f0-guard-candidate
python3 -W error::ResourceWarning -m unittest discover -s tests -t . -v
python3 -m tests.negative_controls --json /tmp/negative_controls.json   # ~2-3 min
```
