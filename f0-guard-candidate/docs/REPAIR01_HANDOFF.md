# Guard R1/R2/R3 repair — bounded technical re-review handoff

TRACK_ID: ORBITHUB-MASTER-EXECUTION-01 / GUARD-REPAIR01

Status: IMPLEMENTED / AUTHOR_TESTED; INDEPENDENT_REACCEPTANCE_OPEN.
TRUSTED_GUARD_NOT_INSTALLED / F0_NOT_RUN / AUTONOMY_NOT_PROVEN.

This batch resumes implementation `54fcc7537c9a53f1b47bb832645c46facc98bb5d`
from evidence head `9c201d80be6c79471c47f69dba88cc9917f60d67`.
The original independent FAIL remains historical and binding until a qualified
separate technical reviewer issues a new, source-bound verdict. GPT participates
in the historical factory contract and authored this repair: neither this author
nor a subordinate reviewing agent is a whole protected-contract acceptance authority.
No protected installation, release, merge, policy, ruleset, workflow or real identity
change is included.

## Changes

- R1: `TrustedContext.caller_id` is an explicitly authenticated runner input.
  RECONCILE requires a policy owner of kind `owner`, registered task, and exact
  repository/work-branch/base identity. Missing, author, reviewer and unknown
  callers fail closed before any ledger mutation. Recovery does not require
  the potentially expired task envelope. Caller authentication itself remains
  an unimplemented protected-runner responsibility; an untrusted caller must
  never be allowed to construct this context.
- R2: signed, valid, fresh revocation observations are retained in the anchored
  ledger. Their repository-wide timestamp cannot decrease, and observed revoked
  task IDs are sticky even across equal-epoch or newer omissions. A signed list
  at the same timestamp may add revocations; it cannot remove recorded ones.
  Observation custody accompanies allowed action events as payload metadata.
  A denied action or otherwise empty action records `REVOCATION_OBSERVED` only.
  `Outcome.applied` still means a requested action effect was appended;
  `Outcome.observation_applied` separately reports safety-fact custody. CLI
  `--apply` persists either kind atomically. Pure `evaluate()` is intentionally
  non-persistent and cannot by itself establish an observation across calls.
- R3: glob matching uses iterative dynamic programming, O(pattern length × path
  length) time and O(path length) memory. The existing wildcard limit remains;
  matching no longer depends on regex backtracking. Legacy small-input semantics
  for `*`, `?`, `**` and `**/`, case folding and normalization are checked.

## Validation and evidence

All raw output is under `evidence/repair01/`; earlier evidence is untouched.

1. Before repair, the ten initial regressions produced six semantic assertion
   failures for R1/R2 and a two-second child-process timeout for R3. The timeout
   is the deliberate latency oracle; it is not an environment/setup error.
2. Initial repair: 80 tests passed, comprising all 70 unchanged original test
   bodies and ten regressions. Additional CLI-custody, CAS and forged-status
   tests bring the final suite to 83 passed with PYTHONHASHSEED=12345.
3. Three focused mutants were killed: removing recovery authorization, ignoring
   recorded revocation observations, restoring the original backtracking matcher.
4. See `negative_controls.json` and `.exit` for the original 39-mutant run.

Commands:

```sh
python3 -W error::ResourceWarning -m unittest discover -s tests -t . -v
python3 -m tests.negative_controls --json evidence/repair01/negative_controls.json
python3 -m tests.negative_controls_repair01
```

The fixture now supplies an explicit synthetic owner caller; original test bodies,
original negative-control script and historical evidence remain byte-for-byte
unchanged. The pre-repair source snapshot is a local reproduction aid, not a new
product or a publishable second source tree.

## Re-review focus and remaining limits

Independently probe missing/forged caller custody, policy/repository rebinding,
no-op recovery, older/equal/newer status replay, CLI denial persistence, lost
anchor/CAS races and adversarial legal path patterns. Distinguish authentic
signed facts from authorization to request an effect. The external anchor must
be advanced with every actual append, including a denied-action observation;
failure to advance it correctly must block further effects.

The entire trusted context, HMAC keyring and observed facts still depend on a
protected runner outside author control. This code is not evidence of OS-level
isolation, provider spending enforcement, genuine reviewer identity custody or
automatic event-to-execution. No external reviewer/provider was contacted.
