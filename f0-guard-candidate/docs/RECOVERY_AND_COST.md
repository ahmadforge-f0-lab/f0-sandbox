# Recovery and cost-stop logic (candidate, locally tested only)

State is **never** held in memory between invocations. It is always reduced from the
hash-chained ledger (`state.reduce_events`), and the ledger tip must match the tip
anchored in a trusted store (`expected_tip`). Absent anchor => DENY.

## Events and transitions

| Event (written only by the guard) | Written when | Effect on state |
|---|---|---|
| `TASK_REGISTERED` | verified owner envelope, unseen task id and nonce | stores terms (expiry, caps, allowed paths), envelope digest |
| `ATTEMPT_STARTED` | no attempt in flight, no resume pending, retries and budget remain, new head | in-flight attempt, reserve held, attempt counter +1 |
| `ATTEMPT_COMPLETED` | signed evidence from a trusted producer for the in-flight head, within lease | charge = max(meter cost, policy minimum); `BUDGET_STOP` appended if ceiling crossed |
| `ATTEMPT_INTERRUPTED` | `RECONCILE` finds lease expired, or task expired/revoked | charges the full reserve (conservative), sets resume-pending |
| `RESUMED` | `RESUME` whose attempt number, head, **envelope digest** and **interruption event hash** match the ledger | clears resume-pending |
| `BUDGET_STOP` / `TASK_EXPIRED` / `TASK_REVOKED` | completion or `RECONCILE` | terminal for START/COMPLETE/ACCEPT/RESUME |
| `ACCEPTED` | passing `ACCEPT` | terminal; second accept denied |

## Invariants (asserted by tests, including 200 seeded random walks)

- at most one `ACCEPTED`; at most `max_attempts` `ATTEMPT_STARTED`; one in-flight attempt;
- no `ATTEMPT_STARTED`/`ACCEPTED`/`RESUMED` after `BUDGET_STOP`, `TASK_EXPIRED` or `TASK_REVOKED`;
- semantic event keys and delivery ids are unique in the ledger (redelivery is a no-op deny);
- `spent` equals the sum of recorded charges; the ledger chain always verifies.

## Cost

Units are abstract integers supplied by policy and a signed meter. **No provider price, quota,
overage or spend limit is encoded or verified.** Provider spending controls: `UNKNOWN`.
No billable exhaustion test was run or is authorized.

## Deliberate limits

- A retry must present a **new head SHA** (same head => `DUPLICATE_EVENT`).
- Cost integrity depends on the meter key holder; an under-reporting meter is out of scope.
- Event-triggered recovery has **not** been executed anywhere; only the pure logic is tested.
