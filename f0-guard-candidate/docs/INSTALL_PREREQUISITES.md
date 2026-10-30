# Trusted-base installation prerequisites (NOT performed)

The guard stays a **candidate** until all of the following hold. None is done.

1. **Source protection.** Guard source, tests and policy are merged to `main` through the reviewed PR
   path and protected from author edits (path rules/CODEOWNERS covering `f0-guard-candidate/**` and the
   policy file), then pinned by commit SHA + `guard_digest`.
2. **Policy authority separate from implementation.** A pinned policy file whose sha256 is stored where
   the author cannot write it (not in the PR under test).
3. **Execution identity.** The guard runs under an identity the author cannot influence, evaluating
   `main`'s copy of the guard against the PR head, never the PR's own copy.
4. **Trusted status source.** The guard result is published as a required status/check by that
   identity, and the ruleset requires it. Not configured.
5. **Keys.** Owner, reviewer-roster and meter keys provisioned and held outside author control
   (asymmetric preferred over the candidate's HMAC).
6. **Observed-facts runner.** A component that measures head/base/paths/author/digests from GitHub
   and supplies them as TRUSTED input. Not written.
7. **Ledger anchor store** writable only by the guard identity.
8. **Cost gates.** Provider/GitHub spending limits confirmed by an owner-visible source (`UNKNOWN` now).

## Inability under the existing ruleset (recorded, not circumvented)

Ruleset `F0-BASE-GUARD` (26168998) requires one approving PR review on `main`, has no bypass actors and
blocks deletion and non-fast-forward. With those protections intact, the guard can reach `main` only
through a PR that a human with permission approves. This batch did not and must not approve or merge.
Steps 3-4 additionally need Actions/App configuration changes that were forbidden here. Therefore the
guard cannot be installed by the author within this authorization, and no protection was weakened.
