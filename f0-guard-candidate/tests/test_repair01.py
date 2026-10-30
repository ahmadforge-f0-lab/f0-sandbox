"""R1/R2/R3 regressions; source baseline is 54fcc7537c9a53f1b47bb832645c46facc98bb5d."""
import copy
import itertools
import json
from pathlib import Path
import tempfile
import re
import subprocess
import sys
import unittest
from f0_guard import guard as G
from f0_guard.ledger import Ledger
from f0_guard.state import reduce_events
from tests.support import World, NOW0, H1, H2


class Repair01(unittest.TestCase):
    def started(self):
        w = World()
        self.assertTrue(w.register().decision.allow)
        self.assertTrue(w.start().decision.allow)
        return w

    def test_r1_unauthorized_reconcile_cannot_charge(self):
        for caller in (None, 'author-1', 'rogue-1', 'unknown'):
            w = self.started()
            t = w.trusted()
            t.caller_id = caller
            before = w.ledger.to_jsonl()
            out = w.run('RECONCILE', NOW0 + 700, trusted=t)
            self.assertFalse(out.decision.allow, caller)
            self.assertEqual(w.ledger.to_jsonl(), before)

    def test_r1_other_repository_cannot_reconcile(self):
        w = self.started()
        t = w.trusted(observed=w.make_observed(repo='other/repo'))
        t.caller_id = 'owner-1'
        before = w.ledger.to_jsonl()
        out = w.run('RECONCILE', NOW0 + 700, trusted=t)
        self.assertFalse(out.decision.allow)
        self.assertEqual(w.ledger.to_jsonl(), before)

    def test_r1_registered_scope_cannot_be_rebound(self):
        w = self.started()
        t = w.trusted(observed=w.make_observed(branch='claude/other'))
        t.caller_id = 'owner-1'
        before = w.ledger.to_jsonl()
        self.assertFalse(w.run('RECONCILE', NOW0 + 700, trusted=t).decision.allow)
        self.assertEqual(w.ledger.to_jsonl(), before)

    def test_r1_authorized_recovery_works_without_envelope(self):
        w = self.started()
        t = w.trusted()
        t.caller_id = 'owner-1'
        self.assertTrue(w.run('RECONCILE', NOW0 + 700, trusted=t).decision.allow)
        st = reduce_events(w.ledger.events, w.task_id)
        self.assertEqual(st.spent, 100)
        self.assertIsNone(st.in_flight)

    def test_r2_denied_new_status_survives_reload_and_old_replay(self):
        w = World()
        w.register()
        old = copy.deepcopy(w.revocations)
        w.revocations = w.make_revocations([w.task_id], issued_at=NOW0 + 2)
        self.assertFalse(w.start(now=NOW0 + 3).decision.allow)
        w.ledger = Ledger.from_jsonl(w.ledger.to_jsonl())
        w.revocations = old
        out = w.start(now=NOW0 + 4)
        self.assertFalse(out.decision.allow)
        self.assertIn('REVOCATION_STATUS_ROLLBACK', out.decision.reasons)
        self.assertNotIn('ATTEMPT_STARTED', w.types())

    def test_r2_watermark_is_repository_wide(self):
        w = World()
        w.register()
        old = copy.deepcopy(w.revocations)
        w.revocations = w.make_revocations(['task-002'], issued_at=NOW0 + 2)
        self.assertTrue(w.start(now=NOW0 + 3).decision.allow)
        w.task_id = 'task-002'
        w.envelope = w.make_envelope(nonce='1' * 32)
        w.revocations = old
        self.assertFalse(w.register(now=NOW0 + 4).decision.allow)

    def test_r2_equal_epoch_cannot_remove_revocation(self):
        w = World()
        w.register()
        w.revocations = w.make_revocations([w.task_id], issued_at=NOW0 + 2)
        self.assertFalse(w.start(now=NOW0 + 3).decision.allow)
        w.revocations = w.make_revocations([], issued_at=NOW0 + 2)
        self.assertFalse(w.start(now=NOW0 + 4).decision.allow)

    def test_r2_pure_evaluation_requires_process_for_custody(self):
        w = World()
        w.register()
        before = w.ledger.to_jsonl()
        w.revocations = w.make_revocations([w.task_id], issued_at=NOW0 + 2)
        self.assertFalse(w.run('START_ATTEMPT', NOW0 + 3, apply=False).decision.allow)
        self.assertEqual(w.ledger.to_jsonl(), before)

    def test_r2_cli_persists_denied_signed_observation(self):
        w = World()
        w.register()
        old = copy.deepcopy(w.revocations)
        w.revocations = w.make_revocations([w.task_id], issued_at=NOW0 + 2)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'ledger').write_text(w.ledger.to_jsonl())
            (root / 'trusted').write_text(json.dumps(w.trusted().__dict__))
            (root / 'envelope').write_text(json.dumps(w.envelope))
            (root / 'request').write_text(json.dumps(w.request('START_ATTEMPT')))
            run = subprocess.run([sys.executable, '-m', 'f0_guard', '--trusted', str(root / 'trusted'),
                '--envelope', str(root / 'envelope'), '--request', str(root / 'request'),
                '--ledger', str(root / 'ledger'), '--now', str(NOW0 + 3), '--apply'],
                capture_output=True, text=True, timeout=5)
            self.assertEqual(run.returncode, 2, run.stderr)
            w.ledger = Ledger.from_jsonl((root / 'ledger').read_text())
        w.revocations = old
        self.assertFalse(w.start(now=NOW0 + 4).decision.allow)
        self.assertNotIn('ATTEMPT_STARTED', w.types())

    def test_r2_denied_observation_respects_cas(self):
        w = World()
        w.register()
        stale = w.trusted()
        w.revocations = w.make_revocations([w.task_id], issued_at=NOW0 + 2)
        self.assertFalse(w.start(now=NOW0 + 3).decision.allow)
        before = w.ledger.to_jsonl()
        out = w.run('START_ATTEMPT', NOW0 + 4, trusted=stale)
        self.assertFalse(out.decision.allow)
        self.assertEqual(w.ledger.to_jsonl(), before)

    def test_r2_forged_new_status_cannot_poison_watermark(self):
        from tests.support import secret
        w = World()
        w.register()
        before = w.ledger.to_jsonl()
        w.revocations = w.make_revocations([w.task_id], issued_at=NOW0 + 2,
                                          secret_override=secret('attacker'))
        self.assertFalse(w.start(now=NOW0 + 3).decision.allow)
        self.assertEqual(w.ledger.to_jsonl(), before)
        w.revocations = w.make_revocations([], issued_at=NOW0)
        self.assertTrue(w.start(now=NOW0 + 4).decision.allow)

    def test_r3_legal_adversarial_glob_finishes_in_bounded_process(self):
        code = "from f0_guard.guard import _matches; assert not _matches(['*a*a*a*a*a*a'], 'a'*250+'b')"
        result = subprocess.run([sys.executable, '-c', code], capture_output=True, timeout=2)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_r3_glob_language_matches_legacy_small_inputs(self):
        def legacy(g):
            out, i = [], 0
            while i < len(g):
                if g.startswith('**/', i):
                    out.append('(?:.*/)?'); i += 3
                elif g.startswith('**', i):
                    out.append('.*'); i += 2
                else:
                    c = g[i]; out.append('[^/]*' if c == '*' else '[^/]' if c == '?' else re.escape(c)); i += 1
            return re.compile(''.join(out))
        patterns = ['*', '**', '**/', '**/a', 'a/**/b', 'a*?b', '*a*a', '**/**/a', 'a/?', 'Ａ/**']
        paths = [''.join(cs) for n in range(5) for cs in itertools.product('ab/', repeat=n)]
        for p in patterns:
            oracle = legacy(G._fold(p))
            for s in paths:
                self.assertEqual(bool(oracle.fullmatch(G._fold(s))), bool(G._matches([p], s)), (p, s))


if __name__ == '__main__':
    unittest.main()
