"""Targeted controls: each repair must be necessary for its regression oracle."""
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from f0_guard import guard as G
from tests.test_repair01 import Repair01


def main():
    results = []
    for name, target, replacement, methods in [
        ('reconcile_authority_removed', 'check_reconcile_authority', lambda c: None,
         ['test_r1_unauthorized_reconcile_cannot_charge', 'test_r1_other_repository_cannot_reconcile']),
        ('revocation_observation_ignored', 'observed_revocations', lambda ledger, repo: (-1, set()),
         ['test_r2_denied_new_status_survives_reload_and_old_replay', 'test_r2_equal_epoch_cannot_remove_revocation']),
    ]:
        stream = io.StringIO()
        with patch.object(G, target, replacement):
            run = unittest.TextTestRunner(stream=stream).run(unittest.TestSuite(Repair01(x) for x in methods))
        results.append({'mutant': name, 'killed': not run.wasSuccessful(), 'failures': len(run.failures),
                        'errors': len(run.errors), 'output': stream.getvalue()})
    # Inject the original vulnerable matcher into a disposable source copy.
    # The fixed regression's own timeout must kill it; never leave it running.
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as tmp:
        for folder in ('f0_guard', 'tests'):
            shutil.copytree(root / folder, Path(tmp) / folder, ignore=shutil.ignore_patterns('__pycache__'))
        p = Path(tmp) / 'f0_guard/guard.py'
        source = p.read_text()
        start = source.index('def _glob_match(')
        end = source.index('\ndef _matches', start)
        legacy = '''def _glob_match(glob, path):
    out, i = [], 0
    while i < len(glob):
        ch = glob[i]
        if glob.startswith("**/", i):
            out.append("(?:.*/)?"); i += 3; continue
        if glob.startswith("**", i):
            out.append(".*"); i += 2; continue
        out.append("[^/]*" if ch == "*" else "[^/]" if ch == "?" else re.escape(ch))
        i += 1
    return re.fullmatch("".join(out), path)

'''
        p.write_text(source[:start] + legacy + source[end:])
        run = subprocess.run([sys.executable, '-m', 'unittest',
            'tests.test_repair01.Repair01.test_r3_legal_adversarial_glob_finishes_in_bounded_process'],
            cwd=tmp, capture_output=True, text=True, timeout=10)
        results.append({'mutant': 'legacy_backtracking_restored', 'killed': run.returncode != 0 and
                        'TimeoutExpired' in run.stderr, 'exit': run.returncode, 'output': run.stderr})
    print(json.dumps(results, indent=2))
    return 0 if all(r['killed'] for r in results) else 1


if __name__ == '__main__':
    sys.exit(main())
