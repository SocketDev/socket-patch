"""Regression coverage for failure-only historical Bun runtime diagnostics."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    'probe_bun_historical_linux',
    Path(__file__).resolve().parents[1] / 'probe-bun-historical-linux.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class HistoricalLinuxProbeTests(unittest.TestCase):
    def test_restricted_proc_files_do_not_prevent_binary_probes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / 'results'
            argv = ['probe', '--tools', str(root / 'tools'), '--output', str(output)]
            with patch('sys.argv', argv), \
                    patch.object(probe.platform, 'system', return_value='Linux'), \
                    patch.object(probe.shutil, 'which', return_value=None), \
                    patch.object(Path, 'read_text', side_effect=PermissionError('restricted proc')):
                probe.main()
            context = json.loads((output / 'context.json').read_text())
            self.assertEqual(context['vm/mmap_rnd_bits'], {'error': 'restricted proc'})
            # The probe loop still runs and reports each unavailable executable.
            summary = json.loads((output / 'summary.json').read_text())
            self.assertEqual([row['version'] for row in summary], ['0.5.9', '0.6.7', '0.6.8'])
            self.assertTrue(all('executable missing' in row['error'] for row in summary))


if __name__ == '__main__':
    unittest.main()
