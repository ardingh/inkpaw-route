import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from inkpaw import build, cli, policy, sources


class RuntimeTests(unittest.TestCase):
    def test_cli_dispatches_each_mode(self):
        with mock.patch.object(build, "build_config") as generate:
            self.assertEqual(cli.main(["--no-backup", "--report", "status.json"]), 0)
            self.assertIsNone(generate.call_args.kwargs["backup_dir"])
            self.assertEqual(generate.call_args.kwargs["report_path"], "status.json")
        with mock.patch.object(build, "validate_monitored_sources") as monitor:
            self.assertEqual(cli.main(["--validate-monitored-sources"]), 0)
            monitor.assert_called_once_with()
        with mock.patch.object(build, "validate_config_file") as validate:
            self.assertEqual(cli.main(["--validate-config", "config.conf"]), 0)
            validate.assert_called_once_with("config.conf")

    def test_module_entry_point_validates_real_config(self):
        result = subprocess.run([sys.executable, "-m", "inkpaw", "--validate-config",
                                 "inkpaw-route.conf"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_journal_reports_actual_selected_content(self):
        journal = []
        specs = [("a", "https://example.com/a", Path("unused"), "Example", None)]
        with mock.patch.object(sources, "fetch_or_fallback", return_value=(False, "cached")):
            sources.fetch_sources_parallel(specs, journal=journal)
        self.assertEqual(journal, [{"name": "Example", "url": "https://example.com/a",
                                   "mode": "cache", "sha256": hashlib.sha256(b"cached").hexdigest()}])

    def test_monitor_covers_all_domestic_sources(self):
        with mock.patch.object(sources, "_download_source", return_value=(b"fixture", "text/plain")), \
             mock.patch.object(build.validation, "validate_johnshall_content", return_value=1), \
             mock.patch.object(build.validation, "validate_blackmatrix_openai_content", return_value=1), \
             mock.patch.object(build.validation, "validate_metacubex_openai_content", return_value=1), \
             mock.patch.object(build.validation, "validate_provider_content", return_value=1):
            result = build.validate_monitored_sources()
        self.assertEqual(set(result), {"Johnshall", "OpenAI blackmatrix7", "OpenAI MetaCubeX"} | set(policy.domestic_lists))
