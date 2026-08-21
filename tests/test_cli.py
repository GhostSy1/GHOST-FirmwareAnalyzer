import json
import sys
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from contextlib import redirect_stdout
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from ghost_firmware_analyzer.cli import run
from ghost_firmware_analyzer.ledger import verify


class CliTests(unittest.TestCase):
    def test_cli_generates_all_requested_outputs_from_real_temp_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "device.bin"
            source.write_bytes(b"\x7fELF\x00mqtt telnetd")
            json_path = base / "report.json"
            csv_path = base / "report.csv"
            sarif_path = base / "report.sarif"
            ledger_path = base / "ledger.jsonl"
            output = StringIO()
            with redirect_stdout(output):
                code = run(["--no-clear", "--firmware", str(source), "--json", str(json_path), "--csv", str(csv_path), "--sarif", str(sarif_path), "--ledger", str(ledger_path)])
            self.assertEqual(code, 0)
            self.assertTrue(json_path.exists())
            self.assertTrue(csv_path.exists())
            self.assertTrue(sarif_path.exists())
            self.assertTrue(ledger_path.exists())
            report = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(report["mode"], "static-file")
            self.assertGreaterEqual(report["summary"]["finding_count"], 2)
            self.assertEqual(verify(ledger_path), (True, "ledger verified"))
            self.assertIn("Risk score", output.getvalue())

    def test_cli_rejects_missing_target_in_noninteractive_mode(self):
        with patch("sys.stdin.isatty", return_value=False):
            with self.assertRaises(SystemExit) as context:
                run(["--no-clear"])
        self.assertEqual(context.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
