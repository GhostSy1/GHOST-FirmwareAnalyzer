import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from ghost_firmware_analyzer.analyzer import analyze_file, analyze_rootfs
from ghost_firmware_analyzer.artifacts import detect_magic, entropy, printable_strings
from ghost_firmware_analyzer.ledger import append_record, verify
from ghost_firmware_analyzer.reporting import write_json, write_sarif


class AnalyzerTests(unittest.TestCase):
    def test_artifact_metadata_and_static_indicators(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "firmware.bin"
            path.write_bytes(b"\x7fELF\x00" + b"telnetd mqtt 1883 authorized_keys" + bytes(range(32)))
            report = analyze_file(path)
            self.assertEqual(report.artifacts[0].magic, "ELF")
            self.assertEqual(report.artifacts[0].size_bytes, path.stat().st_size)
            self.assertTrue(report.artifacts[0].sha256)
            rule_ids = {finding.rule_id for finding in report.findings}
            self.assertIn("FW-SVC-TELNET", rule_ids)
            self.assertIn("FW-CRED-AUTHKEY", rule_ids)
            self.assertIn("FW-PROTO-MQTT", rule_ids)
            self.assertFalse(report.metadata["execution_performed"])
            self.assertFalse(report.metadata["network_access_performed"])

    def test_rootfs_analysis_does_not_follow_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "rootfs"
            root.mkdir()
            (root / "etc").mkdir()
            (root / "etc" / "services.conf").write_text("rpcd\n/bin/sh\n", encoding="utf-8")
            (root / "link").symlink_to(root / "etc" / "services.conf")
            report = analyze_rootfs(root)
            self.assertEqual(report.metadata["files_scanned"], 1)
            self.assertFalse(report.metadata["symlinks_followed"])
            self.assertTrue(any(finding.rule_id == "FW-PROTO-UBUS" for finding in report.findings))

    def test_helpers_are_deterministic(self):
        data = b"AAAA BBBB"
        self.assertGreater(entropy(data), 0)
        self.assertIn("AAAA BBBB", printable_strings(data))
        self.assertEqual(detect_magic(b"MZ"), "PE/COFF executable")

    def test_reports_and_ledger(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "image.bin"
            source.write_bytes(b"plain firmware content")
            report = analyze_file(source)
            json_path = base / "report.json"
            sarif_path = base / "report.sarif"
            ledger_path = base / "ledger.jsonl"
            write_json(report, json_path)
            write_sarif(report, sarif_path)
            append_record(ledger_path, "a" * 64, report.target, len(report.findings))
            append_record(ledger_path, "b" * 64, report.target, len(report.findings))
            self.assertEqual(json.loads(json_path.read_text(encoding="utf-8"))["schema_version"], "1.0.0")
            self.assertEqual(json.loads(sarif_path.read_text(encoding="utf-8"))["version"], "2.1.0")
            self.assertEqual(verify(ledger_path), (True, "ledger verified"))


if __name__ == "__main__":
    unittest.main()
