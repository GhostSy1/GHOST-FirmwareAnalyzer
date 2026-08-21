import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path


class UpgradedEngineTests(unittest.TestCase):
    def test_analysis_runs_cleanly_and_hashes_input(self):
        path = Path(__file__).parents[1] / "tools" / "ghost_extension.py"
        spec = importlib.util.spec_from_file_location("ext", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "sample.txt"
            content = b"password=supersecret\n"
            target.write_bytes(content)
            report = module.analyze(target)
        self.assertEqual(report["artifacts"][0]["sha256"], hashlib.sha256(content).hexdigest())
        self.assertFalse(report["metadata"]["execution_performed"])
        self.assertFalse(report["metadata"]["network_access_performed"])


if __name__ == "__main__":
    unittest.main()
