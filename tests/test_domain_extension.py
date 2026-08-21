import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path


class DomainExtensionTests(unittest.TestCase):
    def test_hashes_real_input_and_never_executes_or_connects(self):
        module_path = Path(__file__).parents[1] / "tools" / "ghost_extension.py"
        spec = importlib.util.spec_from_file_location("ghost_extension", module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "input.txt"
            content = b"operator supplied evidence\n"
            target.write_bytes(content)
            report = module.analyze(target)
        self.assertEqual(report["artifacts"][0]["sha256"], hashlib.sha256(content).hexdigest())
        self.assertFalse(report["metadata"]["execution_performed"])
        self.assertFalse(report["metadata"]["network_access_performed"])
        self.assertFalse(report["metadata"]["external_tools_invoked"])


if __name__ == "__main__":
    unittest.main()
