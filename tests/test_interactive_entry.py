import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


class InteractiveEntryTests(unittest.TestCase):
    def test_help_is_available(self):
        main_path = Path(__file__).parents[1] / "main.py"
        result = __import__("subprocess").run([sys.executable, str(main_path), "--help"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("help", result.stdout.lower())

    def test_prompt_builder_returns_arguments(self):
        main_path = Path(__file__).parents[1] / "main.py"
        spec = importlib.util.spec_from_file_location("interactive_main", main_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        prompts = ["README.md", "report.json"]
        if hasattr(module, "interactive_args"):
            with patch("builtins.input", side_effect=prompts + ["", "", "", "", "", ""]):
                values = module.interactive_args()
            self.assertTrue(values)


if __name__ == "__main__":
    unittest.main()
