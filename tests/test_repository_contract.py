from pathlib import Path
import unittest


class RepositoryContractTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).parents[1]

    def test_release_documents_exist(self):
        for name in ("README.md", "SECURITY.md", "CONTRIBUTING.md", "LICENSE"):
            self.assertTrue((self.root / name).exists(), name)

    def test_documentation_contains_scope_language(self):
        readme = (self.root / "README.md").read_text(encoding="utf-8", errors="ignore").lower()
        self.assertTrue(any(term in readme for term in ("authorized", "security", "analysis", "audit")))

    def test_tracked_source_does_not_contain_common_private_key_headers(self):
        forbidden = ("begin " + "rsa private key", "begin " + "openssh private key", "begin " + "ec private key", "begin " + "dsa private key")
        for path in self.root.rglob("*"):
            if not path.is_file() or ".git" in path.parts or "__pycache__" in path.parts:
                continue
            if path.suffix.lower() not in {".py", ".js", ".ts", ".tsx", ".go", ".rs", ".md", ".yml", ".yaml", ".json", ".toml", ".txt"}:
                continue
            content = path.read_text(encoding="utf-8", errors="ignore").lower()
            self.assertFalse(any(marker in content for marker in forbidden), str(path))


if __name__ == "__main__":
    unittest.main()
