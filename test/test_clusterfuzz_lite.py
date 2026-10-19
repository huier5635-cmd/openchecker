"""Regression coverage for ClusterFuzzLite Dockerfile detection.

Run with PYTHONPATH=openchecker python -m unittest discover -s test
-p test_clusterfuzz_lite.py.
"""

import tempfile
import unittest
from pathlib import Path

from openchecker.checkers.fuzzing_checker import check_clusterfuzz_lite


class TestClusterFuzzLiteDockerfile(unittest.TestCase):
    def test_detects_instructions_after_comments(self):
        contents = (
            "# Copyright 2026 Example Authors\nFROM example/fuzz-base\n",
            "\n  # A build description\n\n  FROM example/fuzz-base\n",
            "# syntax=docker/dockerfile:1\nFROM example/fuzz-base\n",
        )
        with tempfile.TemporaryDirectory() as repo:
            dockerfile = Path(repo) / ".clusterfuzzlite" / "Dockerfile"
            dockerfile.parent.mkdir()
            for content in contents:
                with self.subTest(content=content):
                    dockerfile.write_text(content, encoding="utf-8")
                    result = check_clusterfuzz_lite(repo)
                    self.assertTrue(result["found"])
                    self.assertEqual(result["tool"], "ClusterFuzzLite")
                    self.assertEqual(result["files"], [str(dockerfile)])

    def test_does_not_detect_empty_or_comment_only_files(self):
        with tempfile.TemporaryDirectory() as repo:
            dockerfile = Path(repo) / ".clusterfuzzlite" / "Dockerfile"
            dockerfile.parent.mkdir()
            for content in ("", " \n\t\n", "# Only a comment\n", "\n# First\n  # Second\n"):
                with self.subTest(content=content):
                    dockerfile.write_text(content, encoding="utf-8")
                    result = check_clusterfuzz_lite(repo)
                    self.assertFalse(result["found"])
                    self.assertEqual(result["files"], [])

    def test_detects_instruction_without_leading_comments(self):
        with tempfile.TemporaryDirectory() as repo:
            dockerfile = Path(repo) / ".clusterfuzzlite" / "Dockerfile"
            dockerfile.parent.mkdir()
            dockerfile.write_text("FROM example/fuzz-base\n", encoding="utf-8")
            self.assertTrue(check_clusterfuzz_lite(repo)["found"])

    def test_missing_dockerfile(self):
        with tempfile.TemporaryDirectory() as repo:
            result = check_clusterfuzz_lite(repo)
            self.assertFalse(result["found"])
            self.assertEqual(result["files"], [])


if __name__ == "__main__":
    unittest.main()
