import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ssrsf.cli import main
from ssrsf.workflow import ReferenceApp


class ConsoleTests(unittest.TestCase):
    def test_user_input_persists_and_reopens(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            text_file = Path(directory) / "input.txt"
            text_file.write_text("My own document", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main(["--file", str(text_file), "--state", str(state)]), 0)
            self.assertIn('"audit_verified": true', output.getvalue())
            self.assertEqual(ReferenceApp(state).read("user-token")["raw"], "My own document")

    def test_interactive_controls_and_version_bound_approval(self):
        commands = ["ingest Original document", "purge", "telemetry", "tamper My payload",
                    "auth invalid", "auth admin-token", "approve", "ingest Replacement",
                    "purge", "read", "approve", "purge", "purge", "audit", "quit"]
        with patch("builtins.input", side_effect=["1", *commands]), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main([]), 0)
        text = output.getvalue()
        for expected in ("Independent exact-scope approval required", "Detailed telemetry restricted",
                         "Event integrity failure", "Invalid gateway credential", "Missing or replaced target",
                         '"raw": "Replacement"', '"deleted": 1', "Purge replay", '"audit_verified": true'):
            self.assertIn(expected, text)

    def test_oversized_file_returns_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.txt"
            path.write_text("x" * 129)
            with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--file", str(path)]), 1)

    def test_eof_exits_cleanly(self):
        with patch("builtins.input", side_effect=EOFError), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main([]), 0)
