"""Interactive input, failure recovery and exact retry behavior for the client."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import call, patch, Mock

from ssrsf.prototype import client as cli
from ssrsf.prototype.transport import RemoteError

RESULT = {"id": "workflow-id", "state": "complete", "label": "short", "text": "hello document"}


class InteractivePrototypeTests(unittest.TestCase):
    def run_menu(self, answers):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch("builtins.input", side_effect=answers):
            cli.main([])
        return output.getvalue()

    def test_default_menu_quits_without_initializing_or_dispatching(self):
        with patch.object(cli, "initialize") as initialize, patch.object(cli, "request") as request:
            output = self.run_menu(["0"])
        initialize.assert_not_called()
        request.assert_not_called()
        self.assertIn("Enter document text", output)

    def test_invalid_input_then_submit_status_and_exact_retry(self):
        with patch.object(cli, "credential", return_value="client-token"), \
                patch.object(cli.secrets, "token_hex", return_value="workflow-id"), \
                patch.object(cli, "request", return_value=RESULT) as request, \
                patch.object(cli, "wait_complete", return_value=RESULT):
            output = self.run_menu(["2", "", "2", "x" * 129, "2", "hello document", "4", "", "5", "0"])
        body = {"id": "workflow-id", "text": "hello document"}
        self.assertEqual(request.call_args_list, [
            call("http://127.0.0.1:8080/submit", "client-token", body),
            call("http://127.0.0.1:8080/status", "client-token", {"id": "workflow-id"}),
            call("http://127.0.0.1:8080/submit", "client-token", body)])
        self.assertIn("1 to 128", output)
        self.assertIn("Classification: short", output)
        self.assertIn("Processed text: hello document", output)

    def test_file_input_rejects_missing_or_oversized_files_before_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            large = Path(directory) / "large.txt"
            large.write_text("x" * 10000)
            valid = Path(directory) / "valid.txt"
            valid.write_text("hello café", encoding="utf-8")
            with patch.object(cli, "credential", return_value="client-token"), \
                    patch.object(cli, "request") as request, \
                    patch.object(cli, "wait_complete", return_value=RESULT):
                output = self.run_menu(["3", str(Path(directory) / "missing"),
                                        "3", str(large), "3", str(valid), "0"])
        self.assertEqual(request.call_count, 1)
        self.assertEqual(request.call_args.args[2]["text"], "hello café")
        self.assertIn("File not found", output)

    def test_service_outage_retains_exact_submission_for_retry(self):
        with patch.object(cli, "credential", return_value="client-token"), \
                patch.object(cli, "request", side_effect=[RemoteError(503, "offline"), {}]) as request, \
                patch.object(cli, "wait_complete", return_value=RESULT):
            output = self.run_menu(["2", "my input", "5", "0"])
        self.assertEqual(request.call_args_list[0], request.call_args_list[1])
        self.assertIn("Service unavailable", output)
        self.assertIn("Classification: short", output)

    def test_cancelled_wait_retains_submission_and_menu_recovers(self):
        with patch.object(cli, "credential", return_value="client-token"), \
                patch.object(cli, "request") as request, \
                patch.object(cli, "wait_complete", side_effect=[KeyboardInterrupt, RESULT]):
            output = self.run_menu(["2", "my input", "5", "0"])
        self.assertEqual(request.call_args_list[0], request.call_args_list[1])
        self.assertIn("Action cancelled", output)

    def test_actions_validate_load_count_and_preserve_state_on_stop(self):
        with patch.object(cli, "initialize") as initialize, \
                patch.object(cli.subprocess, "run") as run, \
                patch.object(cli, "check") as check, patch.object(cli, "load") as load:
            output = self.run_menu(["1", "6", "7", "invalid", "7", "21", "7", "2", "8", "0"])
        initialize.assert_called_once()
        check.assert_called_once_with("http://127.0.0.1:8080")
        load.assert_called_once_with("http://127.0.0.1:8080", 2)
        self.assertEqual(run.call_args_list, [
            call(["docker", "compose", "up", "--build", "-d", "--wait"], cwd=cli.ROOT, check=True),
            call(["docker", "compose", "down"], cwd=cli.ROOT, check=True)])
        self.assertIn("Stored workflows and credentials are preserved", output)

    def test_eof_and_missing_last_submission_do_not_dispatch(self):
        with patch.object(cli, "request") as request:
            output = self.run_menu(["5", "4", "", EOFError])
        request.assert_not_called()
        self.assertIn("Submit a document before retrying", output)
        self.assertIn("Goodbye", output)

    def test_missing_docker_produces_actionable_startup_error(self):
        with patch.object(cli, "initialize"), \
                patch.object(cli.subprocess, "run", side_effect=FileNotFoundError("docker")):
            with self.assertRaisesRegex(RuntimeError, "Docker was not found"):
                cli.start_services()

    def test_healthy_running_services_are_reused_without_rebuild(self):
        rows = [{"Service": name, "State": "running", "Health": "healthy"}
                for name in ("controller", "guard", "ingest", "extract", "classify")]
        for payload in (json.dumps(rows), "\n".join(json.dumps(row) for row in rows)):
            with self.subTest(format=payload[:1]), patch.object(cli, "initialize"), \
                    patch.object(cli.subprocess, "run", return_value=Mock(stdout=payload)) as run, \
                    contextlib.redirect_stdout(io.StringIO()):
                cli.start_services(reuse=True)
            run.assert_called_once_with(["docker", "compose", "ps", "--format", "json"],
                                        cwd=cli.ROOT, check=True, capture_output=True, text=True)

    def test_missing_services_trigger_startup_after_status_check(self):
        with patch.object(cli, "initialize"), \
                patch.object(cli.subprocess, "run", return_value=Mock(stdout="")) as run:
            cli.start_services(reuse=True)
        self.assertEqual(run.call_args_list, [
            call(["docker", "compose", "ps", "--format", "json"],
                 cwd=cli.ROOT, check=True, capture_output=True, text=True),
            call(["docker", "compose", "up", "--build", "-d", "--wait"], cwd=cli.ROOT, check=True)])
