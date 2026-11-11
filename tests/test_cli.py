import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ssrsf.cli import main
from ssrsf.evaluation import EXPERIMENTS


class InteractiveCLI(unittest.TestCase):
    def test_default_menu_runs_guided_experiments(self):
        with patch("builtins.input", side_effect=["invalid", "2", *([""] * 5), "3"]), \
                patch("ssrsf.cli.evaluate", return_value={"experiments": {}}) as evaluate, \
                patch("ssrsf.cli.write_bundle"), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main([]), 0)
        evaluate.assert_called_once_with(30, 42, .000001, list(EXPERIMENTS))

    def test_default_menu_can_quit_without_starting_work(self):
        with patch("builtins.input", return_value="3"), \
                patch("ssrsf.cli.evaluate") as evaluate, \
                patch("ssrsf.console.run") as console, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main([]), 0)
        evaluate.assert_not_called()
        console.assert_not_called()

    def test_document_mode_starts_containers_and_returns_to_main_menu(self):
        with patch("builtins.input", side_effect=["1", "3"]), \
                patch("ssrsf.prototype.client.start_services") as start, \
                patch("ssrsf.prototype.client.interactive") as documents, \
                patch("ssrsf.console.run") as local, \
                patch("ssrsf.cli.evaluate") as experiments, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main([]), 0)
        start.assert_called_once_with(reuse=True)
        documents.assert_called_once_with("http://127.0.0.1:8080", return_to_main=True)
        local.assert_not_called()
        experiments.assert_not_called()

    def test_docker_failure_keeps_experiments_available(self):
        with patch("builtins.input", side_effect=["1", "2", *([""] * 5), "3"]), \
                patch("ssrsf.prototype.client.start_services", side_effect=RuntimeError("Docker unavailable")), \
                patch("ssrsf.prototype.client.interactive") as documents, \
                patch("ssrsf.cli.evaluate", return_value={"experiments": {}}) as evaluate, \
                patch("ssrsf.cli.write_bundle"), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as error:
            self.assertEqual(main([]), 0)
        documents.assert_not_called()
        evaluate.assert_called_once()
        self.assertIn("Docker unavailable", error.getvalue())

    def test_cancelled_evaluation_returns_to_main_menu(self):
        with patch("builtins.input", side_effect=["2", KeyboardInterrupt, "3"]), \
                patch("ssrsf.cli.evaluate") as evaluate, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main([]), 0)
        evaluate.assert_not_called()

    def test_user_can_process_document_then_run_experiments_in_one_session(self):
        result = {"id": "test-id", "state": "complete", "label": "short", "text": "my document"}
        with patch("builtins.input", side_effect=["1", "1", "my document", "0", "2", *([""] * 5), "3"]), \
                patch("ssrsf.prototype.client.start_services"), \
                patch("ssrsf.prototype.client.credential", return_value="test-token"), \
                patch("ssrsf.prototype.client.request") as request, \
                patch("ssrsf.prototype.client.wait_complete", return_value=result), \
                patch("ssrsf.cli.evaluate", return_value={"experiments": {}}) as evaluate, \
                patch("ssrsf.cli.write_bundle"), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main([]), 0)
        self.assertEqual(request.call_args.args[2]["text"], "my document")
        evaluate.assert_called_once()
        self.assertIn("Back to main menu", output.getvalue())
        self.assertIn("Processed text: my document", output.getvalue())

    def test_evaluate_prompts_with_options_as_defaults(self):
        with patch("builtins.input", side_effect=[""] * 5), \
                patch("ssrsf.cli.evaluate", return_value={"experiments": {}}) as evaluate, \
                patch("ssrsf.cli.write_bundle") as write_bundle, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["evaluate", "--trials", "2", "--seed", "7",
                                   "--experiment", "events", "--unit-price", "0.25",
                                   "--output", "custom-results"]), 0)
        evaluate.assert_called_once_with(2, 7, .25, ["events"])
        write_bundle.assert_called_once_with({"experiments": {}}, Path("custom-results"))

    def test_non_interactive_evaluation_never_prompts(self):
        with patch("builtins.input", side_effect=AssertionError("Unexpected prompt")), \
                patch("ssrsf.cli.evaluate", return_value={"experiments": {}}) as evaluate, \
                patch("ssrsf.cli.write_bundle"), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["evaluate", "--non-interactive"]), 0)
        evaluate.assert_called_once_with(30, 42, .000001, EXPERIMENTS)

    def test_interactive_runs_selected_experiments_and_reprompts(self):
        with tempfile.TemporaryDirectory() as directory:
            answers = ["unknown", "1,1", "1,authorization", "0", "2", "-1", "123",
                       "nan", "0.25", directory]
            with patch("builtins.input", side_effect=answers), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["interactive"]), 0)
            result = json.loads((Path(directory) / "results.json").read_text())
            self.assertEqual(result["configuration"], {
                "trials": 2, "seed": 123, "unit_price": 0.25,
                "experiments": ["events", "authorization"],
            })
            self.assertTrue((Path(directory) / "report.md").exists())

    def test_explicit_interactive_accepts_defaults(self):
        with patch("builtins.input", side_effect=[""] * 5), \
                patch("ssrsf.cli.evaluate", return_value={"experiments": {}}) as evaluate, \
                patch("ssrsf.cli.write_bundle") as write_bundle, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["interactive"]), 0)
        evaluate.assert_called_once_with(30, 42, .000001, list(EXPERIMENTS))
        write_bundle.assert_called_once_with({"experiments": {}}, Path("results"))

    def test_cancel_does_not_run_evaluation(self):
        for exception, status in ((EOFError, 1), (KeyboardInterrupt, 130)):
            with self.subTest(exception=exception), \
                    patch("builtins.input", side_effect=exception), \
                    patch("ssrsf.cli.evaluate") as evaluate, \
                    contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["interactive"]), status)
                evaluate.assert_not_called()
