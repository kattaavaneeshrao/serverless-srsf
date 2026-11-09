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
        with patch("builtins.input", side_effect=["invalid", "2", *([""] * 5)]), \
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
