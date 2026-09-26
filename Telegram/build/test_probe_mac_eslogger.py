import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from Telegram.build import probe_mac_eslogger as probe


class ProbeEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name) / "Telegram Desktop"
        self.parent_path = self.root / ".probe" / "parent-access"
        self.child_path = self.root / ".probe" / "child-access"
        self.fixture = {
            "parent_pid": 101,
            "child_pid": 102,
            "parent_access_count": 4,
            "child_exit_status": 0,
        }
        self.records = [
            self.record(
                1,
                "exec",
                101,
                {"target": {"path": "/usr/bin/python3"}, "env": ["CANARY_SECRET"]},
            ),
            self.record(
                2,
                "fork",
                101,
                {"child": {"audit_token": {"pid": 102}}},
            ),
            self.record(
                3,
                "write",
                900,
                {"args": ["CANARY_SECRET"], "env": ["CANARY_SECRET"]},
            ),
            self.record(
                4,
                "open",
                101,
                {"file": {"path": str(self.parent_path)}},
            ),
            self.record(
                5,
                "open",
                102,
                {"file": {"path": str(self.child_path)}},
            ),
            self.record(6, "exit", 102, {}),
            self.record(7, "exit", 101, {}),
        ]
        self.checks = {
            "sentinel_event_observed_before_fixture": True,
            "fixture_exit_code": 0,
            "logger_started": True,
            "logger_alive_at_parent_exit": True,
            "logger_exit_code": 0,
            "logger_group_exited": True,
            "no_eslogger_process_remains": True,
            "private_data_removed": True,
            "fixture_files_removed": True,
        }

    def tearDown(self):
        self.tempdir.cleanup()

    @staticmethod
    def record(sequence, kind, pid, details):
        return {
            "global_seq_num": sequence,
            "seq_num": sequence + 100,
            "event": {kind: details},
            "process": {
                "audit_token": {"pid": pid, "pidversion": 8},
                "ppid": 1,
                "start_time": "start-" + str(pid),
                "args": ["CANARY_SECRET"],
                "env": ["CANARY_SECRET"],
                "cwd": {"path": "/private/CANARY_SECRET"},
                "fds": ["CANARY_SECRET"],
            },
        }

    def analyze(self, records=None, checks=None):
        return probe.analyze_records(
            self.records if records is None else records,
            [],
            self.fixture,
            self.root,
            self.checks if checks is None else checks,
        )

    def test_global_sequence_detects_gap_across_event_types(self):
        records = [dict(record) for record in self.records]
        records[4]["global_seq_num"] = 6
        records[5]["global_seq_num"] = 7
        records[6]["global_seq_num"] = 8

        summary = self.analyze(records)

        self.assertEqual(summary["global_sequence"]["gaps"], 1)
        self.assertFalse(summary["global_sequence"]["contiguous"])
        self.assertEqual(summary["fixture_result"], "UNAVAILABLE")

    def test_missing_global_sequence_fails_closed(self):
        records = [dict(record) for record in self.records]
        del records[3]["global_seq_num"]

        summary = self.analyze(records)

        self.assertEqual(summary["global_sequence"]["missing"], 1)
        self.assertFalse(summary["sequence_gap_detection_available"])
        self.assertEqual(summary["fixture_result"], "UNAVAILABLE")

    def test_parent_exec_and_exit_are_required(self):
        for kind in ("exec", "exit"):
            with self.subTest(kind=kind):
                records = [
                    record
                    for record in self.records
                    if not (
                        probe.event_kind(record)[0] == kind
                        and probe.process_identity(record)[0] == 101
                    )
                ]

                summary = self.analyze(records)

                self.assertEqual(summary["fixture_result"], "UNAVAILABLE")
                if kind == "exec":
                    self.assertFalse(summary["parent_exec_observed"])
                else:
                    self.assertFalse(summary["parent_exit_observed"])

    def test_logger_liveness_and_shutdown_are_required(self):
        self.assertFalse(probe.probe_step_failed(self.analyze()))
        failure_cases = (
            {"logger_alive_at_parent_exit": False},
            {"logger_exit_code": None},
            {"logger_group_exited": False},
            {"no_eslogger_process_remains": False},
        )
        for changes in failure_cases:
            with self.subTest(changes=changes):
                checks = dict(self.checks, **changes)
                summary = self.analyze(checks=checks)
                self.assertEqual(summary["fixture_result"], "UNAVAILABLE")
                if "logger_alive_at_parent_exit" in changes:
                    self.assertFalse(probe.probe_step_failed(summary))
                else:
                    self.assertTrue(probe.probe_step_failed(summary))

    def test_uploaded_files_drop_raw_environment_and_process_fields(self):
        summary = self.analyze()
        summary["tracked_process_events"] *= 100
        fixture = dict(self.fixture, env=["CANARY_SECRET"], extra="CANARY_SECRET")
        console = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            summary_path = Path(directory) / "summary.json"
            fixture_path = Path(directory) / "fixture.json"
            with contextlib.redirect_stdout(console):
                probe.write_summary(summary_path, summary)
            fixture_path.write_text(
                json.dumps(probe.public_fixture(fixture)),
                encoding="utf-8",
            )
            uploaded = summary_path.read_text(encoding="utf-8") + fixture_path.read_text(
                encoding="utf-8"
            )

        self.assertNotIn("CANARY_SECRET", uploaded)
        self.assertNotIn('"env"', uploaded)
        self.assertNotIn('"args"', uploaded)
        self.assertNotIn('"cwd"', uploaded)
        self.assertNotIn('"fds"', uploaded)
        logged = console.getvalue()
        self.assertIn("telemetry_probe_summary=", logged)
        diagnostic_line = next(
            line
            for line in logged.splitlines()
            if line.startswith("telemetry_probe_summary=")
        )
        diagnostics = json.loads(diagnostic_line.split("=", 1)[1])
        self.assertIn("global_sequence", diagnostics)
        self.assertIn("logger_shutdown_pass", diagnostics)
        self.assertNotIn("tracked_process_events", diagnostics)
        self.assertLess(len(diagnostic_line), 4096)
        self.assertNotIn("CANARY_SECRET", logged)
        self.assertNotIn('"env"', logged)
        self.assertNotIn('"args"', logged)
        self.assertNotIn('"cwd"', logged)
        self.assertNotIn('"fds"', logged)
        self.assertIn("/parent-access", uploaded)
        self.assertIn("outside_tree_event_counts", uploaded)


if __name__ == "__main__":
    unittest.main()
