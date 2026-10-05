import hashlib
import json
import os
import signal
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import question_lab_run as runner


class QuestionDecisionProcessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="naome-question-process-control-")
        self.directory = Path(self.temp.name)
        self.lock_directory = self.directory / "temporary"
        self.lock_directory.mkdir()
        self.env = mock.patch.dict(os.environ, {"TMPDIR": str(self.lock_directory)})
        self.env.start()
        self.request = self.directory / "question-request.json"
        self.request.write_text('{"source":"fixture"}')
        self.config = self.directory / "config.json"
        self.config.write_text('{}')

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def child(self, body):
        path = self.directory / "fixture-child"
        path.write_text(f"#!{sys.executable}\n" +
                        "import hashlib,json,os,sys,time\nfrom pathlib import Path\n" +
                        "directory=Path(sys.argv[-1])\n" + body)
        path.chmod(0o700)
        return path

    def receipt_code(self):
        # This is an output-format control, never a qualified model artifact.
        return ("receipt=" + repr({"schema": 1, "decision": "APPROVE", "reason": "FORMAT_FIXTURE_ONLY",
                "policy": runner.POLICY, "feature_schema": runner.FEATURES,
                "input_digest_kind": "raw-submission-json-v1",
                "checks": [{"id": f"GF{i:02}", "status": "PASS"} for i in range(1, 11)]}) + "\n" +
                "receipt['input_sha256']=hashlib.sha256((directory/'question-request.json').read_bytes()).hexdigest()\n" +
                "(directory/'question-decision.json').write_text(json.dumps(receipt))\n")

    def decide(self, body, milliseconds=1500):
        result = runner.run_decision(self.child(body), self.config, self.directory, milliseconds)
        retained = json.loads((self.directory / "question-final-decision.json").read_text())
        self.assertEqual(result, retained)
        self.assertTrue(result['process_supervision']['owned_group_empty'])
        self.assertFalse(result['process_supervision']['automatic_retry'])
        self.assertEqual(result['raw_input_sha256'], hashlib.sha256(self.request.read_bytes()).hexdigest())
        return result

    def test_completed_all_pass_format_receipt_survives_supervision(self):
        self.assertEqual(self.decide(self.receipt_code())['decision'], 'APPROVE')

    def test_deadline_kills_owned_child_and_removes_only_its_pid_lock(self):
        body = ("(directory/'pid').write_text(str(os.getpid()))\n" +
                "(Path(os.environ['TMPDIR'])/'naome-proof-lab.lock').write_text(f'{os.getpid()}\\n')\n" +
                self.receipt_code() + "time.sleep(30)\n")
        start = time.monotonic()
        result = self.decide(body, 600)
        self.assertEqual(result['reason'], 'DECISION_DEADLINE')
        self.assertEqual(result['decision'], 'DECLINE')
        self.assertLess(time.monotonic() - start, 1.5)
        self.assertEqual(json.loads((self.directory/'question-decision.json').read_text())['decision'], 'APPROVE')
        with self.assertRaises(ProcessLookupError):
            os.kill(int((self.directory/'pid').read_text()), 0)
        self.assertFalse((self.lock_directory/'naome-proof-lab.lock').exists())

    def test_foreign_lock_is_preserved(self):
        lock = self.lock_directory/'naome-proof-lab.lock'
        lock.write_text('123456789\n')
        self.decide(self.receipt_code())
        self.assertEqual(lock.read_text(), '123456789\n')

    def test_partial_receipt_and_failed_launch_decline(self):
        result = self.decide("(directory/'question-decision.json').write_text('{')\n")
        self.assertEqual(result['decision'], 'DECLINE')
        self.assertEqual(result['reason'], 'ASSESSMENT_UNAVAILABLE')

    def test_failed_launch_is_a_terminal_decline(self):
        result = runner.run_decision(self.directory/'absent', self.config, self.directory)
        self.assertEqual(result['decision'], 'DECLINE')
        self.assertEqual(result['reason'], 'ASSESSMENT_UNAVAILABLE')
        self.assertTrue(result['process_supervision']['owned_group_empty'])

    def test_process_enumeration_failure_declines_and_reaps_child(self):
        with mock.patch.object(runner, 'decision_members', side_effect=[subprocess.TimeoutExpired('ps', .05), []]):
            result = self.decide("time.sleep(30)\n")
        self.assertEqual(result['decision'], 'DECLINE')
        self.assertEqual(result['reason'], 'ASSESSMENT_UNAVAILABLE')

    def test_finished_output_over_resource_ceiling_declines(self):
        body = self.receipt_code() + "with (directory/'excess').open('wb') as stream: stream.truncate(65*1024**2)\n"
        result = self.decide(body)
        self.assertEqual(result['decision'], 'DECLINE')
        self.assertEqual(result['reason'], 'RESOURCE_LIMIT')

    def test_wrong_input_and_failed_checkpoint_cannot_approve(self):
        body = self.receipt_code() + "receipt['input_sha256']='0'*64\nreceipt['checks'][6]['status']='FAIL'\n(directory/'question-decision.json').write_text(json.dumps(receipt))\n"
        result = self.decide(body)
        self.assertEqual(result['decision'], 'DECLINE')

    def test_stale_receipt_does_not_launch_a_child(self):
        (self.directory/'question-decision.json').write_text('{}')
        result = self.decide("(directory/'launched').write_text('yes')\n")
        self.assertEqual(result['decision'], 'DECLINE')
        self.assertFalse((self.directory/'launched').exists())

    def test_unavailable_output_directory_still_returns_terminal_decline(self):
        result = runner.run_decision(self.directory/"absent", self.config, self.directory/"absent-output")
        self.assertEqual(result["decision"], "DECLINE")
        self.assertEqual(result["receipt_retention_error"], "FileNotFoundError")

    def test_parent_fifo_read_is_inside_the_whole_decision_deadline(self):
        self.request.unlink()
        os.mkfifo(self.request)
        started = time.monotonic()
        result = runner.run_decision(self.directory/"absent", self.config, self.directory, 300)
        self.assertEqual(result['decision'], 'DECLINE')
        self.assertEqual(result['reason'], 'DECISION_DEADLINE')
        self.assertLess(time.monotonic() - started, .8)
        self.assertTrue(result['process_supervision']['owned_group_empty'])
        self.assertEqual(json.loads((self.directory/'question-final-decision.json').read_text())['decision'], 'DECLINE')

    def test_blocking_final_retention_cannot_publish_late_approve(self):
        def blocked_save(*_args):
            time.sleep(5)
        started = time.monotonic()
        with mock.patch.object(runner, 'save', side_effect=blocked_save):
            result = runner.run_decision(self.child(self.receipt_code()), self.config, self.directory, 400)
        self.assertEqual(result['decision'], 'DECLINE')
        self.assertEqual(result['reason'], 'DECISION_DEADLINE')
        self.assertLess(time.monotonic() - started, 1)
        self.assertFalse((self.directory/'question-final-decision.json').exists())
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL)[0], 0)

    def test_blocked_stdout_echo_does_not_wait_or_change_retained_decision(self):
        reader, writer = os.pipe()
        try:
            os.set_blocking(writer, False)
            while True:
                try:
                    os.write(writer, b'x' * 4096)
                except BlockingIOError:
                    break
            fake = mock.Mock()
            fake.fileno.return_value = writer
            started = time.monotonic()
            with mock.patch.object(runner.sys, 'stdout', fake):
                result = runner.run_decision(self.child(self.receipt_code()), self.config, self.directory, 1500, emit=True)
            self.assertLess(time.monotonic() - started, 1)
            self.assertEqual(result['decision'], 'APPROVE')
            self.assertEqual(json.loads((self.directory/'question-final-decision.json').read_text())['decision'], 'APPROVE')
        finally:
            os.close(reader)
            os.close(writer)

    def test_alarm_immediately_after_successful_link_keeps_one_terminal_result(self):
        native_link = os.link

        def alarm_after_link(source, target):
            native_link(source, target)
            signal.raise_signal(signal.SIGALRM)

        with mock.patch.object(runner.os, 'link', side_effect=alarm_after_link):
            result = self.decide(self.receipt_code())
        self.assertEqual(result['decision'], 'APPROVE')
        self.assertNotIn('receipt_retention_error', result)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL)[0], 0)

    def test_blocked_link_before_publication_declines_without_late_approve(self):
        native_link = os.link
        calls = []

        def block_first_link(source, target):
            calls.append(source)
            if len(calls) == 1:
                time.sleep(5)
            native_link(source, target)

        started = time.monotonic()
        with mock.patch.object(runner.os, 'link', side_effect=block_first_link):
            result = self.decide(self.receipt_code(), 400)
        self.assertEqual(result['decision'], 'DECLINE')
        self.assertEqual(result['reason'], 'DECISION_DEADLINE')
        self.assertLess(time.monotonic() - started, 1)
        self.assertEqual(len(calls), 2)

    def test_interrupted_fallback_never_creates_partial_authoritative_json(self):
        self.request.unlink()
        os.mkfifo(self.request)

        def partial_pending_save(path, _value):
            with path.open('x') as stream:
                stream.write('{')
                stream.flush()
                time.sleep(5)

        started = time.monotonic()
        with mock.patch.object(runner, 'save', side_effect=partial_pending_save):
            result = runner.run_decision(self.directory/'absent', self.config, self.directory, 300)
        self.assertEqual(result['decision'], 'DECLINE')
        self.assertEqual(result['reason'], 'DECISION_DEADLINE')
        self.assertLess(time.monotonic() - started, .8)
        self.assertFalse((self.directory/'question-final-decision.json').exists())
        self.assertEqual((self.directory/'question-final-decline.pending').read_bytes(), b'{')
        self.assertEqual(result['receipt_retention_error'], 'DecisionDeadline')

    def test_alarm_during_optional_echo_cannot_rewrite_committed_result(self):
        echoed = []

        def echo_with_alarm(_result, payload):
            signal.raise_signal(signal.SIGALRM)
            echoed.append(json.loads(payload))

        with mock.patch.object(runner, 'emit_decision', side_effect=echo_with_alarm):
            result = runner.run_decision(self.child(self.receipt_code()), self.config,
                                         self.directory, 1500, emit=True)
        retained = json.loads((self.directory/'question-final-decision.json').read_text())
        self.assertEqual(result['decision'], 'APPROVE')
        self.assertEqual(result, retained)
        self.assertEqual(echoed, [retained])
        self.assertTrue(result['process_supervision']['owned_group_empty'])

    def test_native_cpu_parser_keeps_bsd_and_gnu_units(self):
        self.assertEqual(runner.cpu_seconds('1.2 real 0.5 user 0.2 sys'), .7)
        self.assertEqual(runner.cpu_seconds('User time (seconds): 0.5\nSystem time (seconds): 0.2'), .7)
        with self.assertRaises(RuntimeError):
            runner.cpu_seconds('CPU unavailable')


if __name__ == '__main__':
    unittest.main()
