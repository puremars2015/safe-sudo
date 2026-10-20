"""Offline root controller tests: no real process, unit, or filesystem."""
import unittest
from unittest.mock import Mock, patch
from test_deployment import load


class SupervisionTests(unittest.TestCase):
    def test_late_monitor_grace_begins_at_actual_term(self):
        m = load('telegram_sudo')
        p = Mock(stdin=None)
        p.wait.return_value = 1
        with patch.object(m.time, 'monotonic', return_value=2500), patch.object(m, 'signal_deploy_process') as signal, patch.object(m, 'drain_deploy_stdout', side_effect=[(b'', False), (b'{"ok":false,"status":"rolled_back"}', True)]) as drain:
            self.assertEqual(m.monitor_deployment(p, 100)['status'], 'rolled_back')
        self.assertEqual(drain.call_args_list[1].args[1], 2620)
        signal.assert_called_once_with(p, force=False)

    def test_broker_never_force_kills_and_waits_for_supervisor(self):
        m = load('telegram_sudo')
        p = Mock(stdin=None)
        p.wait.return_value = 1
        with patch.object(m, 'signal_deploy_process') as signal, patch.object(m, 'drain_deploy_stdout', side_effect=[(b'', False), (b'', False), (b'{"ok":false,"status":"rolled_back"}', True)]):
            result = m.monitor_deployment(p, 100)
        self.assertEqual(result['status'], 'rolled_back')
        self.assertEqual([c.kwargs['force'] for c in signal.call_args_list], [False])

    def test_runner_does_not_cleanup_at_stale_execution_deadline(self):
        m = load('telegram_sudo')
        runner = load('telegram_request')
        s = m.DeploymentSession('123:FAKE', 1)
        s._accept(100)
        s.response_complete.set()
        s.finished = Mock()
        s.finished.is_set.side_effect = [False, True]
        s.finished.wait.side_effect = [False, True]
        s.result = {'ok': False, 'status': 'rolled_back'}
        with patch.object(runner.time, 'monotonic', return_value=2500):
            result = runner.wait_for_result(s)
        self.assertEqual(result['status'], 'rolled_back')
        self.assertEqual(s.finished.wait.call_count, 2)

    def test_term_during_unit_submission_retries_stop_until_proven(self):
        m = load('telegram_sudo')
        ns = {}
        with patch('signal.signal'):
            exec(m.DEPLOY_BOOTSTRAP.replace('__SOURCE__', repr(m.DEPLOY_SOURCE)).replace('__PIN__', repr('a' * 64)).split('\ntry:\n    main()')[0], ns)
        launcher = Mock(stdin=None, stdout=Mock())
        launcher.poll.side_effect = [None, 0, 0]
        launcher.wait.return_value = 1
        stop = Mock(return_value=True)
        proof = Mock(side_effect=[False, True])
        with patch.object(ns['os'], 'set_blocking'), patch.object(ns['subprocess'], 'Popen', return_value=launcher), patch.object(ns['time'], 'sleep'), patch.dict(ns, {'TERMINATING': True, 'read_output': Mock(return_value=b''), 'stop_unit': stop, 'unit_stopped': proof}):
            raw, rc = ns['supervise']('/fixed/root-owned.py')
        self.assertGreaterEqual(stop.call_count, 2, 'early stop must not lose TERM before unit creation')
        self.assertEqual(proof.call_count, 2)
        self.assertEqual(rc, 1)
        launcher.kill.assert_not_called()
        launcher.terminate.assert_not_called()
        self.assertEqual({c.args[0] for c in stop.call_args_list}, {proof.call_args.args[0]})

    def test_session_deadline_tracks_late_term_grace(self):
        m = load('telegram_sudo')
        s = m.DeploymentSession('123:FAKE', 1)
        s._accept(100)
        p = Mock(stdin=None)
        p.wait.return_value = 1
        with patch.object(m.time, 'monotonic', return_value=2500), patch.object(m, 'signal_deploy_process'), patch.object(m, 'drain_deploy_stdout', side_effect=[(b'', False), (b'{"ok":false,"status":"rolled_back"}', True)]):
            s._monitor(p)
        self.assertGreaterEqual(s.execution_deadline, 2620)
        self.assertTrue(s.finished.is_set())

    def test_root_stop_proof_rejects_running_unknown_and_private_properties(self):
        m = load('telegram_sudo')
        ns = {}
        with patch('signal.signal'):
            exec(m.DEPLOY_BOOTSTRAP.replace('__SOURCE__', repr(m.DEPLOY_SOURCE)).replace('__PIN__', repr('a' * 64)).split('\ntry:\n    main()')[0], ns)
        unit = 'hermes-ymir-4b8a3af-aaaaaaaaaaaaaaaa-42.service'
        for output, rc, expected in [(b'ActiveState=inactive\nMainPID=0\n', 0, True), (b'ActiveState=failed\nMainPID=0\n', 0, True), (b'ActiveState=active\nMainPID=0\n', 0, False), (b'ActiveState=inactive\nMainPID=42\n', 0, False), (b'ActiveState=inactive\nMainPID=0\n', 1, False), (b'TEST-PRIVATE', 0, False), (b'ActiveState=inactive\nMainPID=0\nEnvironment=TEST-PRIVATE\n', 0, False)]:
            with patch.object(ns['subprocess'], 'run', return_value=Mock(returncode=rc, stdout=output)) as run:
                self.assertIs(ns['unit_stopped'](unit), expected)
                self.assertEqual(run.call_args.args[0][-1], unit)
                self.assertNotIn('--user', run.call_args.args[0])
                self.assertNotIn('Environment', repr(run.call_args))
        with patch.object(ns['subprocess'], 'run', side_effect=OSError('TEST-PRIVATE')):
            self.assertFalse(ns['unit_stopped'](unit))
            self.assertFalse(ns['stop_unit'](unit))

    def test_root_controller_own_timeout_stops_exact_unit_and_waits(self):
        m = load('telegram_sudo')
        ns = {}
        with patch('signal.signal'):
            exec(m.DEPLOY_BOOTSTRAP.replace('__SOURCE__', repr(m.DEPLOY_SOURCE)).replace('__PIN__', repr('a' * 64)).split('\ntry:\n    main()')[0], ns)
        launcher = Mock(stdout=Mock())
        launcher.poll.side_effect = [None, 1]
        launcher.wait.return_value = 1
        stop = Mock(return_value=True)
        with patch.object(ns['os'], 'set_blocking'), patch.object(ns['subprocess'], 'Popen', return_value=launcher), patch.object(ns['time'], 'monotonic', side_effect=[100, 1901, 1902]), patch.object(ns['time'], 'sleep') as sleep, patch.dict(ns, {'read_output': Mock(side_effect=[b'x' * 9000, b'', b'']), 'stop_unit': stop, 'unit_stopped': Mock(return_value=True)}):
            raw, rc = ns['supervise']('/fixed/root-owned.py')
        self.assertEqual(len(raw), 8193)
        self.assertEqual(stop.call_count, 2)
        sleep.assert_called_once()
        launcher.kill.assert_not_called()
        launcher.terminate.assert_not_called()

    def test_launcher_poll_failure_cannot_exit_before_stop_proof(self):
        m = load('telegram_sudo')
        ns = {}
        with patch('signal.signal'):
            exec(m.DEPLOY_BOOTSTRAP.replace('__SOURCE__', repr(m.DEPLOY_SOURCE)).replace('__PIN__', repr('a' * 64)).split('\ntry:\n    main()')[0], ns)
        launcher = Mock(stdout=Mock())
        launcher.poll.side_effect = [OSError('TEST-PRIVATE'), 1]
        launcher.wait.return_value = 1
        proof = Mock(return_value=True)
        stop = Mock(return_value=True)
        with patch.object(ns['os'], 'set_blocking'), patch.object(ns['subprocess'], 'Popen', return_value=launcher), patch.object(ns['time'], 'sleep'), patch.dict(ns, {'read_output': Mock(return_value=b''), 'stop_unit': stop, 'unit_stopped': proof}):
            try:
                with self.assertRaises(ValueError):
                    ns['supervise']('/fixed/root-owned.py')
            except OSError:
                self.fail('poll error escaped before root stop proof')
        proof.assert_called_once()
        stop.assert_called_once()
        launcher.wait.assert_called_once()

    def test_session_does_not_certify_stopped_from_sudo_exit_without_root_json(self):
        m = load('telegram_sudo')
        s = m.DeploymentSession('123:FAKE', 1)
        s._accept(100)
        with patch.object(m, 'monitor_deployment', return_value={'ok': False, 'status': 'invalid_root_result'}):
            s._monitor(Mock())
        self.assertFalse(s.finished.is_set(), 'sudo exit alone is not root-unit stop proof')
        self.assertEqual(s.phase, 'supervision_unconfirmed')

    def test_root_unit_has_pid1_limits_and_exact_root_controlled_name(self):
        m = load('telegram_sudo')
        ns = {}
        exec_source = m.DEPLOY_BOOTSTRAP.replace('__SOURCE__', repr(m.DEPLOY_SOURCE)).replace('__PIN__', repr('a' * 64)).split('\ntry:\n    main()')[0]
        with patch('signal.signal'):
            exec(exec_source, ns)
        self.assertIn('supervise', ns, 'root-owned controller missing')
        launcher = Mock(stdin=None, stdout=Mock())
        launcher.poll.return_value = 0
        launcher.wait.return_value = 0
        launcher.stdout.read.return_value = b'{"ok":false,"status":"blocked"}'
        with patch.object(ns['os'], 'getpid', return_value=42), patch.object(ns['os'], 'set_blocking'), patch.object(ns['subprocess'], 'Popen', return_value=launcher) as popen, patch.dict(ns, {'read_output': Mock(side_effect=[b'{"ok":false,"status":"blocked"}', b'']), 'unit_stopped': Mock(return_value=True), 'stop_unit': Mock(return_value=True)}):
            raw, rc = ns['supervise']('/usr/local/libexec/ymir-deploy/' + 'a' * 64 + '.py')
        argv = popen.call_args.args[0]
        self.assertEqual(argv[0], '/usr/bin/systemd-run')
        self.assertIn('--property=WorkingDirectory=/', argv, 'explicit D-Bus property must survive systemd-run root-directory normalization')
        for option in ('--quiet', '--wait', '--pipe', '--service-type=exec', '--property=RuntimeMaxSec=1800s', '--property=TimeoutStopSec=120s', '--property=KillMode=control-group', '--property=KillSignal=SIGTERM', '--property=FinalKillSignal=SIGKILL', '--property=SendSIGKILL=yes', '--uid=root', '--gid=root', '--working-directory=/', '--unit=hermes-ymir-4b8a3af-aaaaaaaaaaaaaaaa-42.service', '--setenv=HERMES_DEPLOY_UNIT=hermes-ymir-4b8a3af-aaaaaaaaaaaaaaaa-42.service'):
            self.assertIn(option, argv)
        self.assertNotIn('--user', argv)
        self.assertNotIn('--scope', argv)
        self.assertEqual(argv[-4:], ['/usr/bin/python3', '-I', '-S', '/usr/local/libexec/ymir-deploy/' + 'a' * 64 + '.py'])
        self.assertEqual(popen.call_args.kwargs['stdin'], ns['subprocess'].DEVNULL)
        self.assertEqual(popen.call_args.kwargs['stderr'], ns['subprocess'].DEVNULL)
        self.assertTrue(popen.call_args.kwargs['start_new_session'])
        self.assertEqual(rc, 0)


if __name__ == '__main__':
    unittest.main()
