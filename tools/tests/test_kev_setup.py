"""Installation recovery and preflight with fixture files; no downloads or GPU."""
from contextlib import ExitStack, redirect_stderr
import io
import json
import os
from pathlib import Path
import signal
import subprocess
from types import SimpleNamespace
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from naome_kev import config, install, runtime, setup


def archive(extra=None):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w:gz') as stream:
        for name in setup.SOURCE_FILES:
            content = b'fixture source'
            item = tarfile.TarInfo('kev-pinned/' + name)
            item.size = len(content)
            stream.addfile(item, io.BytesIO(content))
        if extra is not None:
            stream.addfile(extra)
    return out.getvalue()


def installed(root):
    config.configure(root)
    files, sources = {}, {}
    for name in install.REQUIRED_FILES | install.REQUIRED_SOURCES:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(name.encode())
        if name in install.REQUIRED_FILES:
            files[name] = {'sha256': install.sha256(path), 'bytes': path.stat().st_size,
                           'identity': install.identity(path.stat())}
        else:
            sources[name] = install.sha256(path)
    python = root / 'venv/bin/python'
    python.parent.mkdir(parents=True)
    python.write_text('fixture interpreter')
    manifest = {'version': 1, 'source_revision': runtime.SOURCE_REVISION, 'model': config.MODEL,
                'files': files, 'sources': sources, 'packages': {name: 'fixture' for name in install.PACKAGES},
                'python': 'fixture'}
    install.atomic_json(root / 'manifest.json', manifest)
    return manifest


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='kev-setup-', dir='/tmp')
        self.root = Path(self.temp.name)
        self.stack = ExitStack()
        self.stack.enter_context(patch.object(setup.platform, 'system', return_value='Darwin'))
        self.stack.enter_context(patch.object(setup.platform, 'machine', return_value='arm64'))
        self.memory = self.stack.enter_context(patch.object(setup, 'physical_memory', return_value=24 * setup.GIB))

    def tearDown(self):
        self.stack.close()
        self.temp.cleanup()

    def test_preflight_prevents_network_and_subprocess_work(self):
        with patch.object(setup, 'source') as source, patch.object(setup, '_run') as run:
            with patch.object(setup.platform, 'system', return_value='Linux'):
                with self.assertRaisesRegex(setup.SetupError, 'macOS'):
                    setup.setup(self.root)
            with patch.object(setup.shutil, 'which', return_value=None):
                with self.assertRaisesRegex(setup.SetupError, 'Install uv'):
                    setup.setup(self.root)
            with patch.object(setup.shutil, 'which', return_value='/fixture/uv'), \
                 patch.object(setup.shutil, 'disk_usage', return_value=SimpleNamespace(free=0)):
                with self.assertRaisesRegex(setup.SetupError, 'disk space'):
                    setup.setup(self.root)
            source.assert_not_called()
            run.assert_not_called()

    def test_concurrent_setup_cannot_modify_installation(self):
        with setup.setup_lock(self.root), patch.object(setup, 'source') as source:
            with self.assertRaisesRegex(setup.SetupError, 'Another Kev setup'):
                setup.setup(self.root)
            source.assert_not_called()

    def test_low_memory_fails_before_creating_directory_or_downloading(self):
        self.memory.return_value = 8 * setup.GIB
        root = self.root / 'not-created'
        with patch.object(setup, 'source') as source, patch.object(setup, '_run') as run, \
             redirect_stderr(io.StringIO()) as output:
            with self.assertRaisesRegex(setup.SetupError, '16 GiB'):
                setup.setup(root)
        self.assertFalse(root.exists())
        self.assertIn('8.0 GiB', output.getvalue())
        source.assert_not_called()
        run.assert_not_called()

    def test_interrupted_subprocess_is_reaped_and_progress_is_visible(self):
        children = []
        real_popen = subprocess.Popen

        def spawn(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            children.append(child)
            return child

        def interrupt(_signal, _frame):
            raise KeyboardInterrupt

        previous = signal.signal(signal.SIGALRM, interrupt)
        try:
            with patch.object(setup.subprocess, 'Popen', side_effect=spawn), \
                 patch.object(setup, 'PROGRESS_SECONDS', .01), redirect_stderr(io.StringIO()) as output:
                signal.setitimer(signal.ITIMER_REAL, .2)
                with self.assertRaises(KeyboardInterrupt):
                    setup._run(self.root, [sys.executable, '-c', 'import time; time.sleep(60)'],
                               os.environ.copy(), 'models_failed')
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].poll())
        self.assertIn('still working', output.getvalue())
        self.assertIn(str(self.root / 'setup.log'), output.getvalue())
        self.assertEqual((self.root / 'setup.log').stat().st_mode & 0o777, 0o600)
        # Interruption releases all ownership, allowing a resumable retry.
        with setup.setup_lock(self.root):
            pass

    def test_interruption_after_waitpid_reaps_without_claiming_success(self):
        children = []
        real_popen = subprocess.Popen
        real_waitpid = os.waitpid
        interrupted = False

        def spawn(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            children.append(child)
            return child

        def interrupt_after_reap(pid, options):
            nonlocal interrupted
            result = real_waitpid(pid, options)
            if not interrupted and result[0] == children[0].pid:
                interrupted = True
                raise KeyboardInterrupt('after owned waitpid reaped the child')
            return result

        with patch.object(setup.subprocess, 'Popen', side_effect=spawn), \
             patch.object(runtime.os, 'waitpid', side_effect=interrupt_after_reap):
            with self.assertRaises(KeyboardInterrupt):
                setup._run(self.root, [sys.executable, '-c', 'pass'],
                           os.environ.copy(), 'models_failed')
        self.assertTrue(interrupted)
        self.assertEqual(len(children), 1)
        # The exit status was lost to the interrupt; it must not become success.
        self.assertEqual(children[0].returncode, 125)
        with self.assertRaises(ChildProcessError):
            os.waitpid(children[0].pid, os.WNOHANG)

    def test_nonzero_owned_child_exit_remains_setup_failure(self):
        with self.assertRaises(setup.SetupError) as error:
            setup._run(self.root, [sys.executable, '-c', 'import sys; sys.exit(7)'],
                       os.environ.copy(), 'models_failed')
        self.assertEqual(error.exception.code, 'models_failed')

    def test_owned_cleanup_reaps_with_poisoned_popen_wait_lock(self):
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'],
                                 start_new_session=True)
        child._waitpid_lock.acquire()
        try:
            runtime._terminate_owned(child)
            self.assertEqual(child.returncode, -signal.SIGTERM)
        finally:
            child._waitpid_lock.release()
            if child.returncode is None:
                child.kill()
                child.wait(timeout=2)

    def test_sigterm_reaps_installation_before_releasing_setup_lock(self):
        launcher = '''
import os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from naome_kev import setup
root = Path(sys.argv[2])
download = 'import os,sys,time; from pathlib import Path; Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(60)'
with setup.termination_cleanup(), setup.setup_lock(root):
    setup._run(root, [sys.executable, '-c', download, str(root / 'download.pid')], os.environ.copy(), 'models_failed')
'''
        process = subprocess.Popen([sys.executable, '-c', launcher,
                                    str(Path(__file__).resolve().parents[1]), str(self.root)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        download_pid = None
        try:
            deadline = time.monotonic() + 5
            while not (self.root / 'download.pid').exists() and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertTrue((self.root / 'download.pid').exists())
            download_pid = int((self.root / 'download.pid').read_text())
            with self.assertRaisesRegex(setup.SetupError, 'Another Kev setup'):
                with setup.setup_lock(self.root):
                    pass
            process.terminate()
            self.assertEqual(process.wait(timeout=5), 128 + signal.SIGTERM)
            with self.assertRaises(ProcessLookupError):
                os.kill(download_pid, 0)
            with setup.setup_lock(self.root):
                pass
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            if download_pid is not None:
                try:
                    os.kill(download_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_interrupted_extraction_retries_without_deleting_model_downloads(self):
        model = self.root / 'base/retained.safetensors'
        model.parent.mkdir()
        model.write_bytes(b'resumable-model')
        with patch.object(setup.urllib.request, 'urlopen', side_effect=lambda *a, **k: io.BytesIO(archive())), \
             patch.object(setup, '_extract', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                setup.source(self.root)
        self.assertFalse((self.root / 'vendor').exists())
        self.assertEqual(list(self.root.glob('.vendor-stage-*')), [])
        # Also recover a stage left by abrupt process termination.
        (self.root / '.vendor-stage-abandoned').mkdir()
        with patch.object(setup.urllib.request, 'urlopen', return_value=io.BytesIO(archive())):
            setup.source(self.root)
        self.assertEqual(model.read_bytes(), b'resumable-model')
        self.assertEqual((self.root / 'vendor/.source-revision').read_text().strip(), runtime.SOURCE_REVISION)
        with patch.object(setup.urllib.request, 'urlopen') as download:
            setup.source(self.root)
            download.assert_not_called()

    def test_archive_traversal_symlinks_and_expansion_are_rejected(self):
        for name, kind in (('kev-pinned/../../escape', tarfile.DIRTYPE),
                           ('kev-pinned/link', tarfile.SYMTYPE)):
            item = tarfile.TarInfo(name)
            item.type = kind
            with tempfile.TemporaryDirectory(dir=self.root) as stage:
                with self.assertRaises(setup.SetupError):
                    setup._extract(archive(item), Path(stage))
        with tempfile.TemporaryDirectory(dir=self.root) as stage, \
             patch.object(setup, 'MAX_SOURCE_BYTES', 1):
            with self.assertRaises(setup.SetupError):
                setup._extract(archive(), Path(stage))

    def test_completed_legacy_install_is_reused_without_uv_or_downloads(self):
        installed(self.root)
        (self.root / 'source-revision').write_text(runtime.SOURCE_REVISION)
        with patch.object(setup.shutil, 'which', return_value=None), \
             patch.object(setup, 'source') as source, patch.object(setup, '_run') as run:
            result = setup.setup(self.root)
        self.assertTrue(result['installed'])
        self.assertTrue(result['reused'])
        source.assert_not_called()
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[1][-1], '--check')

    def test_manifest_publication_is_atomic_and_checks_detect_drift(self):
        manifest = installed(self.root)
        before = (self.root / 'manifest.json').read_bytes()
        with patch.object(install.os, 'replace', side_effect=OSError('fixture interruption')):
            with self.assertRaises(OSError):
                install.atomic_json(self.root / 'manifest.json', {'partial': True})
        self.assertEqual((self.root / 'manifest.json').read_bytes(), before)
        self.assertEqual(list(self.root.glob('.manifest.json-*')), [])
        with patch.object(install.importlib.metadata, 'version', return_value='fixture'):
            self.assertEqual(install.check_install(self.root), manifest)
        with patch.object(install.importlib.metadata, 'version', return_value='changed'):
            with self.assertRaisesRegex(install.InstallError, 'packages_changed'):
                install.check_install(self.root)
        (self.root / 'base/config.json').write_text('changed')
        with self.assertRaisesRegex(install.InstallError, 'installation_changed'):
            install.check_install(self.root, check_packages=False)

    def test_unrelated_files_and_symlinks_do_not_reduce_disk_budget(self):
        (self.root / 'unrelated').write_bytes(b'x' * 8192)
        (self.root / 'base').symlink_to(self.root, target_is_directory=True)
        self.assertEqual(setup.remaining_space(self.root), setup.FRESH_BYTES)
        (self.root / 'base').unlink()
        (self.root / 'base').mkdir()
        (self.root / 'base/partial.safetensors').write_bytes(b'x' * 8192)
        self.assertLess(setup.remaining_space(self.root), setup.FRESH_BYTES)
        self.assertGreaterEqual(setup.remaining_space(self.root), setup.MINIMUM_RESUME_BYTES)


if __name__ == '__main__':
    unittest.main()
