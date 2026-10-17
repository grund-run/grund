#!/usr/bin/env python3
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent


class ReleaseIdentity(unittest.TestCase):
    def setUp(self):
        self.environment = os.environ | {'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull}
        scratch = ROOT / 'scratch'
        scratch.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix='release-identity-', dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name)
        (self.repo / 'tools').mkdir()
        (self.repo / 'crates/grund-agent').mkdir(parents=True)
        for name in ('tools/release.py', 'compose.yaml', 'crates/grund-agent/install.sh'):
            shutil.copyfile(ROOT / name, self.repo / name)
        self.git('init', '-q', '-b', 'main')
        self.git('config', 'user.name', 'Release test')
        self.git('config', 'user.email', 'release@test.invalid')
        self.git('add', '.')
        self.git('commit', '-qm', 'release source')
        self.commit = self.git('rev-parse', 'HEAD')
        self.tag = 'v0.0.0-alpha.9'
        self.git('tag', '-a', self.tag, '-m', 'annotated alpha')
        self.object = self.git('rev-parse', 'refs/tags/' + self.tag)

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.repo, env=self.environment, text=True).strip()

    def prepare(self):
        environment = self.environment | {'CI_COMMIT_TAG': self.tag, 'CI_COMMIT_SHA': self.object}
        return subprocess.run([sys.executable, 'tools/release.py', 'prepare'], cwd=self.repo,
                              env=environment, capture_output=True, text=True)

    def test_an_annotated_tag_object_stages_the_peeled_source_commit(self):
        self.assertNotEqual(self.object, self.commit)
        result = self.prepare()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.repo / 'scratch/tag-release/dist/release.txt').read_text(), self.commit + '\n')

    def test_an_annotated_tag_cannot_publish_a_different_checkout(self):
        self.git('commit', '--allow-empty', '-qm', 'another source commit')
        result = self.prepare()
        self.assertEqual(result.returncode, 1)
        self.assertFalse((self.repo / 'scratch/tag-release/dist/release.txt').exists())

    def test_a_concurrent_reader_never_observes_partial_release_metadata(self):
        result = self.prepare()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.git('commit', '--allow-empty', '-qm', 'next source commit')
        next_commit = self.git('rev-parse', 'HEAD')
        next_tag = 'v0.0.0-alpha.10'
        self.git('tag', '-a', next_tag, '-m', 'next annotated alpha')
        specification = importlib.util.spec_from_file_location('release', self.repo / 'tools/release.py')
        release = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(release)
        release.TAG = next_tag
        release.REVISION = next_commit
        previous_directory = Path.cwd()
        os.chdir(self.repo)
        self.addCleanup(os.chdir, previous_directory)
        partial_write = threading.Event()
        finish_write = threading.Event()
        open_file = io.open
        payload = next_commit + '\n'

        class PausedWriter:
            def __init__(self, file):
                self.file = file

            def __getattr__(self, name):
                return getattr(self.file, name)

            def __enter__(self):
                self.file.__enter__()
                return self

            def __exit__(self, *args):
                return self.file.__exit__(*args)

            def write(self, data):
                if data != payload and data != payload.encode():
                    return self.file.write(data)
                midpoint = len(data) // 2
                first = self.file.write(data[:midpoint])
                self.file.flush()
                partial_write.set()
                if not finish_write.wait(10):
                    raise TimeoutError('concurrent metadata reader did not finish')
                return first + self.file.write(data[midpoint:])

        def pause_metadata_write(*args, **kwargs):
            return PausedWriter(open_file(*args, **kwargs))

        metadata = self.repo / 'scratch/tag-release/dist/release.txt'
        with mock.patch.object(io, 'open', side_effect=pause_metadata_write):
            with ThreadPoolExecutor(max_workers=1) as executor:
                writer = executor.submit(release.prepare)
                try:
                    self.assertTrue(partial_write.wait(10), 'metadata writer did not reach its midpoint')
                    self.assertEqual(metadata.read_text(), self.commit + '\n')
                finally:
                    finish_write.set()
                writer.result(timeout=10)
        self.assertEqual(metadata.read_text(), next_commit + '\n')


if __name__ == '__main__':
    unittest.main()
