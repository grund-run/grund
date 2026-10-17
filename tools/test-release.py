#!/usr/bin/env python3
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

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


if __name__ == '__main__':
    unittest.main()
