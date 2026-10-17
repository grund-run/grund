#!/usr/bin/env python3
"""Measure the real non-publishing release builder and its staged bytes."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent


def cgroup(name):
    try:
        return Path('/sys/fs/cgroup', name).read_text().strip()
    except OSError:
        return 'unavailable'


def cpu_usage():
    return dict(line.split() for line in cgroup('cpu.stat').splitlines() if len(line.split()) == 2).get('usage_usec')


def measure(arch, label, jobs, cgu=1, database=None, fresh_workspace=False):
    environment = os.environ.copy()
    environment.update({
        'CARGO_BUILD_JOBS': str(jobs), 'CARGO_INCREMENTAL': '0',
        'GRUND_RELEASE_BENCHMARK_VERSION': f'ciperf-{label}-{environment["CI_COMMIT_SHA"]}',
    })
    if cgu == 1:
        environment.pop('CARGO_PROFILE_RELEASE_CODEGEN_UNITS', None)
    else:
        environment['CARGO_PROFILE_RELEASE_CODEGEN_UNITS'] = str(cgu)
    if arch == 'amd64':
        environment.pop('CARGO_BUILD_TARGET', None)
        target = 'target/release-build' if cgu == 1 else 'target/release-cgu16'
        step = 'release' if cgu == 1 else 'release-native-cgu16'
    else:
        environment['CARGO_BUILD_TARGET'] = 'aarch64-unknown-linux-musl'
        target = 'target/release-arm64'
        step = 'release-arm64'
    environment['CARGO_TARGET_DIR'] = target
    restore = ['ci-cache', 'restore', step, '--preset', 'cargo']
    if arch == 'arm64':
        restore.extend(['--dir', 'scratch/tag-release/tooling'])
    if shutil.which('ci-cache'):
        subprocess.run(restore, cwd=ROOT, env=environment, check=True)
        subprocess.run(['ci-cache', 'env'], cwd=ROOT, env=environment, check=True)
    if fresh_workspace:
        # Match snapshot restores: dependencies stay, workspace artifacts do not.
        metadata = json.loads(subprocess.check_output([
            'cargo', 'metadata', '--locked', '--no-deps', '--format-version', '1', '--offline',
        ], cwd=ROOT, env=environment, text=True))
        packages = [argument for package in metadata['packages'] for argument in ('-p', package['name'])]
        subprocess.run(['cargo', 'clean', '--release', *packages], cwd=ROOT,
                       env=environment, check=True)
    before = cpu_usage()
    started = time.monotonic()
    subprocess.run(['sh', 'tools/release-build.sh', '--benchmark', arch], cwd=ROOT,
                   env=environment, check=True)
    elapsed = time.monotonic() - started
    after = cpu_usage()
    binary = ROOT / 'scratch/tag-release/dist' / f'grund-linux-{arch}'
    destination = ROOT / 'scratch/tag-perf' / label
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(binary, destination / 'grund')
    (destination / 'grund').chmod(0o755)
    result = {
        'label': label, 'agent': environment.get('CI_MACHINE', ''), 'arch': arch,
        'jobs': jobs, 'codegen_units': cgu, 'wall_s': elapsed,
        'binary_bytes': binary.stat().st_size,
        'sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
        'cpu_s': (int(after) - int(before)) / 1e6 if before and after else None,
        'cpu_max': cgroup('cpu.max'), 'memory_max': cgroup('memory.max'),
        'memory_peak_bytes': cgroup('memory.peak'),
    }
    print('RELEASE_MEASURE ' + json.dumps(result, sort_keys=True), flush=True)
    (destination / 'measure.json').write_text(json.dumps(result, indent=2))
    if shutil.which('ci-cache'):
        subprocess.run(['ci-cache', 'stats', step], cwd=ROOT, env=environment, check=True)
    if database:
        environment['GRUND_RELEASE_DATABASE_URL'] = database
        subprocess.run(['python3', 'tools/release-runtime.py', str(destination / 'grund'), '--benchmark'],
                       cwd=ROOT, env=environment, check=True)


def main():
    os.chdir(ROOT)
    if os.environ.get('CI_PIPELINE_EVENT') != 'push' or os.environ.get('CI_COMMIT_TAG'):
        raise RuntimeError('release measurements require a non-tag push pipeline')
    print('RELEASE_CAPACITY ' + json.dumps({
        'agent': os.environ.get('CI_MACHINE', ''), 'logical_cpus': os.cpu_count(),
        'cpu_max': cgroup('cpu.max'), 'memory_max': cgroup('memory.max'),
    }, sort_keys=True), flush=True)
    if sys.argv[1:] == ['matrix']:
        measure('amd64', 'thin-cgu1-j4', 4, database=os.environ['PERF_DATABASE_CGU1'], fresh_workspace=True)
        measure('amd64', 'thin-cgu16-seed-j4', 4, cgu=16, fresh_workspace=True)
        measure('amd64', 'thin-cgu16-j4', 4, cgu=16, database=os.environ['PERF_DATABASE_CGU16'], fresh_workspace=True)
        measure('amd64', 'thin-cgu1-j8', 8, database=os.environ['PERF_DATABASE_CGU1_J8'], fresh_workspace=True)
        measure('amd64', 'thin-cgu16-j8', 8, cgu=16, database=os.environ['PERF_DATABASE_CGU16_J8'], fresh_workspace=True)
    elif len(sys.argv) == 3 and sys.argv[1] in ('amd64', 'arm64'):
        measure(sys.argv[1], sys.argv[2], int(os.environ.get('CARGO_BUILD_JOBS', '4')))
    else:
        raise RuntimeError('usage: release-measure.py {matrix|<amd64|arm64> <label>}')


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, KeyError, ValueError, subprocess.SubprocessError) as error:
        print(f'release measurement failed: {error}', file=sys.stderr)
        raise SystemExit(1)
