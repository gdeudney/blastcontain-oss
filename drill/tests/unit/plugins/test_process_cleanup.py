"""Pipe backpressure regressions using real child processes, without Podman."""
import asyncio
import sys

import pytest

from blastcontain_drill.contracts import PluginManifest
from blastcontain_drill.plugins.runtime import PodmanWorker, WorkerError, _control


@pytest.mark.parametrize('fd', [1, 2], ids=['stdout', 'stderr'])
def test_worker_close_reaps_process_with_full_pipe(fd):
    async def run():
        manifest = PluginManifest('fixture', '1', 'sha256:'+'a'*64, ('attack_strategy',), (), 'Apache-2.0')
        worker = PodmanWorker(manifest, [])
        worker.process = await asyncio.create_subprocess_exec(
            sys.executable, '-c', f'import os,time; os.write({fd},b"x"*10000000); time.sleep(60)',
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            await asyncio.sleep(.2)
            await asyncio.wait_for(worker.close(), 4)
            assert worker.process.returncode is not None
            assert worker.process.stdout.at_eof() and worker.process.stderr.at_eof()
        finally:
            # A regression must not leave the test child running after failure.
            if worker.process.returncode is None:
                worker.process.kill()
            worker.process._transport.close()

    asyncio.run(run())


@pytest.mark.parametrize('fd', [1, 2], ids=['stdout', 'stderr'])
def test_control_overflow_reaps_child_without_blocking(fd):
    async def run():
        command = [sys.executable, '-c', f'import os,time; os.write({fd},b"x"*10000000); time.sleep(60)']
        with pytest.raises(WorkerError, match='byte limit'):
            await asyncio.wait_for(_control(command), 4)
    asyncio.run(run())
