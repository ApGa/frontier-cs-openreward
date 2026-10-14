"""Exercise the PSS owner with real bounded processes and the vendored transport.

The host fixture substitutes only Singularity lifecycle operations; exec transport,
process registration, accounting, recovery ordering, and command failures are real.
Actual namespace orphan adoption is covered by the separate deployed SIF probe.
"""
import asyncio
import os
import shlex
import signal
import sys

import pytest

from frontier_cs_openreward import runtime, sandbox_backends
from frontier_cs_openreward.contracts import InfrastructureError


@pytest.fixture
def backend_module():
    assert runtime._backend_module() is sandbox_backends
    return sandbox_backends


class HostInstance:
    def __init__(self, directory):
        self.directory = directory
        self.name = 'owned-test-instance'
        self.started = False
        self._stopping = False
        self.default_timeout = 10
        self.instance_pid = None
        self.process = None
        self.restarts = 0
        self.forced_stops = 0
        self.retired = []

    async def start(self):
        # Only the first instance responds to the trigger; the trigger file
        # survives restart to verify the workspace is preserved.
        code = ('import os,time; from pathlib import Path; trigger=Path("allocate"); '
                'data=None\nwhile True:\n'
                ' if trigger.exists() and data is None: data=bytearray(160*1024**2)\n'
                ' time.sleep(.05)') if not self.restarts else 'import time; time.sleep(60)'
        self.process = await asyncio.create_subprocess_exec(
            sys.executable, '-c', code, cwd=self.directory, start_new_session=True)
        self.instance_pid = self.process.pid
        self.started = True

    def _exec_args(self, command):
        return ['/bin/bash', '-c', 'cd ' + shlex.quote(str(self.directory)) + ' && ' + command]

    def _instance_environment(self):
        return None

    async def _kill(self):
        if self.process and self.process.returncode is None:
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await self.process.wait()
        if self.process:
            self.retired.append(self.process)

    async def _stop_instance(self, *, force=False):
        self.forced_stops += int(force)
        await self._kill()
        self.started = False

    async def _restart_after_interrupted_command(self, *, force=False):
        await self._kill()
        self.restarts += 1
        await self.start()

    async def stop(self):
        self._stopping = True
        await self._kill()
        self.started = False


def owner(directory, limit=96 * 1024**2):
    sandbox = object.__new__(runtime.Sandbox)
    sandbox.backend = HostInstance(directory)
    sandbox.memory_limit_bytes = limit
    sandbox._generation = runtime._SandboxGeneration()
    sandbox._closing = False
    sandbox._close_task = None
    return sandbox


def python(code):
    return shlex.quote(sys.executable) + ' -c ' + shlex.quote(code)


ALLOC = 'import time; data=bytearray(160*1024**2); time.sleep(30)'


@pytest.mark.asyncio
@pytest.mark.parametrize('command', [
    python(ALLOC),
    python('import subprocess,sys; subprocess.run([sys.executable,"-c",' + repr(ALLOC) + '])'),
    python('import subprocess,sys,time; data=subprocess.run([sys.executable,"-c",'
           '"import sys; sys.stdout.buffer.write(b\'x\'*(160*1024**2))"],capture_output=True); time.sleep(30)'),
    'result=$(' + python('import sys; sys.stdout.buffer.write(b"x"*(160*1024**2))') + '); sleep 30',
    python('import os; os.close(1); os.close(2); ' + ALLOC),
])
async def test_actual_exec_memory_breach_recovers_and_preserves_files(backend_module, tmp_path, command):
    sandbox = owner(tmp_path)
    await sandbox.start()
    (tmp_path / 'retained').write_text('still here')
    try:
        result = await asyncio.wait_for(sandbox.run(command), 8)
        assert result.exit_code == 137
        assert 'Task memory limit exceeded' in result.output
        assert sandbox.backend.restarts == 1
        assert sandbox.backend.forced_stops == 1
        assert not sandbox._generation.exec_pids
        assert (await sandbox.run('cat retained')).output == 'still here'
    finally:
        await sandbox.close()
    assert all(proc.returncode is not None for proc in sandbox.backend.retired)


@pytest.mark.asyncio
async def test_background_breach_is_reported_on_next_call(backend_module, tmp_path):
    sandbox = owner(tmp_path)
    await sandbox.start()
    try:
        assert (await sandbox.run('touch allocate')).exit_code == 0
        async def wait_for_idle_breach():
            while sandbox._generation.recovery is None:
                await asyncio.sleep(.05)
            await sandbox._generation.recovery
        await asyncio.wait_for(wait_for_idle_breach(), 8)
        assert (await sandbox.run('echo first')).exit_code == 137
        assert (await sandbox.run('test -f allocate && echo healthy')).output == 'healthy\n'
        assert sandbox.backend.restarts == 1
        assert sandbox.backend.forced_stops == 1
    finally:
        await sandbox.close()


@pytest.mark.asyncio
async def test_parallel_execs_share_one_budget_and_one_recovery(backend_module, tmp_path):
    sandbox = owner(tmp_path)
    await sandbox.start()
    try:
        command = python('import time; data=bytearray(60*1024**2); time.sleep(30)')
        results = await asyncio.wait_for(asyncio.gather(sandbox.run(command), sandbox.run(command)), 8)
        assert [item.exit_code for item in results] == [137, 137]
        assert sandbox.backend.restarts == 1
        assert (await sandbox.run('echo recovered')).output == 'recovered\n'
    finally:
        await sandbox.close()


@pytest.mark.asyncio
async def test_unrelated_sandbox_is_not_killed_or_charged(backend_module, tmp_path):
    (tmp_path / 'other').mkdir()
    first, other = owner(tmp_path), owner(tmp_path / 'other')
    await asyncio.gather(first.start(), other.start())
    try:
        result, sibling = await asyncio.wait_for(asyncio.gather(
            first.run(python(ALLOC)), other.run('sleep 2; echo sibling')), 8)
        assert result.exit_code == 137
        assert sibling.output == 'sibling\n'
        assert other.backend.restarts == 0
    finally:
        await asyncio.gather(first.close(), other.close())


@pytest.mark.asyncio
async def test_cancellation_and_close_reap_commands_and_watcher(backend_module, tmp_path):
    sandbox = owner(tmp_path)
    await sandbox.start()
    generation = sandbox._generation
    first = asyncio.create_task(sandbox.run('sleep 30'))
    second = asyncio.create_task(sandbox.run('sleep 30'))
    while len(generation.exec_pids) != 2:
        await asyncio.sleep(.01)
    first.cancel()
    results = await asyncio.gather(first, second, return_exceptions=True)
    assert isinstance(results[0], asyncio.CancelledError)
    assert isinstance(results[1], InfrastructureError)
    assert sandbox.backend.restarts == 1
    assert sandbox.backend.forced_stops == 0
    assert not generation.exec_pids
    assert generation.watcher.done()
    current = sandbox._generation
    active = asyncio.create_task(sandbox.run('sleep 30'))
    while not current.exec_pids:
        await asyncio.sleep(.01)
    await sandbox.close()
    assert isinstance((await asyncio.gather(active, return_exceptions=True))[0], InfrastructureError)
    assert sandbox.backend.restarts == 1
    assert current.watcher.done()
    assert not current.exec_pids


@pytest.mark.asyncio
async def test_sensor_error_fails_closed_and_stops_allocating_exec(backend_module, monkeypatch, tmp_path):
    sandbox = owner(tmp_path)
    await sandbox.start()
    def broken(_):
        raise ValueError('missing accounting')
    monkeypatch.setattr(runtime, 'process_tree_pss_bytes', broken)
    try:
        with pytest.raises(InfrastructureError):
            await asyncio.wait_for(sandbox.run('sleep 30'), 8)
        assert sandbox.backend.restarts == 1
    finally:
        await sandbox.close()


@pytest.mark.asyncio
async def test_close_wins_when_transport_timeout_is_ready(backend_module, monkeypatch, tmp_path):
    sandbox = owner(tmp_path)
    await sandbox.start()
    closing = []
    async def timed_out(*args, **kwargs):
        # Queue close at the transport completion boundary, before its caller
        # handles timeout recovery. This covers the non-cancellation path.
        asyncio.get_running_loop().call_soon(
            lambda: closing.append(asyncio.create_task(sandbox.close())))
        return backend_module.LocalRunResult('timed out', 124)
    monkeypatch.setattr(backend_module, '_run_process', timed_out)
    try:
        with pytest.raises(InfrastructureError, match='closed'):
            await sandbox.run('ignored')
        await asyncio.gather(*closing)
        assert sandbox.backend.restarts == 0
        assert not sandbox.backend.started
    finally:
        await sandbox.close()


@pytest.mark.asyncio
async def test_close_during_recovery_reaps_without_restarting(backend_module, tmp_path):
    sandbox = owner(tmp_path)
    await sandbox.start()
    generation = sandbox._generation
    reaping, release = asyncio.Event(), asyncio.Event()
    async def transport_cleanup():
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            reaping.set()
            await release.wait()
            raise
    operation = asyncio.create_task(transport_cleanup())
    generation.operations.add(operation)
    await asyncio.sleep(0)
    sandbox._begin_recovery(generation, runtime.MemoryLimitExceeded('test limit'))
    await reaping.wait()
    closing = asyncio.create_task(sandbox.close())
    await asyncio.sleep(0)
    release.set()
    await closing
    assert generation.recovery.done()
    assert operation.done()
    assert sandbox.backend.restarts == 0
    assert not sandbox.backend.started
