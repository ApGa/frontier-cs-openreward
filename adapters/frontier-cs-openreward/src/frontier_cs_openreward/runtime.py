"""Isolated HPC runtime built on the existing OpenReward Singularity backend."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from functools import lru_cache
import hashlib
import importlib
import json
import logging
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
from typing import Any
from uuid import uuid4

from .contracts import CommandResult, InfrastructureError, TaskRecord

_BACKEND_REVISION = "97bc90e619f61dd1d21e80be3627dddd42235d63"


@lru_cache(maxsize=1)
def _backend_module():
    path = Path(os.environ["FRONTIER_SANDBOX_BACKEND_ROOT"]).resolve()
    revision = subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()
    if revision != _BACKEND_REVISION:
        raise InfrastructureError("Frontier-CS sandbox dependency revision mismatch")
    changed = subprocess.check_output(
        ["git", "-C", str(path), "diff", "HEAD", "--", "sandbox_backends.py", "session_cleanup.py"], text=True,
    )
    if changed:
        raise InfrastructureError("Frontier-CS sandbox dependency has uncommitted changes")
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
    module = importlib.import_module("sandbox_backends")
    if Path(module.__file__).resolve() != path / "sandbox_backends.py":
        raise InfrastructureError("Another sandbox backend shadows the pinned dependency")
    return module


@dataclass
class _SandboxGeneration:
    # One shared budget and recovery per instance lifetime. Completed runs do
    # not retain PID roots; orphaned background work belongs to namespace init.
    exec_pids: set[int] = field(default_factory=set)
    operations: set[asyncio.Task] = field(default_factory=set)
    watcher: asyncio.Task | None = None
    failure: Exception | None = None
    recovery: asyncio.Task | None = None


class Sandbox:
    """One private writable instance; mounts and environment are operator-only.

    A single lifetime watchdog charges the instance and every active exec tree
    to one PSS budget, including background work between tools. On a breach all
    execs are reaped before the instance restarts; its writable files survive.
    Active calls (or the next call after an idle breach) return 137. Subsequent
    calls use the recovered instance. Memory sensor errors fail as infrastructure.
    """

    def __init__(
        self, image: str, *, mounts=(), env=None, cpus=(), workdir="/app",
        memory_limit_bytes: int | None = None,
    ):
        backend = _backend_module()
        # Writable Singularity instances otherwise retain an empty image
        # resolver. Only this trusted host file is exposed, read-only.
        self.mounts = (*mounts, (Path("/etc/resolv.conf"), "/etc/resolv.conf", True))
        self.env = dict(env or {})
        self.cpus = tuple(cpus)
        self.workdir = workdir
        self.memory_limit_bytes = (int(os.getenv("SWE_SINGULARITY_MEMORY_LIMIT_BYTES", "0"))
                                   if memory_limit_bytes is None else memory_limit_bytes)
        if self.memory_limit_bytes < 0:
            raise ValueError("Sandbox memory limit cannot be negative")
        owner = self

        class TaskSandbox(backend.SingularitySandbox):
            async def _ensure_image(self):
                # The reused backend is OCI-only. Operator manifests also
                # contain prebuilt, pinned local SIF images; never pull those
                # paths as if they were Docker repository names.
                if image.startswith(("/", "file://")):
                    path = Path(image.removeprefix("file://")).resolve(strict=True)
                    if not await self._sif_is_valid(path):
                        raise InfrastructureError("Configured local Frontier-CS image is not a valid SIF")
                    return path
                return await super()._ensure_image()

            async def _discover_image_workdir(self):
                return owner.workdir

            async def _discover_container_workdir(self):
                return owner.workdir

            async def _create_writable_directory(self):
                await super()._create_writable_directory()
                root = self.writable_rootfs_path.resolve(strict=True)
                for source, destination, _ in owner.mounts:
                    source = Path(source).resolve(strict=True)
                    relative = Path(destination).relative_to("/")
                    if ".." in relative.parts or ":" in destination:
                        raise ValueError("Invalid container mount destination")
                    target = root
                    for part in relative.parts:
                        target = target / part
                        if target.is_symlink():
                            raise ValueError("Container bind destination traverses a symlink")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if source.is_dir():
                        target.mkdir(exist_ok=True)
                    elif not target.exists():
                        target.touch()
                    elif not target.is_file():
                        raise ValueError("Container file bind destination is not a file")

            def _environment_file(self):
                destination = self.session_dir / "frontier-environment"
                if destination.exists():
                    return str(destination)
                lines = []
                for key, value in owner.env.items():
                    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) or "\n" in str(value):
                        raise ValueError("Invalid container environment entry")
                    lines.append(f"{key}={value}\n")
                temporary = destination.with_name(f".frontier-environment-{uuid4().hex}")
                with open(temporary, "x", opener=lambda path, flags: os.open(path, flags, 0o600)) as stream:
                    stream.write("".join(lines))
                temporary.replace(destination)
                return str(destination)

            def _instance_start_args(self):
                args = super()._instance_start_args()
                extra = ["--env-file", self._environment_file()]
                for source, destination, readonly in owner.mounts:
                    source = Path(source).resolve(strict=True)
                    if ":" in str(source) or ":" in destination or not destination.startswith("/"):
                        raise ValueError("Invalid container mount")
                    extra += ["--bind", f"{source}:{destination}:{'ro' if readonly else 'rw'}"]
                return args[:-2] + extra + args[-2:]

            def _exec_args(self, command, *, cwd=None):
                args = super()._exec_args(command, cwd=cwd)
                index = args.index(f"instance://{self.name}")
                args[index:index] = ["--env-file", self._environment_file()]
                if owner.cpus:
                    index = args.index(f"instance://{self.name}") + 1
                    args[index:index] = ["taskset", "--cpu-list", ",".join(map(str, owner.cpus))]
                return args

        self.backend = TaskSandbox(image)
        self.backend.writable_directory = True
        self._generation = _SandboxGeneration()
        self._closing = False
        self._close_task = None

    def _memory_roots(self, generation):
        return tuple(pid for pid in (self.backend.instance_pid, *generation.exec_pids) if pid)

    def _start_watcher(self, generation):
        if self.memory_limit_bytes:
            generation.watcher = asyncio.create_task(self._monitor_memory(generation))

    async def _monitor_memory(self, generation):
        try:
            await _watch_memory(lambda: self._memory_roots(generation), self.memory_limit_bytes)
        except (MemoryLimitExceeded, OSError, ValueError) as exc:
            logging.getLogger(__name__).error(
                "frontier_sandbox_memory_failure %s",
                json.dumps({"sandbox": self.backend.name,
                            "limit_bytes": self.memory_limit_bytes,
                            "roots": self._memory_roots(generation),
                            "error": f"{type(exc).__name__}: {exc}"}),
            )
            self._begin_recovery(generation, exc)

    def _begin_recovery(self, generation, failure):
        if generation.failure is None:
            generation.failure = failure
        if generation.recovery is None:
            self.backend.started = False
            generation.recovery = asyncio.create_task(self._recover(generation))

    async def _recover(self, generation):
        # Cancel only the raw transports, not their callers. Transport cleanup
        # kills and reaps its own process group before a fresh instance exists.
        tasks = tuple(generation.operations)
        if generation.watcher is not None:
            tasks += (generation.watcher,)
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if not self._closing:
            await self.backend._restart_after_interrupted_command()

    async def _finish_recovery(self, generation):
        try:
            await finish_cleanup(generation.recovery)
        except Exception as exc:
            raise InfrastructureError("Sandbox could not recover after interrupted command") from exc
        if self._generation is generation and not self._closing:
            self._generation = _SandboxGeneration()
            self._start_watcher(self._generation)

    async def _report_failure(self, generation):
        await self._finish_recovery(generation)
        if isinstance(generation.failure, MemoryLimitExceeded):
            return CommandResult(str(generation.failure), 137)
        raise InfrastructureError("Sandbox command interrupted by instance recovery") from generation.failure

    async def start(self):
        try:
            await self.backend.start()
        except Exception as exc:
            raise InfrastructureError(f"Could not start Frontier-CS container: {exc}") from exc
        self._start_watcher(self._generation)

    async def run(self, command, timeout=None, stdin_data=None) -> CommandResult:
        sandbox, generation = self.backend, self._generation
        if self._closing:
            raise InfrastructureError("Frontier-CS sandbox is closed")
        if generation.failure is not None:
            return await self._report_failure(generation)
        if not sandbox.started or sandbox._stopping:
            raise InfrastructureError("Frontier-CS sandbox is unavailable")

        async def transport():
            process = None

            def started(proc):
                nonlocal process
                process = proc
                generation.exec_pids.add(proc.pid)

            try:
                return await _backend_module()._run_process(
                    sandbox._exec_args(command),
                    timeout=sandbox.default_timeout if timeout is None else timeout,
                    env=sandbox._instance_environment(), stdin_data=stdin_data,
                    on_process_started=started,
                )
            finally:
                if process is not None:
                    generation.exec_pids.discard(process.pid)

        operation = asyncio.create_task(transport())
        generation.operations.add(operation)
        try:
            result = await asyncio.shield(operation)
        except asyncio.CancelledError:
            if self._closing:
                raise InfrastructureError("Frontier-CS sandbox was closed")
            caller_cancelled = asyncio.current_task().cancelling() > 0
            self._begin_recovery(generation, InfrastructureError("Command cancelled"))
            if caller_cancelled:
                await self._finish_recovery(generation)
                raise
            return await self._report_failure(generation)
        finally:
            generation.operations.discard(operation)
        if self._closing:
            raise InfrastructureError("Frontier-CS sandbox was closed")
        if generation.failure is not None:
            return await self._report_failure(generation)
        if result.return_code in (124, 137):
            self._begin_recovery(generation, InfrastructureError("Command interrupted"))
            await self._finish_recovery(generation)
        return CommandResult(result.output, result.return_code)

    async def _close(self):
        self._closing = True
        generation = self._generation
        if generation.watcher is not None:
            generation.watcher.cancel()
        tasks = tuple(generation.operations)
        for task in tasks:
            task.cancel()
        if generation.watcher is not None:
            tasks += (generation.watcher,)
        if generation.recovery is not None:
            tasks += (generation.recovery,)
        await asyncio.gather(*tasks, return_exceptions=True)
        await self.backend.stop()

    async def close(self):
        self._closing = True
        if self._close_task is None:
            self._close_task = asyncio.create_task(self._close())
        await finish_cleanup(self._close_task)


class Service:
    """Foreground daemon inside an instance, with an operator-private log."""

    def __init__(self, sandbox: Sandbox, command: str):
        self.sandbox = sandbox
        self.command = command
        self.process = None
        self.log = None
        self._close_task = None
        self._monitor_task = None
        self.memory_exceeded = False
        self.monitor_error = None

    async def start(self):
        backend = self.sandbox.backend
        self.log = (backend.session_dir / f"service-{uuid4().hex[:8]}.log").open("wb")
        try:
            self.process = await asyncio.create_subprocess_exec(
                *backend._exec_args(self.command), stdout=self.log, stderr=self.log,
                env=backend._instance_environment(), start_new_session=True,
            )
            if self.sandbox.memory_limit_bytes:
                self._monitor_task = asyncio.create_task(self._monitor_memory())
        except BaseException:
            self.log.close()
            raise

    def alive(self):
        return self.process is not None and self.process.returncode is None

    async def _monitor_memory(self):
        try:
            await _watch_memory((self.sandbox.backend.instance_pid, self.process.pid),
                                self.sandbox.memory_limit_bytes)
        except (MemoryLimitExceeded, OSError, ValueError) as exc:
            self.memory_exceeded = isinstance(exc, MemoryLimitExceeded)
            self.monitor_error = f"{type(exc).__name__}: {exc}"
            if self.log is not None and not self.log.closed:
                self.log.write(("\nFrontier-CS memory monitor failure: " + self.monitor_error + "\n").encode())
                self.log.flush()
            # Killing the judge itself is infrastructure failure. The caller
            # must never reinterpret service death as candidate quality zero.
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await self.process.wait()

    async def _stop(self):
        try:
            if self.alive():
                try:
                    os.killpg(self.process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    await asyncio.wait_for(self.process.wait(), 10)
                except TimeoutError:
                    try:
                        os.killpg(self.process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    await self.process.wait()
        finally:
            if self._monitor_task is not None:
                self._monitor_task.cancel()
                await asyncio.gather(self._monitor_task, return_exceptions=True)
            if self.log is not None:
                self.log.close()

    async def close(self):
        if self._close_task is None:
            self._close_task = asyncio.create_task(self._stop())
        await finish_cleanup(self._close_task)


_PARENT_DEATH_EXEC = '''import ctypes, os, signal, sys
parent = int(sys.argv[1])
if os.getppid() != parent:
    sys.exit(125)
if ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGKILL, 0, 0, 0):
    raise OSError(ctypes.get_errno(), "prctl(PR_SET_PDEATHSIG) failed")
if os.getppid() != parent:
    sys.exit(125)
os.execv(sys.argv[2], sys.argv[2:])
'''


class HostService(Service):
    """Owned native daemon using only a pinned binary and explicit environment."""

    def __init__(self, sandbox, args, *, expected_sha256):
        super().__init__(sandbox, "")
        self.args = list(args)
        self.executable = Path(self.args[0]).resolve(strict=True)
        with self.executable.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if digest != expected_sha256:
            raise InfrastructureError("Native Frontier-CS service binary hash mismatch")
        self.args[0] = str(self.executable)
        self.service_id = uuid4().hex
        self.marker = None

    async def start(self):
        session = self.sandbox.backend.session_dir
        self.log = open(session / f"service-{self.service_id}.log", "xb",
                        opener=lambda path, flags: os.open(path, flags, 0o600))
        args = self.args
        if self.sandbox.cpus:
            args = ["/usr/bin/taskset", "--cpu-list", ",".join(map(str, self.sandbox.cpus)), *args]
        environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TMPDIR": str(session / "tmp"),
                       "FRONTIER_NATIVE_SERVICE_ID": self.service_id}
        try:
            self.process = await asyncio.create_subprocess_exec(
                sys.executable, "-c", _PARENT_DEATH_EXEC, str(os.getpid()), *args,
                stdout=self.log, stderr=self.log, env=environment, cwd=session,
                start_new_session=True,
            )
            await self._record_identity(session)
            if self.sandbox.memory_limit_bytes:
                self._monitor_task = asyncio.create_task(self._monitor_memory())
        except BaseException:
            await self.close()
            raise

    async def _record_identity(self, session):
        process = Path(f"/proc/{self.process.pid}")
        for _ in range(100):
            if self.process.returncode is not None:
                raise InfrastructureError("Native Frontier-CS service exited before identity capture")
            try:
                executable = (process / "exe").resolve(strict=True)
                token = f"FRONTIER_NATIVE_SERVICE_ID={self.service_id}".encode()
                environment = (process / "environ").read_bytes().split(b"\0")
                if executable == self.executable and token in environment:
                    break
            except (FileNotFoundError, ProcessLookupError):
                pass
            await asyncio.sleep(0.01)
        else:
            raise InfrastructureError("Native Frontier-CS service identity did not stabilize")
        fields = (process / "stat").read_text().rsplit(")", 1)[1].split()
        identity = {"version": 1, "hostname": socket.gethostname(), "uid": os.getuid(),
                    "pid": self.process.pid, "pgid": os.getpgid(self.process.pid),
                    "start_time": fields[19], "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                    "executable": str(self.executable), "session_path": str(session),
                    "service_instance_id": self.service_id}
        directory = Path(os.environ["FRONTIER_SESSION_ROOT"]) / ".native-services"
        directory.mkdir(mode=0o700, exist_ok=True)
        directory.chmod(0o700)
        self.marker = directory / f"{self.service_id}.json"
        temporary = self.marker.with_suffix(".tmp")
        with open(temporary, "x", opener=lambda path, flags: os.open(path, flags, 0o600)) as stream:
            json.dump(identity, stream)
        temporary.replace(self.marker)

    async def _stop(self):
        await super()._stop()
        if self.marker is not None:
            try:
                os.killpg(self.process.pid, 0)
            except ProcessLookupError:
                self.marker.unlink(missing_ok=True)
            # Retain evidence for the exact-ownership janitor if any group
            # member survives normal teardown.


async def finish_cleanup(task):
    """Finish owned cleanup before propagating caller cancellation."""
    cancelled = False
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            cancelled = True
    result = task.result()
    if cancelled:
        raise asyncio.CancelledError
    return result


class MemoryLimitExceeded(RuntimeError):
    """A task's process tree exceeded its proportional resident memory budget."""


@lru_cache(maxsize=1024)
def _note_rss_fallback(pid):
    logging.getLogger(__name__).warning(
        "frontier_memory_accounting_fallback pid=%s fallback=VmRSS reason=smaps_permission_denied", pid
    )


def _resident_bytes(process):
    try:
        for line in (process / "smaps_rollup").read_text().splitlines():
            if line.startswith("Pss:"):
                return int(line.split()[1]) * 1024
    except PermissionError:
        # The setuid Singularity supervisor can remain non-dumpable. Charge
        # its RSS conservatively; ordinary candidate/shared assets retain PSS.
        for line in (process / "status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                _note_rss_fallback(int(process.name))
                return int(line.split()[1]) * 1024
        fields = (process / "stat").read_text().rsplit(")", 1)[1].split()
        if fields[0] == "Z":
            return 0
        raise PermissionError(f"Neither PSS nor RSS is readable for task process {process.name}")
    fields = (process / "stat").read_text().rsplit(")", 1)[1].split()
    if fields[0] == "Z":
        return 0
    raise ValueError(f"Missing PSS accounting for task process {process.name}")


def process_tree_pss_bytes(root_pid: int | tuple[int, ...]) -> int:
    """Count private pages fully and shared resident pages proportionally.

    Like the existing backend watchdog this is a sampled guard, not a cgroup.
    PSS avoids charging every copy of immutable mmap-backed assets in full.
    Non-dumpable supervisors fall back conservatively to RSS, with a log event.
    """
    pending = [root_pid] if isinstance(root_pid, int) else list(root_pid)
    seen, total = set(), 0
    while pending:
        pid = pending.pop()
        if pid in seen:
            continue
        seen.add(pid)
        process = Path(f"/proc/{pid}")
        try:
            total += _resident_bytes(process)
            for thread in (process / "task").iterdir():
                try:
                    pending.extend(int(child) for child in (thread / "children").read_text().split())
                except (FileNotFoundError, ProcessLookupError):
                    pass
        except (FileNotFoundError, ProcessLookupError):
            pass
    return total


async def _watch_memory(root_pid, limit):
    unreadable_since = None
    while True:
        try:
            roots = root_pid() if callable(root_pid) else root_pid
            used = await asyncio.to_thread(process_tree_pss_bytes, roots)
            unreadable_since = None
        except PermissionError:
            # A setuid Singularity starter is temporarily non-dumpable before
            # exec. Retry that transition briefly; persistent unreadable task
            # memory still fails closed instead of disabling enforcement.
            now = asyncio.get_running_loop().time()
            if unreadable_since is None:
                unreadable_since = now
            if now - unreadable_since >= 2:
                raise
            await asyncio.sleep(0.1)
            continue
        if used > limit:
            raise MemoryLimitExceeded(f"Task memory limit exceeded: PSS {used} bytes > {limit} bytes")
        await asyncio.sleep(1)


async def _guard_memory(operation, root_pid, limit):
    if not limit:
        return await operation
    command = asyncio.create_task(operation)
    watcher = asyncio.create_task(_watch_memory(root_pid, limit))
    try:
        done, _ = await asyncio.wait((command, watcher), return_when=asyncio.FIRST_COMPLETED)
        if watcher in done:
            watcher.result()
        return await command
    finally:
        for task in (command, watcher):
            if not task.done():
                task.cancel()
        cleanup = asyncio.gather(command, watcher, return_exceptions=True)
        await finish_cleanup(cleanup)


def reserve_port() -> socket.socket:
    reservation = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    reservation.bind(("127.0.0.1", 0))
    return reservation


async def request_json(url: str, *, method="GET", json=None, data=None, headers=None, timeout=30):
    import aiohttp
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout), trust_env=False) as client:
            async with client.request(method, url, json=json, data=data, headers=headers) as response:
                response.raise_for_status()
                payload = await response.json(content_type=None)
                if not isinstance(payload, dict):
                    raise ValueError("Expected a JSON object")
                return payload
    except (aiohttp.ClientError, TimeoutError, ValueError) as exc:
        # Do not include the URL: it may contain a per-session capability.
        raise InfrastructureError(f"Frontier-CS judge request failed ({type(exc).__name__})") from exc


class FrontierRuntimeFactory:
    def __init__(self, manifest: dict[str, Any], source_root: Path):
        self.manifest = manifest
        self.source_root = source_root
        self.algorithmic_pool = None

    def create(self, task: TaskRecord):
        if task.suite == "algorithmic":
            from .algorithmic_runtime import AlgorithmicPool, AlgorithmicSession
            if not self.manifest.get("algorithmic", {}).get("ready"):
                raise InfrastructureError("Algorithmic runtime has not passed preflight")
            if self.algorithmic_pool is None:
                self.algorithmic_pool = AlgorithmicPool(self.manifest["algorithmic"], self.source_root)
            return AlgorithmicSession(task, self.algorithmic_pool)
        if task.suite == "2.0":
            from .runtime20 import Frontier20Session
            entry = self.manifest.get("tasks", {}).get(task.task_id)
            if not entry or not entry.get("ready"):
                raise InfrastructureError(f"Task runtime has not passed preflight: {task.task_id}")
            return Frontier20Session(task, entry)
        raise ValueError(f"Unsupported Frontier-CS suite: {task.suite}")

    async def close(self):
        if self.algorithmic_pool is not None:
            await self.algorithmic_pool.close()


def create_runtime_factory():
    manifest = json.loads(Path(os.environ["FRONTIER_IMAGE_MANIFEST"]).read_text())
    if manifest.get("version") != 1 or not manifest.get("ready"):
        raise InfrastructureError("Frontier-CS images have not passed deployment preflight")
    return FrontierRuntimeFactory(manifest, Path(os.environ["FRONTIER_SOURCE_ROOT"]))
