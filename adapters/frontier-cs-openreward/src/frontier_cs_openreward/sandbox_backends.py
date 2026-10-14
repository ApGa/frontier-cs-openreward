"""Local sandbox backends for SWE-rebench-V2.

The environment only needs three sandbox operations: start an image, run a
shell command while preserving filesystem changes, and remove the sandbox.
This module provides that small interface for Docker, Enroot, and
Singularity/Apptainer so local self-hosting does not depend on OpenReward's
hosted sandbox service.
"""

from __future__ import annotations

import asyncio
from collections import deque
import fcntl
import hashlib
import json
import os
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable, Iterator, Protocol, TextIO
from uuid import uuid4

from .session_cleanup import remove_session_tree

_PID_NAMESPACE_LAUNCHER = """\
import ctypes
import os
import signal
import sys

PR_SET_PDEATHSIG = 1

expected_parent = int(sys.argv[1])
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
    error_number = ctypes.get_errno()
    raise OSError(error_number, os.strerror(error_number))

# PR_SET_PDEATHSIG has a race if the parent exits between fork and prctl.
if os.getppid() != expected_parent:
    os.kill(os.getpid(), signal.SIGKILL)

os.execvp(sys.argv[2], sys.argv[2:])
"""


_PID_NAMESPACE_REAPER = """\
import os
import signal
import sys


def reap_children(_signum=None, _frame=None):
    while True:
        try:
            child_pid, _status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        except InterruptedError:
            continue
        if child_pid == 0:
            return


# A process inside a PID namespace can signal PID 1 only for signals for
# which PID 1 installed a handler. SIG_IGN deliberately does not provide a
# task-controlled handler that could terminate this reaper. The host-side
# namespace owner uses SIGKILL for teardown.
for protected_signal in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
    signal.signal(protected_signal, signal.SIG_IGN)
signal.signal(signal.SIGCHLD, reap_children)

with open(sys.argv[1], "x", encoding="utf-8") as ready_file:
    ready_file.write("ready\\n")

while True:
    signal.pause()
"""


_PID_NAMESPACE_COMMAND_GATE = """\
import os
import sys

marker_fd = os.open(
    sys.argv[1],
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
    0o600,
)
os.write(marker_fd, b"entered\\n")
os.close(marker_fd)
os.execvp(sys.argv[2], sys.argv[2:])
"""


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


@dataclass
class LocalRunResult:
    output: str
    return_code: int

    @property
    def exit_code(self) -> int:
        return self.return_code

    def __iter__(self) -> Iterator[str | int]:
        yield self.output
        yield self.return_code


class SandboxBackend(Protocol):
    async def start(self) -> None: ...

    async def run(
        self,
        command: str,
        timeout: float | None = None,
        stdin_data: bytes | None = None,
    ) -> LocalRunResult: ...

    async def stop(self) -> None: ...


class _ProcessMemoryLimitExceeded(Exception):
    pass


class _BoundedOutput:
    """Keep the beginning and end while draining arbitrarily noisy commands."""

    def __init__(self, limit: int) -> None:
        if limit < 2:
            raise ValueError("SWE_HOST_PROCESS_OUTPUT_MAX_BYTES must be at least 2")
        self.head_limit = limit // 2
        self.tail_limit = limit - self.head_limit
        self.head = bytearray()
        self.tail: deque[bytes] = deque()
        self.tail_size = 0
        self.total = 0

    def append(self, data: bytes) -> None:
        self.total += len(data)
        head_count = min(len(data), self.head_limit - len(self.head))
        self.head.extend(data[:head_count])
        data = data[head_count:]
        if data:
            self.tail.append(data)
            self.tail_size += len(data)
        while self.tail_size > self.tail_limit:
            first = self.tail.popleft()
            excess = self.tail_size - self.tail_limit
            if len(first) > excess:
                self.tail.appendleft(first[excess:])
                self.tail_size -= excess
            else:
                self.tail_size -= len(first)

    def text(self) -> str:
        omitted = self.total - len(self.head) - self.tail_size
        marker = (
            f"\n[Command output truncated: omitted {omitted} bytes]\n".encode()
            if omitted else b""
        )
        return (bytes(self.head) + marker + b"".join(self.tail)).decode(errors="replace")


def _process_tree_rss_bytes(roots: list[int]) -> int:
    """Sum resident memory once per process, including children of all threads.

    This is a best-effort watchdog, not a cgroup limit. Shared pages may be
    counted more than once, and short-lived processes can race the sample.
    """
    pending = list(roots)
    seen: set[int] = set()
    pages = 0
    while pending:
        pid = pending.pop()
        if pid in seen:
            continue
        seen.add(pid)
        try:
            fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
            pages += int(fields[21])
            for thread in Path(f"/proc/{pid}/task").iterdir():
                try:
                    pending.extend(
                        int(child)
                        for child in (thread / "children").read_text().split()
                    )
                except OSError:
                    pass
        except (OSError, IndexError, ValueError):
            continue
    return pages * os.sysconf("SC_PAGE_SIZE")


async def _communicate_bounded(
    proc: asyncio.subprocess.Process,
    output: _BoundedOutput,
    stdin_data: bytes | None = None,
    memory_limit_bytes: int = 0,
    memory_root_pid: int | None = None,
) -> None:
    async def feed_stdin() -> None:
        if stdin_data is not None and proc.stdin is not None:
            try:
                proc.stdin.write(stdin_data)
                await proc.stdin.drain()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                proc.stdin.close()

    writer = asyncio.create_task(feed_stdin())
    next_sample = 0.0
    try:
        assert proc.stdout is not None
        while True:
            if memory_limit_bytes and time.monotonic() >= next_sample:
                roots = [proc.pid] + ([memory_root_pid] if memory_root_pid else [])
                resident = _process_tree_rss_bytes(roots)
                if resident > memory_limit_bytes:
                    raise _ProcessMemoryLimitExceeded(
                        f"Sandbox memory limit exceeded: RSS {resident} bytes "
                        f"> {memory_limit_bytes} bytes"
                    )
                next_sample = time.monotonic() + 1
            try:
                chunk = await asyncio.wait_for(
                    proc.stdout.read(65536),
                    timeout=0.5 if memory_limit_bytes else None,
                )
            except asyncio.TimeoutError:
                continue
            if not chunk:
                if memory_limit_bytes and proc.returncode is None:
                    # A command can close stdout while it keeps allocating.
                    await asyncio.sleep(0.5)
                    continue
                break
            output.append(chunk)
        await writer
        await proc.wait()
    finally:
        if not writer.done():
            writer.cancel()
            try:
                await writer
            except asyncio.CancelledError:
                pass


async def _run_process(
    args: list[str],
    *,
    timeout: float | None = None,
    env: dict[str, str] | None = None,
    stdin_data: bytes | None = None,
    memory_limit_bytes: int = 0,
    memory_root_pid: int | None = None,
    on_process_started: Callable[[asyncio.subprocess.Process], None] | None = None,
) -> LocalRunResult:
    """Run a host command and terminate its process group if interrupted.

    ``stdin_data`` is passed through a pipe instead of being embedded in
    ``args``. This matters for source files and patches, which can readily
    exceed the host's argv size limit. ``on_process_started`` synchronously
    exposes the owned process to an external resource monitor. It runs before
    communication; callback failure uses the same kill-and-reap cleanup.
    """
    output_buffer = _BoundedOutput(
        int(os.getenv("SWE_HOST_PROCESS_OUTPUT_MAX_BYTES", str(16 * 1024**2)))
    )
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdin=asyncio.subprocess.PIPE if stdin_data is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env=env,
        start_new_session=True,
    )
    try:
        if on_process_started is not None:
            on_process_started(proc)
        await asyncio.wait_for(
            _communicate_bounded(
                proc, output_buffer, stdin_data, memory_limit_bytes, memory_root_pid
            ),
            timeout=timeout,
        )
        return LocalRunResult(
            output=output_buffer.text(),
            return_code=proc.returncode or 0,
        )
    except BaseException as error:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        communicate_task = asyncio.create_task(_communicate_bounded(proc, output_buffer))
        # Reap/drain with an absolute bound. A descendant can escape the
        # process group while retaining stdout; in that case communicate()
        # never sees EOF even though the direct child was killed.
        reap_timeout = max(
            0.1,
            float(os.getenv("SWE_HOST_PROCESS_REAP_TIMEOUT_SECONDS", "10")),
        )
        deadline = time.monotonic() + reap_timeout
        cancellation_during_reap = False
        while not communicate_task.done() and time.monotonic() < deadline:
            remaining = max(0.0, deadline - time.monotonic())
            try:
                await asyncio.wait_for(
                    asyncio.shield(communicate_task),
                    timeout=remaining,
                )
            except asyncio.TimeoutError:
                break
            except asyncio.CancelledError:
                if communicate_task.done():
                    break
                cancellation_during_reap = True

        reap_incomplete = not communicate_task.done()
        if reap_incomplete:
            communicate_task.cancel()
            # Closing our pipe endpoints releases communicate even when an
            # escaped descendant inherited the other end.
            transport = getattr(proc, "_transport", None)
            if transport is not None:
                for descriptor in (0, 1, 2):
                    pipe_transport = transport.get_pipe_transport(descriptor)
                    if pipe_transport is not None:
                        pipe_transport.close()
            try:
                await asyncio.wait_for(
                    asyncio.shield(communicate_task),
                    timeout=1,
                )
            except (asyncio.TimeoutError, asyncio.CancelledError):
                pass

        if communicate_task.done() and not communicate_task.cancelled():
            communicate_task.result()

        # Waiting for the direct child does not depend on pipe EOF, but keep
        # this bounded too so cancellation cleanup has a deterministic limit.
        if proc.returncode is None:
            wait_task = asyncio.create_task(proc.wait())
            wait_deadline = time.monotonic() + 1
            while not wait_task.done() and time.monotonic() < wait_deadline:
                try:
                    await asyncio.wait_for(
                        asyncio.shield(wait_task),
                        timeout=max(0.0, wait_deadline - time.monotonic()),
                    )
                except asyncio.TimeoutError:
                    break
                except asyncio.CancelledError:
                    cancellation_during_reap = True
            if not wait_task.done():
                wait_task.cancel()

        if isinstance(error, asyncio.CancelledError) or cancellation_during_reap:
            raise asyncio.CancelledError()

        if not isinstance(error, (asyncio.TimeoutError, _ProcessMemoryLimitExceeded)):
            raise

        output = output_buffer.text()
        if output and not output.endswith("\n"):
            output += "\n"
        memory_exceeded = isinstance(error, _ProcessMemoryLimitExceeded)
        output += (
            str(error) if memory_exceeded
            else f"Command timed out after {timeout:g} seconds"
        )
        if reap_incomplete:
            output += "; output pipe did not close after process-group kill"
        return LocalRunResult(output=output, return_code=137 if memory_exceeded else 124)


def _process_state_and_start_time(pid: int) -> tuple[str, str] | None:
    """Return a process state and stable identity from Linux procfs."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None
    command_end = stat.rfind(")")
    if command_end < 0:
        return None
    fields = stat[command_end + 2 :].split()
    if len(fields) <= 19:
        return None
    return fields[0], fields[19]


def _process_identity_matches(pid: int, start_time: str) -> bool:
    """Return whether ``pid`` still names the same process, including zombies."""
    identity = _process_state_and_start_time(pid)
    return identity is not None and identity[1] == start_time


def _instance_process_start_time(pid: int, name: str) -> str | None:
    """Return a stable identity only for our exact live instance process."""
    if pid <= 0:
        return None
    try:
        process_stat = Path(f"/proc/{pid}").stat()
        command = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ")
    except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
        return None
    if process_stat.st_uid != os.getuid():
        return None
    decoded = command.decode(errors="replace")
    if name not in decoded or "Singularity instance:" not in decoded:
        return None
    identity = _process_state_and_start_time(pid)
    if identity is None or identity[0] == "Z":
        return None
    return identity[1]


def _owned_process_start_time(pid: int) -> str | None:
    """Return a stable identity for a live process owned by this uid."""
    if pid <= 0:
        return None
    try:
        process_stat = Path(f"/proc/{pid}").stat()
    except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
        return None
    if process_stat.st_uid != os.getuid():
        return None
    identity = _process_state_and_start_time(pid)
    if identity is None or identity[0] == "Z":
        return None
    return identity[1]


def _process_state_parent_and_start_time(pid: int) -> tuple[str, int, str] | None:
    """Return state, parent PID, and stable identity in one procfs read."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return None
    command_end = stat.rfind(")")
    if command_end < 0:
        return None
    fields = stat[command_end + 2 :].split()
    if len(fields) <= 19:
        return None
    try:
        return fields[0], int(fields[1]), fields[19]
    except ValueError:
        return None


def _process_pid_namespace_id(pid: int) -> int | None:
    try:
        lines = Path(f"/proc/{pid}/status").read_text().splitlines()
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None
    for line in lines:
        if line.startswith("NSpid:"):
            values = line.split()[1:]
            if values:
                return int(values[-1])
    return None


def _process_namespace_links(pid: int) -> tuple[str, str, str] | None:
    try:
        return tuple(
            os.readlink(f"/proc/{pid}/ns/{namespace}")
            for namespace in ("user", "mnt", "pid")
        )
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None


def _direct_child_pids(pid: int) -> list[int]:
    try:
        children = Path(f"/proc/{pid}/task/{pid}/children").read_text()
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return []
    return [int(child) for child in children.split()]


class DockerSandbox:
    """A persistent writable task container managed by a local Docker daemon."""

    def __init__(self, image: str) -> None:
        self.image = local_image_reference(image)
        self.name = f"swe-rebench-{uuid4().hex[:16]}"
        self.default_timeout = float(
            os.getenv("SWE_SANDBOX_COMMAND_TIMEOUT_SECONDS", "600")
        )
        self.started = False

    async def start(self) -> None:
        if shutil.which("docker") is None:
            raise RuntimeError("SWE_SANDBOX_RUNTIME=docker requires the docker CLI")

        create_args = [
            "docker",
            "create",
            "--name",
            self.name,
            "--network",
            os.getenv("SWE_DOCKER_NETWORK", "none"),
        ]
        if cpus := os.getenv("SWE_DOCKER_CPUS"):
            create_args += ["--cpus", cpus]
        if memory := os.getenv("SWE_DOCKER_MEMORY"):
            create_args += ["--memory", memory]
        create_args += [
            "--entrypoint",
            "/bin/sh",
            self.image,
            "-c",
            "trap 'exit 0' TERM INT; while :; do sleep 3600; done",
        ]

        result = await _run_process(
            create_args,
            timeout=float(os.getenv("SWE_SANDBOX_CREATE_TIMEOUT_SECONDS", "1800")),
        )
        if result.return_code != 0:
            raise RuntimeError(
                f"docker create failed for {self.image}: {result.output.strip()}"
            )

        result = await _run_process(["docker", "start", self.name], timeout=60)
        if result.return_code != 0:
            await self.stop()
            raise RuntimeError(
                f"docker start failed for {self.image}: {result.output.strip()}"
            )
        self.started = True

    async def run(
        self,
        command: str,
        timeout: float | None = None,
        stdin_data: bytes | None = None,
    ) -> LocalRunResult:
        if not self.started:
            raise RuntimeError("Docker sandbox has not been started")
        exec_args = ["docker", "exec"]
        if stdin_data is not None:
            exec_args.append("-i")
        exec_args += [self.name, "/bin/sh", "-c", command]
        result = await _run_process(
            exec_args,
            timeout=self.default_timeout if timeout is None else timeout,
            stdin_data=stdin_data,
        )
        if result.return_code == 124:
            # Killing docker exec does not reliably kill its process in the
            # container. Restart the container to terminate the command while
            # preserving the writable filesystem.
            await _run_process(["docker", "kill", self.name], timeout=60)
            restart = await _run_process(["docker", "start", self.name], timeout=60)
            if restart.return_code != 0:
                self.started = False
                result.output += (
                    "\nSandbox restart after timeout failed: " + restart.output.strip()
                )
        return result

    async def stop(self) -> None:
        await _run_process(["docker", "rm", "-f", self.name], timeout=60)
        self.started = False


_DOCKER_HUB_REGISTRIES = frozenset(
    {"docker.io", "index.docker.io", "registry-1.docker.io"}
)
_PRIME_SWE_IMAGE_PREFIX = "prime/primeintellect/"


def local_image_reference(image: str) -> str:
    """Translate Prime sandbox image IDs back to their public OCI source.

    PrimeIntellect's verified SWE-rebench subset preserves upstream task data
    but rewrites ``docker.io/swerebenchv2/...`` image names for Prime's sandbox
    registry. Docker and Enroot need the original OCI reference. Reversing that
    documented prefix rewrite also preserves compatibility with existing SQSH
    cache keys.
    """
    if image.startswith(_PRIME_SWE_IMAGE_PREFIX):
        return (
            "docker.io/swerebenchv2/"
            + image.removeprefix(_PRIME_SWE_IMAGE_PREFIX)
        )
    return image


def _enroot_import_uri(image: str) -> str:
    image = local_image_reference(image)
    if image.startswith(("dockerd://", "podman://")):
        return image
    if image.startswith("docker://"):
        target = image.removeprefix("docker://")
        for registry in _DOCKER_HUB_REGISTRIES:
            for delimiter in ("#", "/"):
                prefix = f"{registry}{delimiter}"
                if target.startswith(prefix):
                    return f"docker://{target.removeprefix(prefix)}"
        return image

    image = image.removeprefix("https://").removeprefix("http://")
    first, separator, rest = image.partition("/")
    # Enroot 3.5 expects Docker Hub's native shorthand. Treating docker.io as
    # a custom registry (docker://docker.io#...) can fail to parse multi-arch
    # manifests even though docker://namespace/image succeeds.
    if separator and first in _DOCKER_HUB_REGISTRIES:
        return f"docker://{rest}"
    if separator and ("." in first or ":" in first or first == "localhost"):
        return f"docker://{first}#{rest}"
    return f"docker://{image}"


def _singularity_pull_uri(image: str) -> str:
    """Return an OCI URI accepted by both Singularity CE and Apptainer."""
    image = local_image_reference(image)
    if image.startswith(("dockerd://", "podman://")):
        image = "docker://" + image.split("://", 1)[1]
    if image.startswith("docker://"):
        # ``registry#path`` is Enroot syntax. Accept it here as a convenience
        # because older cluster-local task manifests sometimes contain it.
        scheme, target = image.split("://", 1)
        return f"{scheme}://{target.replace('#', '/', 1)}"
    if image.startswith(
        ("library://", "oras://", "shub://", "http://", "https://")
    ):
        return image
    return f"docker://{image}"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _enroot_import_environment() -> dict[str, str]:
    """Return an import environment safe for read-only layer directories.

    Enroot 3.5 extracts each OCI layer with GNU tar. Some task images contain
    interleaved archive members which revisit a directory after its read-only
    mode has already been restored. Delaying all directory metadata restoration
    until the end of extraction prevents those later members from failing with
    ``Permission denied``.
    """
    env = dict(os.environ)
    tar_options = env.get("TAR_OPTIONS", "").split()
    if "--delay-directory-restore" not in tar_options:
        tar_options.append("--delay-directory-restore")
    env["TAR_OPTIONS"] = " ".join(tar_options)
    return env


class EnrootSandbox:
    """A persistent writable task sandbox backed by host Enroot."""

    def __init__(self, image: str) -> None:
        self.image = local_image_reference(image)
        self.name = f"swe-rebench-{uuid4().hex[:16]}"
        cache_default = (
            Path(os.getenv("XDG_CACHE_HOME", Path.home() / ".cache"))
            / "swe-rebench-v2"
            / "enroot-images"
        )
        self.image_cache = Path(
            os.getenv("SWE_ENROOT_IMAGE_CACHE", str(cache_default))
        ).expanduser()
        self.default_timeout = float(
            os.getenv("SWE_SANDBOX_COMMAND_TIMEOUT_SECONDS", "600")
        )
        self.root_remap = _env_bool("SWE_ENROOT_ROOT_REMAP", True)
        self.session_tmp_dir: Path | None = None
        self.namespace_control_dir: Path | None = None
        self.started = False
        self._pid_namespace_process: asyncio.subprocess.Process | None = None
        self._pid_namespace_anchor_pid: int | None = None
        self._pid_namespace_anchor_start_time: str | None = None
        self._pid_namespace_links: tuple[str, str, str] | None = None
        self._unshare_path: str | None = None
        self._nsenter_path: str | None = None
        self._stopping = False
        self._container_created = False
        self._stop_task: asyncio.Task[None] | None = None

    def _cached_image_path(self) -> Path:
        digest = hashlib.sha256(self.image.encode()).hexdigest()
        return self.image_cache / f"{digest}.sqsh"

    def _ensure_image_sync(self) -> Path:
        self.image_cache.mkdir(parents=True, exist_ok=True)
        image_path = self._cached_image_path()
        lock_path = image_path.with_suffix(".lock")

        with lock_path.open("a+") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            if image_path.exists() and image_path.stat().st_size > 0:
                return image_path

            with tempfile.NamedTemporaryFile(
                prefix=image_path.stem + ".",
                suffix=".sqsh",
                dir=self.image_cache,
                delete=False,
            ) as tmp:
                tmp_path = Path(tmp.name)
            tmp_path.unlink(missing_ok=True)

            try:
                attempts = max(
                    1, int(os.getenv("SWE_ENROOT_IMPORT_ATTEMPTS", "3"))
                )
                retry_delay = max(
                    0.0,
                    float(
                        os.getenv(
                            "SWE_ENROOT_IMPORT_RETRY_DELAY_SECONDS",
                            "2",
                        )
                    ),
                )
                timeout = float(
                    os.getenv(
                        "SWE_ENROOT_IMPORT_TIMEOUT_SECONDS",
                        os.getenv(
                            "SWE_SANDBOX_CREATE_TIMEOUT_SECONDS",
                            "1800",
                        ),
                    )
                )
                errors: list[str] = []
                for attempt in range(1, attempts + 1):
                    tmp_path.unlink(missing_ok=True)
                    try:
                        result = subprocess.run(
                            [
                                "enroot",
                                "import",
                                "--output",
                                str(tmp_path),
                                _enroot_import_uri(self.image),
                            ],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            text=True,
                            timeout=timeout,
                            check=False,
                            env=_enroot_import_environment(),
                        )
                    except subprocess.TimeoutExpired as error:
                        errors.append(
                            f"attempt {attempt}/{attempts} timed out after "
                            f"{timeout:g}s: {error.stdout or ''}".strip()
                        )
                    else:
                        if (
                            result.returncode == 0
                            and tmp_path.exists()
                            and tmp_path.stat().st_size > 0
                        ):
                            os.replace(tmp_path, image_path)
                            return image_path
                        detail = result.stdout.strip()
                        if result.returncode == 0:
                            detail = (
                                detail + "\n" if detail else ""
                            ) + "enroot import produced no image data"
                        errors.append(
                            f"attempt {attempt}/{attempts} exited "
                            f"{result.returncode}: {detail}"
                        )

                    if attempt < attempts and retry_delay:
                        time.sleep(retry_delay)

                raise RuntimeError(
                    f"enroot import failed for {self.image} after "
                    f"{attempts} attempt(s):\n" + "\n".join(errors)
                )
            finally:
                tmp_path.unlink(missing_ok=True)

    def _namespace_anchor_identity(self) -> tuple[str, str] | None:
        anchor_pid = self._pid_namespace_anchor_pid
        expected_start_time = self._pid_namespace_anchor_start_time
        if anchor_pid is None or expected_start_time is None:
            return None
        process_identity = _process_state_and_start_time(anchor_pid)
        if process_identity is None or process_identity[1] != expected_start_time:
            return None
        return process_identity

    def _namespace_anchor_identity_matches(self) -> bool:
        # A zombie still occupies a PID and must remain visible to teardown.
        # Treating it as gone lets an outer PID-namespace init accumulate one
        # unreaped process per sandbox session.
        return self._namespace_anchor_identity() is not None

    def _require_pid_namespace_anchor(self) -> None:
        process = self._pid_namespace_process
        anchor_pid = self._pid_namespace_anchor_pid
        anchor_identity = self._namespace_anchor_identity()
        if self._stopping:
            raise RuntimeError(
                "Enroot sandbox is stopping; refusing to start a command"
            )
        if (
            process is None
            or process.returncode is not None
            or anchor_pid is None
            or anchor_identity is None
            or anchor_identity[0] == "Z"
            or anchor_pid not in _direct_child_pids(process.pid)
            or _process_pid_namespace_id(anchor_pid) != 1
            or _process_namespace_links(anchor_pid) != self._pid_namespace_links
        ):
            raise RuntimeError(
                "Enroot sandbox PID namespace anchor is not alive; refusing "
                "to execute a task command"
            )
        if self._nsenter_path is None or not os.access(self._nsenter_path, os.X_OK):
            raise RuntimeError(
                "Enroot sandbox requires an executable nsenter; refusing "
                "to execute a task command"
            )

    def _namespace_enter_args(self, command: list[str]) -> list[str]:
        self._require_pid_namespace_anchor()
        assert self._nsenter_path is not None
        assert self._pid_namespace_anchor_pid is not None
        return [
            self._nsenter_path,
            "--target",
            str(self._pid_namespace_anchor_pid),
            "--user",
            "--preserve-credentials",
            "--mount",
            "--pid",
            "--",
            *command,
        ]

    def _namespace_command_args(self, command: list[str]) -> tuple[list[str], Path]:
        if self.namespace_control_dir is None:
            raise RuntimeError("Enroot sandbox namespace control dir is missing")
        marker_path = self.namespace_control_dir / f"entered-{uuid4().hex}"
        return (
            self._namespace_enter_args(
                [
                    sys.executable,
                    "-c",
                    _PID_NAMESPACE_COMMAND_GATE,
                    str(marker_path),
                    *command,
                ]
            ),
            marker_path,
        )

    def _namespace_launch_args(
        self,
        launcher_path: Path,
        reaper_path: Path,
        ready_path: Path,
    ) -> list[str]:
        if self._unshare_path is None:
            raise RuntimeError("Enroot sandbox requires the unshare CLI")
        return [
            sys.executable,
            str(launcher_path),
            str(os.getpid()),
            self._unshare_path,
            "--user",
            "--map-current-user",
            "--pid",
            "--fork",
            "--kill-child=SIGKILL",
            "--mount-proc",
            "--",
            sys.executable,
            str(reaper_path),
            str(ready_path),
        ]

    async def _wait_for_pid_namespace_anchor(
        self,
        ready_path: Path,
        timeout: float,
    ) -> int:
        process = self._pid_namespace_process
        assert process is not None
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            if process.returncode is not None:
                try:
                    stdout, _ = await asyncio.wait_for(process.communicate(), timeout=1)
                    detail = stdout.decode(errors="replace").strip()
                except asyncio.TimeoutError:
                    detail = ""
                suffix = f": {detail}" if detail else ""
                raise RuntimeError(
                    "Failed to create Enroot sandbox PID namespace" + suffix
                )

            candidates = [
                child_pid
                for child_pid in _direct_child_pids(process.pid)
                if _process_pid_namespace_id(child_pid) == 1
                and ((identity := _process_state_and_start_time(child_pid)) is not None)
                and identity[0] != "Z"
            ]
            if ready_path.exists() and len(candidates) == 1:
                return candidates[0]
            await asyncio.sleep(0.05)

        raise RuntimeError(
            f"Timed out after {timeout:g} seconds while creating Enroot "
            "sandbox PID namespace"
        )

    async def _start_pid_namespace(self) -> None:
        if self.namespace_control_dir is None:
            raise RuntimeError("Enroot sandbox namespace control dir is missing")
        if self._pid_namespace_process is not None:
            raise RuntimeError("Enroot sandbox PID namespace has already been started")

        self._unshare_path = shutil.which("unshare")
        self._nsenter_path = shutil.which("nsenter")
        missing = [
            name
            for name, path in (
                ("unshare", self._unshare_path),
                ("nsenter", self._nsenter_path),
            )
            if path is None
        ]
        if missing:
            raise RuntimeError(
                "SWE_SANDBOX_RUNTIME=enroot requires the host "
                + " and ".join(missing)
                + " CLI"
            )
        assert self._unshare_path is not None

        launcher_path = self.namespace_control_dir / "launcher.py"
        reaper_path = self.namespace_control_dir / "reaper.py"
        ready_path = self.namespace_control_dir / "ready"
        launcher_path.write_text(_PID_NAMESPACE_LAUNCHER)
        reaper_path.write_text(_PID_NAMESPACE_REAPER)
        launcher_path.chmod(0o600)
        reaper_path.chmod(0o600)

        spawn_task = asyncio.create_task(
            asyncio.create_subprocess_exec(
                *self._namespace_launch_args(launcher_path, reaper_path, ready_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                start_new_session=True,
            )
        )
        cancelled_during_spawn = False
        while not spawn_task.done():
            try:
                await asyncio.shield(spawn_task)
            except asyncio.CancelledError:
                # asyncio may already have forked before create_subprocess_exec
                # returns its handle. Let the spawn finish so ordered teardown
                # can kill the namespace init before its unshare owner.
                cancelled_during_spawn = True
        self._pid_namespace_process = spawn_task.result()
        if cancelled_during_spawn:
            raise asyncio.CancelledError()

        startup_timeout = float(
            os.getenv("SWE_ENROOT_NAMESPACE_START_TIMEOUT_SECONDS", "15")
        )
        anchor_pid = await self._wait_for_pid_namespace_anchor(
            ready_path, startup_timeout
        )
        process_identity = _process_state_and_start_time(anchor_pid)
        namespace_links = _process_namespace_links(anchor_pid)
        host_namespace_links = _process_namespace_links(os.getpid())
        if process_identity is None or namespace_links is None:
            raise RuntimeError("Could not verify Enroot sandbox PID namespace anchor")
        if host_namespace_links is None or any(
            child == host for child, host in zip(namespace_links, host_namespace_links)
        ):
            raise RuntimeError(
                "Enroot sandbox namespace setup did not create distinct "
                "user, mount, and PID namespaces"
            )

        self._pid_namespace_anchor_pid = anchor_pid
        self._pid_namespace_anchor_start_time = process_identity[1]
        self._pid_namespace_links = namespace_links

        probe = await _run_process(
            self._namespace_enter_args(["/bin/true"]),
            timeout=min(startup_timeout, 5),
        )
        if probe.return_code != 0:
            raise RuntimeError(
                "Could not enter Enroot sandbox PID namespace: " + probe.output.strip()
            )
        self._require_pid_namespace_anchor()

        # The running interpreters no longer need these files. Removing them
        # leaves only per-command entry markers in the private control dir.
        launcher_path.unlink(missing_ok=True)
        reaper_path.unlink(missing_ok=True)
        ready_path.unlink(missing_ok=True)

    def _try_reap_adopted_namespace_init(
        self,
        pid: int,
        start_time: str,
    ) -> bool:
        """Reap the exact recorded init if it is our adopted zombie."""
        details = _process_state_parent_and_start_time(pid)
        if details is None or details[2] != start_time:
            return True
        state, parent_pid, _ = details
        if state != "Z" or parent_pid != os.getpid():
            return False

        # A zombie cannot recycle its PID before waitpid. The single procfs
        # read above proves both the recorded start time and that this server
        # is now its parent, so this cannot consume another asyncio child.
        try:
            waited_pid, _status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return not _process_identity_matches(pid, start_time)
        if waited_pid == pid:
            return True
        return not _process_identity_matches(pid, start_time)

    async def _stop_pid_namespace(self) -> None:
        process = self._pid_namespace_process
        anchor_pid = self._pid_namespace_anchor_pid
        anchor_identity = self._namespace_anchor_identity()
        teardown_identity: tuple[int, str] | None = None
        signal_namespace_init = False
        stop_timeout = float(
            os.getenv("SWE_ENROOT_NAMESPACE_STOP_TIMEOUT_SECONDS", "10")
        )
        stop_deadline = asyncio.get_running_loop().time() + stop_timeout

        if process is not None and process.returncode is None:
            if anchor_pid is not None and anchor_identity is not None:
                if anchor_pid in _direct_child_pids(process.pid):
                    signal_namespace_init = True
                else:
                    # The owner can exit before asyncio publishes returncode.
                    # Never signal a reparented live process; exact-identity
                    # verification below will reap it once waitable.
                    self._try_reap_adopted_namespace_init(
                        anchor_pid, anchor_identity[1]
                    )
                teardown_identity = (anchor_pid, anchor_identity[1])
            elif anchor_pid is None:
                # Startup cancellation can arrive before the ready handshake
                # records the init. Wait for the launcher to fork so teardown
                # can still kill the child first and let unshare reap it.
                while process.returncode is None:
                    children = _direct_child_pids(process.pid)
                    if len(children) > 1:
                        raise RuntimeError(
                            "Enroot sandbox PID namespace owner has an unexpected "
                            f"process tree: {children}"
                        )
                    if children:
                        child_identity = _process_state_and_start_time(children[0])
                        if child_identity is not None:
                            teardown_identity = (children[0], child_identity[1])
                            signal_namespace_init = True
                            break
                    if asyncio.get_running_loop().time() >= stop_deadline:
                        raise RuntimeError(
                            "Timed out while waiting for the Enroot sandbox PID "
                            "namespace owner to create its init during cleanup"
                        )
                    await asyncio.sleep(0.01)

            if teardown_identity is not None and signal_namespace_init:
                teardown_pid, teardown_start_time = teardown_identity
                identity = _process_state_and_start_time(teardown_pid)
                if (
                    identity is not None
                    and identity[1] == teardown_start_time
                    and identity[0] != "Z"
                ):
                    try:
                        os.kill(teardown_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

            # Do not kill the unshare owner first. It is the only process able
            # to wait(2) its PID-namespace init; killing it first reparents a
            # zombie to the production server when that server is outer PID 1.
            try:
                remaining = max(0.0, stop_deadline - asyncio.get_running_loop().time())
                await asyncio.wait_for(process.wait(), timeout=remaining)
            except asyncio.TimeoutError as error:
                raise RuntimeError(
                    "Timed out while waiting for the Enroot sandbox PID "
                    "namespace owner to reap its init"
                ) from error

        if process is not None:
            # Drain its diagnostic pipe after wait() has reaped the owner.
            await process.communicate()

        if anchor_pid is not None and self._pid_namespace_anchor_start_time is not None:
            # The owner can die between the direct-child check and wait(). Its
            # Pdeath-killed init is then an exact zombie adopted by outer PID 1.
            self._try_reap_adopted_namespace_init(
                anchor_pid, self._pid_namespace_anchor_start_time
            )

        identities_to_verify: list[tuple[int, str]] = []
        if teardown_identity is not None:
            identities_to_verify.append(teardown_identity)
        if anchor_pid is not None and self._pid_namespace_anchor_start_time is not None:
            identities_to_verify.append(
                (anchor_pid, self._pid_namespace_anchor_start_time)
            )

        deadline = asyncio.get_running_loop().time() + 5
        while True:
            # Pdeath delivery can lag behind reaping the killed owner. Retry
            # only the exact recorded identities until an adopted child
            # reaches waitable zombie state.
            for pid, start_time in identities_to_verify:
                self._try_reap_adopted_namespace_init(pid, start_time)
            remaining_identities = [
                (pid, start_time)
                for pid, start_time in identities_to_verify
                if _process_identity_matches(pid, start_time)
            ]
            if not remaining_identities:
                break
            if asyncio.get_running_loop().time() >= deadline:
                raise RuntimeError(
                    "Enroot sandbox PID namespace init survived teardown or "
                    "remained as a zombie"
                )
            await asyncio.sleep(0.05)

        self._pid_namespace_process = None
        self._pid_namespace_anchor_pid = None
        self._pid_namespace_anchor_start_time = None
        self._pid_namespace_links = None
        self._unshare_path = None
        self._nsenter_path = None

    def _start_args(self, command: str) -> list[str]:
        if self.session_tmp_dir is None:
            raise RuntimeError("Enroot sandbox session tmp has not been created")
        args = [
            "enroot",
            "start",
            "--rw",
        ]
        if self.root_remap:
            args.append("--root")

        mounts = os.getenv("SWE_ENROOT_MOUNTS", "")
        for mount in mounts.split(";"):
            mount = mount.strip()
            if mount:
                args += ["--mount", mount]

        # Enroot's generated /etc/rc establishes the image WORKDIR before it
        # executes our explicit command. Image ENTRYPOINT logic lives in
        # /etc/rc.local, so replace only that file with an empty session-local
        # file: this preserves WORKDIR semantics without running a stale image
        # entrypoint.
        rc_local_path = self.session_tmp_dir / ".openreward-enroot-rc.local"
        args += ["--mount", f"{rc_local_path}:/etc/rc.local"]
        args += ["--mount", f"{self.session_tmp_dir}:/tmp"]
        # Enroot's standard configuration bind-mounts the host home directory
        # into every container. Parallel SWE sessions would therefore make
        # `git config --global` race on the same /root/.gitconfig.lock. Keep
        # Git's global config in the already session-private /tmp mount and
        # export the override for every command, including later agent tools.
        isolated_command = (
            "export GIT_CONFIG_GLOBAL=/tmp/.gitconfig-openreward; " + command
        )
        args += [self.name, "/bin/sh", "-c", isolated_command]
        return args

    async def start(self) -> None:
        if shutil.which("enroot") is None:
            raise RuntimeError("SWE_SANDBOX_RUNTIME=enroot requires the enroot CLI")
        if self.started or self._container_created:
            raise RuntimeError("Enroot sandbox has already been started")

        try:
            image_path = await asyncio.to_thread(self._ensure_image_sync)
            tmp_root_value = os.getenv("SWE_ENROOT_SESSION_TMP_ROOT")
            tmp_root = Path(tmp_root_value).expanduser() if tmp_root_value else None
            if tmp_root is not None:
                tmp_root.mkdir(parents=True, exist_ok=True)
            self.session_tmp_dir = Path(
                tempfile.mkdtemp(
                    prefix=f"{self.name}-tmp-",
                    dir=tmp_root,
                )
            )
            self.namespace_control_dir = Path(
                tempfile.mkdtemp(
                    prefix=f"{self.name}-pidns-",
                    dir=tmp_root,
                )
            )
            self.namespace_control_dir.chmod(0o700)
            rc_local_path = self.session_tmp_dir / ".openreward-enroot-rc.local"
            rc_local_path.write_text("")
            rc_local_path.chmod(0o600)
            # Mark removal necessary before spawning create: cancellation can
            # arrive after Enroot creates the named rootfs but before the
            # subprocess result reaches this coroutine.
            self._container_created = True
            result = await _run_process(
                ["enroot", "create", "--name", self.name, str(image_path)],
                timeout=float(os.getenv("SWE_SANDBOX_CREATE_TIMEOUT_SECONDS", "1800")),
            )
            if result.return_code != 0:
                raise RuntimeError(
                    f"enroot create failed for {self.image}: {result.output.strip()}"
                )
            await self._start_pid_namespace()
            self.started = True
        except BaseException as start_error:
            try:
                await self.stop()
            except BaseException as cleanup_error:
                raise RuntimeError(
                    "Enroot sandbox startup failed and cleanup did not "
                    f"complete: {cleanup_error}"
                ) from start_error
            raise

    async def run(
        self,
        command: str,
        timeout: float | None = None,
        stdin_data: bytes | None = None,
    ) -> LocalRunResult:
        if not self.started:
            raise RuntimeError("Enroot sandbox has not been started")
        namespace_args, entered_marker = self._namespace_command_args(
            self._start_args(command)
        )
        try:
            try:
                result = await _run_process(
                    namespace_args,
                    timeout=self.default_timeout if timeout is None else timeout,
                    # Some cluster installations enable an Enroot hook that
                    # bind-mounts the caller's home directory by default.
                    # Never let an untrusted task inherit that host path. An
                    # explicit empty value disables the hook even when the
                    # parent environment sets ENROOT_MOUNT_HOME.
                    env={**os.environ, "ENROOT_MOUNT_HOME": ""},
                    stdin_data=stdin_data,
                )
            except (FileNotFoundError, PermissionError, OSError) as error:
                raise RuntimeError(
                    "Could not enter Enroot sandbox PID namespace; refusing "
                    "to execute a task command"
                ) from error

            if not entered_marker.exists():
                detail = result.output.strip()
                suffix = f": {detail}" if detail else ""
                raise RuntimeError(
                    "Could not enter Enroot sandbox PID namespace; refusing "
                    "to treat the command as executed" + suffix
                )
            self._require_pid_namespace_anchor()
            return result
        finally:
            entered_marker.unlink(missing_ok=True)

    async def _cleanup_resources(self) -> None:
        try:
            await self._stop_pid_namespace()
        except Exception as error:
            # The namespace must be gone before touching the writable rootfs.
            # Preserve all ownership state so a subsequent stop() can retry.
            self.started = False
            raise RuntimeError(
                f"Enroot sandbox namespace cleanup failed: {error}"
            ) from error

        if self._container_created:
            try:
                result = await _run_process(
                    ["enroot", "remove", "-f", self.name],
                    timeout=120,
                )
            except Exception as error:
                self.started = False
                raise RuntimeError(
                    f"Enroot sandbox removal failed: {error}"
                ) from error
            if result.return_code != 0:
                self.started = False
                raise RuntimeError(
                    "Enroot sandbox removal failed: " + result.output.strip()
                )

        if self.session_tmp_dir is not None:
            shutil.rmtree(self.session_tmp_dir, ignore_errors=True)
            self.session_tmp_dir = None
        if self.namespace_control_dir is not None:
            shutil.rmtree(self.namespace_control_dir, ignore_errors=True)
            self.namespace_control_dir = None
        self._container_created = False
        self.started = False
        self._stopping = False

    async def stop(self) -> None:
        if self._stop_task is None or self._stop_task.done():
            self._stopping = True
            self._stop_task = asyncio.create_task(self._cleanup_resources())
        stop_task = self._stop_task
        was_cancelled = False
        try:
            while not stop_task.done():
                try:
                    await asyncio.shield(stop_task)
                except asyncio.CancelledError:
                    # Cleanup owns the namespace and Enroot filesystem. Do
                    # not let request cancellation strand either resource.
                    was_cancelled = True

            stop_task.result()
            if was_cancelled:
                raise asyncio.CancelledError()
        finally:
            if stop_task.done() and self._stop_task is stop_task:
                self._stop_task = None


class SingularitySandbox:
    """A persistent task instance with private node-local writable storage.

    Singularity CE and Apptainer intentionally share this implementation: the
    CLI contract used here is common to both. The task image is immutable and
    may live in a shared cache, while all high-churn state is created below the
    node-local session root.
    """

    _RUNTIME_CANDIDATES = ("singularity", "apptainer")
    _SESSION_OWNER_FILE = ".openreward-session-owner.json"
    _SESSION_LOCK_FILE = ".openreward-session.lock"
    _INSTANCE_CONTROL_LOCK_FILE = ".openreward-instance-control.lock"
    _INSTANCE_PID_FILE = "instance.pid"
    _SERVICE_ADAPTER_VERSION = "openreward-swe-service-v1"
    _SERVICE_STARTSCRIPT = "exec /usr/bin/sleep 2147483647"

    def __init__(self, image: str) -> None:
        self.image = local_image_reference(image)
        self.name = f"swe-rebench-{uuid4().hex[:16]}"

        cache_default = (
            Path(os.getenv("XDG_CACHE_HOME", Path.home() / ".cache"))
            / "swe-rebench-v2"
            / "sif-images"
        )
        cache_value = os.getenv("SWE_APPTAINER_IMAGE_CACHE") or os.getenv(
            "SWE_SINGULARITY_IMAGE_CACHE"
        )
        self.image_cache = Path(cache_value or cache_default).expanduser()

        session_value = os.getenv("SWE_APPTAINER_SESSION_ROOT") or os.getenv(
            "SWE_SINGULARITY_SESSION_ROOT"
        )
        if session_value:
            self.session_root = Path(session_value).expanduser()
        else:
            self.session_root = (
                Path(os.getenv("TMPDIR", tempfile.gettempdir()))
                / "swe-rebench-v2"
                / "sessions"
            )

        self.default_timeout = float(
            os.getenv("SWE_SANDBOX_COMMAND_TIMEOUT_SECONDS", "600")
        )
        self.overlay_size_mb = int(
            os.getenv(
                "SWE_APPTAINER_OVERLAY_SIZE_MB",
                os.getenv("SWE_SINGULARITY_OVERLAY_SIZE_MB", "8192"),
            )
        )
        if self.overlay_size_mb <= 0:
            raise ValueError("SWE_APPTAINER_OVERLAY_SIZE_MB must be positive")
        self.sparse_overlay = _env_bool("SWE_APPTAINER_OVERLAY_SPARSE", True)
        self.writable_directory = _env_bool("SWE_SINGULARITY_WRITABLE_DIRECTORY", False)
        # ABCI's Singularity CE / PRO builds force squashfuse for
        # --fakeroot+--overlay, fail its allow_other mount, and silently fall
        # back to a read-only temporary sandbox. Normal setuid mode mounts the
        # same UID-owned overlay read/write, so it is the safe site default.
        self.fakeroot = _env_bool("SWE_APPTAINER_FAKEROOT", False)

        self.runtime_bin: str | None = None
        self.mkfs_bin: str | None = None
        self.raw_image_path: Path | None = None
        self.raw_image_sha256: str | None = None
        self.image_path: Path | None = None
        self.image_sha256: str | None = None
        self.service_adapter_key: str | None = None
        self.session_dir: Path | None = None
        self.session_tmp_dir: Path | None = None
        self.session_var_tmp_dir: Path | None = None
        self.instance_pid_path: Path | None = None
        self.instance_pid: int | None = None
        self.instance_start_time: str | None = None
        self.instance_hostname: str | None = None
        self.overlay_path: Path | None = None
        self.writable_rootfs_path: Path | None = None
        self.container_workdir: str | None = None
        self.started = False
        self._instance_may_exist = False
        self._stopping = False
        self._stop_task: asyncio.Task[None] | None = None
        self._session_lock_file: TextIO | None = None
        # Python 3.9 binds asyncio primitives to the current event loop at
        # construction time. Environments are often constructed before their
        # serving loop starts, so create this lock lazily in async code.
        self._lifecycle_lock: asyncio.Lock | None = None

    def _resolve_runtime_bin(self) -> str:
        if self.runtime_bin is not None:
            return self.runtime_bin

        configured = os.getenv("SWE_CONTAINER_RUNTIME_BIN", "").strip()
        candidates = (configured,) if configured else self._RUNTIME_CANDIDATES
        for candidate in candidates:
            if candidate and (resolved := shutil.which(candidate)) is not None:
                self.runtime_bin = resolved
                return resolved

        if configured:
            raise RuntimeError(
                "SWE_CONTAINER_RUNTIME_BIN points to a missing executable: "
                f"{configured}"
            )
        raise RuntimeError(
            "SWE_SANDBOX_RUNTIME=singularity/apptainer requires either the "
            "singularity or apptainer CLI"
        )

    def _resolve_mkfs_bin(self) -> str:
        if self.mkfs_bin is not None:
            return self.mkfs_bin
        configured = os.getenv("SWE_APPTAINER_MKFS_BIN", "mkfs.ext3").strip()
        if not configured or (resolved := shutil.which(configured)) is None:
            raise RuntimeError(
                "The Singularity sandbox requires mkfs.ext3 to create its "
                "node-local writable overlay; set SWE_APPTAINER_MKFS_BIN if "
                "it is installed outside PATH"
            )
        self.mkfs_bin = resolved
        return resolved

    def _runtime_environment(self) -> dict[str, str]:
        """Return a deterministic runtime environment without implicit binds."""
        runtime_name = Path(self._resolve_runtime_bin()).name
        env = dict(os.environ)

        # Environment-driven bind options would defeat --no-mount bind-paths.
        # In particular, never inherit a launcher bind of the dataset or home.
        for key in (
            "APPTAINER_BIND",
            "APPTAINER_BINDPATH",
            "SINGULARITY_BIND",
            "SINGULARITY_BINDPATH",
        ):
            env.pop(key, None)
        for key in list(env):
            if key.startswith(("APPTAINERENV_", "SINGULARITYENV_")):
                env.pop(key)

        # The migration environment uses APPTAINER_* names, while ABCI ships
        # Singularity CE. Mirror only cache/build scratch settings so either
        # binary honors the same node-local configuration.
        if runtime_name.startswith("singularity"):
            for suffix in ("CACHEDIR", "TMPDIR"):
                source = f"APPTAINER_{suffix}"
                target = f"SINGULARITY_{suffix}"
                if target not in env and source in env:
                    env[target] = env[source]
        elif runtime_name.startswith("apptainer"):
            for suffix in ("CACHEDIR", "TMPDIR"):
                source = f"SINGULARITY_{suffix}"
                target = f"APPTAINER_{suffix}"
                if target not in env and source in env:
                    env[target] = env[source]
        # Singularity CE 4.4.1 stores unprivileged instance metadata below the
        # passwd database home, regardless of SINGULARITY_CONFIGDIR or HOME.
        # Do not set either CONFIGDIR alias: doing so makes `instance list`
        # look in an empty directory even though `instance start` published
        # global metadata. Exact UUID names and PID identities below provide
        # isolation instead.
        env.pop("SINGULARITY_CONFIGDIR", None)
        env.pop("APPTAINER_CONFIGDIR", None)
        return env

    def _instance_environment(self) -> dict[str, str]:
        return self._runtime_environment()

    def _cached_image_path(self) -> Path:
        # The source identifier is expected to be digest-pinned in production.
        # Hashing its canonical URI makes cache names portable and filesystem
        # safe, while allowing both runtime aliases to share the same SIF.
        source = _singularity_pull_uri(self.image)
        digest = hashlib.sha256(source.encode()).hexdigest()
        return self.image_cache / f"{digest}.sif"

    @staticmethod
    def _instance_record_in_list_payload(
        payload: object,
        name: str,
    ) -> dict[str, object] | None:
        if not isinstance(payload, dict):
            return None
        instances = payload.get("instances")
        if not isinstance(instances, list):
            return None
        matches = [
            instance
            for instance in instances
            if isinstance(instance, dict)
            and instance.get("instance", instance.get("name")) == name
        ]
        if len(matches) > 1:
            raise RuntimeError(f"multiple Singularity records matched {name!r}")
        return matches[0] if matches else None

    @classmethod
    def _instance_pid_from_record(cls, record: dict[str, object]) -> int:
        for key in ("pid", "PID", "Pid"):
            if key in record:
                try:
                    pid = int(record[key])
                except (TypeError, ValueError) as error:
                    raise RuntimeError(
                        f"invalid PID in Singularity instance record: {record}"
                    ) from error
                if pid <= 0:
                    break
                return pid
        raise RuntimeError(f"Singularity instance record has no valid PID: {record}")

    def _open_instance_control_lock(self) -> TextIO:
        """Open the per-node/job lock serializing only our instance controls."""
        self.session_root.mkdir(parents=True, exist_ok=True)
        path = self.session_root / self._INSTANCE_CONTROL_LOCK_FILE
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            lock_stat = os.fstat(descriptor)
            if not stat.S_ISREG(lock_stat.st_mode) or lock_stat.st_uid != os.getuid():
                raise RuntimeError(f"refusing foreign instance-control lock: {path}")
            return os.fdopen(descriptor, "a+")
        except BaseException:
            os.close(descriptor)
            raise

    async def _acquire_instance_control_lock(self) -> TextIO:
        lock_file = self._open_instance_control_lock()
        try:
            while True:
                try:
                    fcntl.flock(
                        lock_file.fileno(),
                        fcntl.LOCK_EX | fcntl.LOCK_NB,
                    )
                    return lock_file
                except BlockingIOError:
                    await asyncio.sleep(0.05)
        except BaseException:
            lock_file.close()
            raise

    def _instance_record_sync_unlocked(
        self,
        name: str,
    ) -> dict[str, object] | None:
        try:
            result = subprocess.run(
                [
                    self._resolve_runtime_bin(),
                    "instance",
                    "list",
                    "--json",
                    name,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=30,
                check=False,
                env=self._runtime_environment(),
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RuntimeError(
                f"could not query Singularity instance {name!r}: {error}"
            ) from error
        if result.returncode != 0:
            raise RuntimeError(
                f"could not query Singularity instance {name!r}: "
                f"{result.stdout.strip()}"
            )
        try:
            payload = json.loads(result.stdout or "{}")
        except json.JSONDecodeError as error:
            raise RuntimeError(
                f"invalid Singularity instance JSON for {name!r}: {result.stdout!r}"
            ) from error
        return self._instance_record_in_list_payload(payload, name)

    def _instance_exists_sync(
        self,
        name: str,
    ) -> bool | None:
        """Return None when the runtime cannot prove instance state."""
        try:
            with self._open_instance_control_lock() as control_lock:
                fcntl.flock(control_lock.fileno(), fcntl.LOCK_EX)
                record = self._instance_record_sync_unlocked(name)
            return record is not None
        except RuntimeError:
            return None

    def _write_session_owner_record(self) -> None:
        if self.session_dir is None:
            raise RuntimeError("Singularity sandbox session directory is missing")
        if self.instance_pid_path is None:
            raise RuntimeError("Singularity instance PID file is missing")
        identity = _process_state_and_start_time(os.getpid())
        if identity is None:
            raise RuntimeError("Could not record sandbox server process identity")
        owner_path = self.session_dir / self._SESSION_OWNER_FILE
        temporary = owner_path.with_name(f".{owner_path.name}.{os.getpid()}.tmp")
        temporary.write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "instance_name": self.name,
                    "owner_pid": os.getpid(),
                    "owner_start_time": identity[1],
                    "session_directory": str(self.session_dir),
                    "hostname": self.instance_hostname or socket.gethostname(),
                    "instance_pid_file": str(self.instance_pid_path),
                    "instance_pid": self.instance_pid,
                    "instance_start_time": self.instance_start_time,
                    "raw_image_path": (
                        str(self.raw_image_path) if self.raw_image_path else None
                    ),
                    "raw_image_sha256": self.raw_image_sha256,
                    "adapted_image_path": (
                        str(self.image_path) if self.image_path else None
                    ),
                    "adapted_image_sha256": self.image_sha256,
                    "service_adapter_key": self.service_adapter_key,
                    "service_adapter_version": self._SERVICE_ADAPTER_VERSION,
                },
                sort_keys=True,
            )
            + "\n"
        )
        temporary.chmod(0o600)
        os.replace(temporary, owner_path)

    @classmethod
    def _session_instance_name(cls, session_dir: Path) -> str | None:
        prefix = "swe-rebench-"
        suffix = session_dir.name.removeprefix(prefix)
        if len(suffix) < 18 or suffix[16] != "-":
            return None
        identifier = suffix[:16]
        if any(character not in "0123456789abcdef" for character in identifier):
            return None
        return prefix + identifier

    @classmethod
    def _open_session_lock(cls, session_dir: Path) -> TextIO:
        lock_path = session_dir / cls._SESSION_LOCK_FILE
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(lock_path, flags, 0o600)
        os.chmod(lock_path, 0o600)
        return os.fdopen(descriptor, "a+")

    def _create_leased_session_dir(self) -> tuple[Path, TextIO]:
        """Publish a session directory and its live-owner lease atomically.

        The same janitor lock guards discovery. If this process crashes before
        obtaining the per-session lease, a later janitor may safely recover
        the newly visible directory as soon as the global lock is released.
        """

        self.session_root.mkdir(parents=True, exist_ok=True)
        janitor_lock_path = self.session_root / ".openreward-session-janitor.lock"
        with janitor_lock_path.open("a+") as janitor_lock:
            fcntl.flock(janitor_lock.fileno(), fcntl.LOCK_EX)
            session_dir = Path(
                tempfile.mkdtemp(prefix=f"{self.name}-", dir=self.session_root)
            )
            session_dir.chmod(0o700)
            session_lock: TextIO | None = None
            try:
                session_lock = self._open_session_lock(session_dir)
                fcntl.flock(session_lock.fileno(), fcntl.LOCK_EX)
            except BaseException:
                if session_lock is not None:
                    session_lock.close()
                shutil.rmtree(session_dir, ignore_errors=True)
                raise
            assert session_lock is not None
        return session_dir, session_lock

    @staticmethod
    def _read_instance_pid_file(path: Path) -> int | None:
        try:
            file_stat = os.stat(path, follow_symlinks=False)
            if (
                not stat.S_ISREG(file_stat.st_mode)
                or file_stat.st_uid != os.getuid()
                or stat.S_IMODE(file_stat.st_mode) & 0o022
            ):
                raise RuntimeError(f"refusing unsafe instance PID file: {path}")
            pid = int(path.read_text().strip())
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as error:
            raise RuntimeError(f"invalid instance PID file {path}: {error}") from error
        if pid <= 0:
            raise RuntimeError(f"invalid instance PID {pid} in {path}")
        return pid

    def _matching_instance_start_time(self, pid: int) -> str | None:
        return _owned_process_start_time(pid)

    @staticmethod
    def _terminate_exact_instance_process(
        pid: int,
        name: str,
        start_time: str,
        grace_seconds: float,
    ) -> None:
        if _instance_process_start_time(pid, name) != start_time:
            raise RuntimeError(
                f"refusing to signal instance {name!r}: PID identity changed"
            )
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + max(0.0, grace_seconds)
        while _process_identity_matches(pid, start_time) and time.monotonic() < deadline:
            time.sleep(0.05)
        if _process_identity_matches(pid, start_time):
            if _instance_process_start_time(pid, name) != start_time:
                raise RuntimeError(
                    f"refusing to kill instance {name!r}: PID identity changed"
                )
            os.kill(pid, signal.SIGKILL)
            deadline = time.monotonic() + 5
            while _process_identity_matches(pid, start_time) and time.monotonic() < deadline:
                time.sleep(0.05)
        if _process_identity_matches(pid, start_time):
            raise RuntimeError(f"exact instance process {name!r} survived SIGKILL")

    def _cleanup_stale_sessions_sync(self) -> None:
        """Stop exact orphaned instances left by a crashed server process.

        A global lock serializes janitors. A per-session lease closes the
        crash window before the owner JSON is published and lets malformed
        records be recovered without touching any session still owned by a
        live server.
        """
        self.session_root.mkdir(parents=True, exist_ok=True)
        lock_path = self.session_root / ".openreward-session-janitor.lock"
        errors: list[str] = []
        with lock_path.open("a+") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            for session_dir in self.session_root.glob("swe-rebench-*"):
                if not session_dir.is_dir() or session_dir.is_symlink():
                    continue
                try:
                    session_stat = session_dir.stat()
                except OSError as error:
                    errors.append(f"could not stat stale session {session_dir}: {error}")
                    continue
                if (
                    session_stat.st_uid != os.getuid()
                    or stat.S_IMODE(session_stat.st_mode) & 0o077
                ):
                    errors.append(
                        f"refusing foreign or non-private stale session {session_dir}"
                    )
                    continue
                name = self._session_instance_name(session_dir)
                if name is None:
                    continue
                try:
                    session_lock = self._open_session_lock(session_dir)
                except OSError as error:
                    errors.append(f"could not open stale-session lease {session_dir}: {error}")
                    continue
                try:
                    try:
                        fcntl.flock(
                            session_lock.fileno(),
                            fcntl.LOCK_EX | fcntl.LOCK_NB,
                        )
                    except BlockingIOError:
                        continue

                    owner_path = session_dir / self._SESSION_OWNER_FILE
                    try:
                        record = json.loads(owner_path.read_text())
                    except (FileNotFoundError, OSError, json.JSONDecodeError):
                        record = None

                    # A live owner identity is advisory protection in addition
                    # to the mandatory session lease.
                    try:
                        owner_pid = int(record["owner_pid"])
                        owner_start_time = str(record["owner_start_time"])
                    except (KeyError, TypeError, ValueError):
                        owner_pid = -1
                        owner_start_time = ""
                    if owner_pid > 0 and _process_identity_matches(
                        owner_pid,
                        owner_start_time,
                    ):
                        continue

                    pid_path = session_dir / self._INSTANCE_PID_FILE
                    record_is_bound_to_session = (
                        isinstance(record, dict)
                        and record.get("schema_version") == 2
                        and record.get("instance_name") == name
                        and record.get("session_directory") == str(session_dir)
                        and record.get("hostname") == socket.gethostname()
                        and record.get("instance_pid_file") == str(pid_path)
                    )
                    pid_from_file = self._read_instance_pid_file(pid_path)
                    try:
                        with self._open_instance_control_lock() as control_lock:
                            fcntl.flock(control_lock.fileno(), fcntl.LOCK_EX)
                            instance_record = self._instance_record_sync_unlocked(name)
                            if instance_record is not None:
                                if not record_is_bound_to_session:
                                    raise RuntimeError(
                                        f"instance {name!r} exists but its owner record "
                                        "is not bound to this session"
                                    )
                                assert isinstance(record, dict)
                                runtime_pid = self._instance_pid_from_record(
                                    instance_record
                                )
                                try:
                                    recorded_pid = int(record["instance_pid"])
                                    instance_start_time = str(
                                        record["instance_start_time"]
                                    )
                                except (KeyError, TypeError, ValueError) as error:
                                    raise RuntimeError(
                                        f"instance {name!r} has incomplete PID identity"
                                    ) from error
                                if (
                                    runtime_pid != recorded_pid
                                    or pid_from_file != recorded_pid
                                    or _owned_process_start_time(runtime_pid)
                                    != instance_start_time
                                ):
                                    raise RuntimeError(
                                        f"instance {name!r} PID identity is ambiguous"
                                    )
                                stop = subprocess.run(
                                    [
                                        self._resolve_runtime_bin(),
                                        "instance",
                                        "stop",
                                        "--timeout",
                                        os.getenv(
                                            "SWE_APPTAINER_INSTANCE_STOP_GRACE_SECONDS",
                                            "10",
                                        ),
                                        name,
                                    ],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT,
                                    text=True,
                                    timeout=float(
                                        os.getenv(
                                            "SWE_APPTAINER_INSTANCE_STOP_TIMEOUT_SECONDS",
                                            "60",
                                        )
                                    ),
                                    check=False,
                                    env=self._runtime_environment(),
                                )
                                remaining = self._instance_record_sync_unlocked(name)
                                if remaining is not None:
                                    raise RuntimeError(
                                        f"stale instance {name!r} survived stop: "
                                        f"{stop.stdout.strip()}"
                                    )
                                if _process_identity_matches(
                                    runtime_pid,
                                    instance_start_time,
                                ):
                                    self._terminate_exact_instance_process(
                                        runtime_pid,
                                        name,
                                        instance_start_time,
                                        2,
                                    )
                            elif record_is_bound_to_session:
                                assert isinstance(record, dict)
                                try:
                                    recorded_pid = int(record["instance_pid"])
                                    instance_start_time = str(
                                        record["instance_start_time"]
                                    )
                                except (KeyError, TypeError, ValueError):
                                    recorded_pid = -1
                                    instance_start_time = ""
                                if recorded_pid > 0 and _process_identity_matches(
                                    recorded_pid,
                                    instance_start_time,
                                ):
                                    if pid_from_file != recorded_pid:
                                        raise RuntimeError(
                                            f"instance {name!r} PID file does not match"
                                        )
                                    self._terminate_exact_instance_process(
                                        recorded_pid,
                                        name,
                                        instance_start_time,
                                        2,
                                    )
                            elif pid_from_file is not None and _instance_process_start_time(
                                pid_from_file,
                                name,
                            ) is not None:
                                raise RuntimeError(
                                    f"unowned live instance process remains for {name!r}"
                                )
                    except (OSError, subprocess.TimeoutExpired, RuntimeError) as error:
                        errors.append(f"could not clean stale instance {name}: {error}")
                        continue
                    try:
                        remove_session_tree(session_dir)
                    except OSError as error:
                        errors.append(
                            f"could not remove stale session {session_dir}: {error}"
                        )
                finally:
                    session_lock.close()
        if errors:
            raise RuntimeError(
                "Singularity stale-session cleanup failed:\n" + "\n".join(errors)
            )

    def _sif_is_valid_sync(self, path: Path) -> bool:
        if not path.is_file() or path.stat().st_size <= 0:
            return False
        try:
            result = subprocess.run(
                [self._resolve_runtime_bin(), "sif", "list", str(path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=float(os.getenv("SWE_APPTAINER_VALIDATE_TIMEOUT_SECONDS", "120")),
                check=False,
                env=self._runtime_environment(),
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return result.returncode == 0

    async def _sif_is_valid(self, path: Path) -> bool:
        if not path.is_file() or path.stat().st_size <= 0:
            return False
        result = await _run_process(
            [self._resolve_runtime_bin(), "sif", "list", str(path)],
            timeout=float(
                os.getenv("SWE_APPTAINER_VALIDATE_TIMEOUT_SECONDS", "120")
            ),
            env=self._runtime_environment(),
        )
        return result.return_code == 0

    def _ensure_image_sync(self) -> Path:
        """Populate the shared SIF cache under an exclusive publication lock."""
        self.image_cache.mkdir(parents=True, exist_ok=True)
        image_path = self._cached_image_path()
        lock_path = image_path.with_suffix(".lock")

        with lock_path.open("a+") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            if self._sif_is_valid_sync(image_path):
                return image_path
            image_path.unlink(missing_ok=True)

            with tempfile.NamedTemporaryFile(
                prefix=image_path.stem + ".",
                suffix=".sif",
                dir=self.image_cache,
                delete=False,
            ) as tmp:
                tmp_path = Path(tmp.name)
            tmp_path.unlink(missing_ok=True)

            attempts = max(1, int(os.getenv("SWE_APPTAINER_PULL_ATTEMPTS", "3")))
            retry_delay = max(
                0.0,
                float(os.getenv("SWE_APPTAINER_PULL_RETRY_DELAY_SECONDS", "2")),
            )
            timeout = float(
                os.getenv(
                    "SWE_APPTAINER_PULL_TIMEOUT_SECONDS",
                    os.getenv("SWE_SANDBOX_CREATE_TIMEOUT_SECONDS", "1800"),
                )
            )
            errors: list[str] = []
            try:
                for attempt in range(1, attempts + 1):
                    tmp_path.unlink(missing_ok=True)
                    try:
                        result = subprocess.run(
                            [
                                self._resolve_runtime_bin(),
                                "pull",
                                "--force",
                                str(tmp_path),
                                _singularity_pull_uri(self.image),
                            ],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            text=True,
                            timeout=timeout,
                            check=False,
                            env=self._runtime_environment(),
                        )
                    except subprocess.TimeoutExpired as error:
                        detail = error.stdout or ""
                        errors.append(
                            f"attempt {attempt}/{attempts} timed out after "
                            f"{timeout:g}s: {detail}".strip()
                        )
                    except OSError as error:
                        errors.append(
                            f"attempt {attempt}/{attempts} could not run the "
                            f"container CLI: {error}"
                        )
                    else:
                        if result.returncode == 0 and self._sif_is_valid_sync(tmp_path):
                            # Validation occurs before publication, and the temp
                            # file is on the same filesystem as the final cache.
                            os.chmod(tmp_path, 0o444)
                            os.replace(tmp_path, image_path)
                            return image_path
                        detail = result.stdout.strip()
                        if result.returncode == 0:
                            detail = (
                                detail + "\n" if detail else ""
                            ) + "pull produced an invalid SIF image"
                        errors.append(
                            f"attempt {attempt}/{attempts} exited "
                            f"{result.returncode}: {detail}"
                        )

                    if attempt < attempts and retry_delay:
                        time.sleep(retry_delay)

                raise RuntimeError(
                    f"container image pull failed for {self.image} after "
                    f"{attempts} attempt(s):\n" + "\n".join(errors)
                )
            finally:
                tmp_path.unlink(missing_ok=True)

    async def _ensure_image(self) -> Path:
        """Populate the SIF cache without an uncancellable blocking pull.

        The publication lock is acquired with nonblocking flock attempts so a
        cancelled setup can stop while another process owns the cache. Pulls
        use the async process-group transport and temporary artifacts are
        removed before cancellation escapes.
        """

        self.image_cache.mkdir(parents=True, exist_ok=True)
        image_path = self._cached_image_path()
        lock_path = image_path.with_suffix(".lock")
        lock_file = lock_path.open("a+")
        lock_acquired = False
        tmp_path: Path | None = None
        try:
            while not lock_acquired:
                try:
                    fcntl.flock(
                        lock_file.fileno(),
                        fcntl.LOCK_EX | fcntl.LOCK_NB,
                    )
                    lock_acquired = True
                except BlockingIOError:
                    await asyncio.sleep(0.1)

            if await self._sif_is_valid(image_path):
                return image_path
            image_path.unlink(missing_ok=True)

            with tempfile.NamedTemporaryFile(
                prefix=image_path.stem + ".",
                suffix=".sif",
                dir=self.image_cache,
                delete=False,
            ) as tmp:
                tmp_path = Path(tmp.name)
            tmp_path.unlink(missing_ok=True)

            attempts = max(
                1,
                int(os.getenv("SWE_APPTAINER_PULL_ATTEMPTS", "3")),
            )
            retry_delay = max(
                0.0,
                float(
                    os.getenv(
                        "SWE_APPTAINER_PULL_RETRY_DELAY_SECONDS",
                        "2",
                    )
                ),
            )
            timeout = float(
                os.getenv(
                    "SWE_APPTAINER_PULL_TIMEOUT_SECONDS",
                    os.getenv("SWE_SANDBOX_CREATE_TIMEOUT_SECONDS", "1800"),
                )
            )
            errors: list[str] = []
            for attempt in range(1, attempts + 1):
                tmp_path.unlink(missing_ok=True)
                result = await _run_process(
                    [
                        self._resolve_runtime_bin(),
                        "pull",
                        "--force",
                        str(tmp_path),
                        _singularity_pull_uri(self.image),
                    ],
                    timeout=timeout,
                    env=self._runtime_environment(),
                )
                if result.return_code == 0 and await self._sif_is_valid(tmp_path):
                    os.chmod(tmp_path, 0o444)
                    os.replace(tmp_path, image_path)
                    return image_path
                detail = result.output.strip()
                if result.return_code == 0:
                    detail = (
                        detail + "\n" if detail else ""
                    ) + "pull produced an invalid SIF image"
                errors.append(
                    f"attempt {attempt}/{attempts} exited "
                    f"{result.return_code}: {detail}"
                )
                if attempt < attempts and retry_delay:
                    await asyncio.sleep(retry_delay)

            raise RuntimeError(
                f"container image pull failed for {self.image} after "
                f"{attempts} attempt(s):\n" + "\n".join(errors)
            )
        finally:
            if tmp_path is not None:
                tmp_path.unlink(missing_ok=True)
            if lock_acquired:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            lock_file.close()

    def _service_adapter_material(self, raw_sha256: str) -> tuple[str, str, str]:
        content = {
            "schema_version": 1,
            "adapter_version": self._SERVICE_ADAPTER_VERSION,
            "raw_image_sha256": raw_sha256,
            "startscript": self._SERVICE_STARTSCRIPT,
        }
        canonical = json.dumps(content, sort_keys=True, separators=(",", ":"))
        content_sha256 = hashlib.sha256(canonical.encode()).hexdigest()
        adapter_key = hashlib.sha256(
            f"openreward-swe-adapter\0{canonical}".encode()
        ).hexdigest()
        return adapter_key, content_sha256, canonical

    def _service_image_path(self, adapter_key: str) -> Path:
        return self.image_cache / f"service-{adapter_key}.sif"

    @staticmethod
    def _service_provenance_path(image_path: Path) -> Path:
        return image_path.with_suffix(".provenance.json")

    async def _service_image_is_valid(
        self,
        image_path: Path,
        *,
        adapter_key: str,
        adapter_content_sha256: str,
        raw_sha256: str,
    ) -> tuple[bool, str | None]:
        provenance_path = self._service_provenance_path(image_path)
        try:
            image_stat = image_path.stat()
            provenance_stat = provenance_path.stat()
            if (
                image_stat.st_uid != os.getuid()
                or provenance_stat.st_uid != os.getuid()
                or stat.S_IMODE(image_stat.st_mode) & 0o222
                or stat.S_IMODE(provenance_stat.st_mode) & 0o222
            ):
                return False, None
            provenance = json.loads(provenance_path.read_text())
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            return False, None
        expected = {
            "schema_version": 1,
            "adapter_key": adapter_key,
            "adapter_content_sha256": adapter_content_sha256,
            "adapter_version": self._SERVICE_ADAPTER_VERSION,
            "raw_image_sha256": raw_sha256,
        }
        if any(provenance.get(key) != value for key, value in expected.items()):
            return False, None
        if not await self._sif_is_valid(image_path):
            return False, None
        inspection = await _run_process(
            [
                self._resolve_runtime_bin(),
                "inspect",
                "--labels",
                str(image_path),
            ],
            timeout=float(
                os.getenv("SWE_APPTAINER_VALIDATE_TIMEOUT_SECONDS", "120")
            ),
            env=self._runtime_environment(),
        )
        required_labels = (
            f"org.openreward.swe-adapter-key: {adapter_key}",
            f"org.openreward.swe-raw-sha256: {raw_sha256}",
            "org.openreward.swe-service-adapter: "
            f"{self._SERVICE_ADAPTER_VERSION}",
        )
        if inspection.return_code != 0 or any(
            label not in inspection.output for label in required_labels
        ):
            return False, None
        adapted_sha256 = await asyncio.to_thread(_sha256_file, image_path)
        if provenance.get("adapted_image_sha256") != adapted_sha256:
            return False, None
        return True, adapted_sha256

    async def _ensure_service_image(self, raw_image_path: Path) -> Path:
        """Build and atomically cache a persistent-service adapter SIF.

        OCI task images contain an executable but empty startscript on ABCI.
        Singularity reports a successful instance start and immediately exits.
        The adapter adds only a long-lived startscript; the task filesystem is
        inherited byte-for-byte from the immutable raw SIF.
        """

        self.image_cache.mkdir(parents=True, exist_ok=True)
        raw_sha256 = await asyncio.to_thread(_sha256_file, raw_image_path)
        adapter_key, content_sha256, canonical = self._service_adapter_material(
            raw_sha256
        )
        self.raw_image_sha256 = raw_sha256
        self.service_adapter_key = adapter_key
        image_path = self._service_image_path(adapter_key)
        provenance_path = self._service_provenance_path(image_path)
        lock_path = image_path.with_suffix(".lock")
        lock_file = lock_path.open("a+")
        lock_acquired = False
        build_dir: Path | None = None
        cache_partial: Path | None = None
        provenance_partial: Path | None = None
        try:
            while not lock_acquired:
                try:
                    fcntl.flock(
                        lock_file.fileno(),
                        fcntl.LOCK_EX | fcntl.LOCK_NB,
                    )
                    lock_acquired = True
                except BlockingIOError:
                    await asyncio.sleep(0.1)

            valid, adapted_sha256 = await self._service_image_is_valid(
                image_path,
                adapter_key=adapter_key,
                adapter_content_sha256=content_sha256,
                raw_sha256=raw_sha256,
            )
            if valid:
                assert adapted_sha256 is not None
                self.image_sha256 = adapted_sha256
                return image_path

            image_path.unlink(missing_ok=True)
            provenance_path.unlink(missing_ok=True)
            for stale_partial in self.image_cache.glob(
                f".{image_path.name}.partial-*"
            ):
                if stale_partial.is_file() and not stale_partial.is_symlink():
                    stale_partial.unlink(missing_ok=True)
            for stale_partial in self.image_cache.glob(
                f".{provenance_path.name}.partial-*"
            ):
                if stale_partial.is_file() and not stale_partial.is_symlink():
                    stale_partial.unlink(missing_ok=True)

            scratch_root = Path(
                os.getenv("SINGULARITY_TMPDIR")
                or os.getenv("APPTAINER_TMPDIR")
                or self.session_root
            )
            scratch_root.mkdir(parents=True, exist_ok=True)
            build_dir = Path(
                tempfile.mkdtemp(prefix="openreward-swe-adapter-", dir=scratch_root)
            )
            build_dir.chmod(0o700)
            raw_local = build_dir / "raw-task.sif"
            definition = build_dir / "service-adapter.def"
            built_image = build_dir / "service-adapted.sif"
            copy_result = await _run_process(
                ["/bin/cp", "--", str(raw_image_path), str(raw_local)],
                timeout=float(
                    os.getenv("SWE_APPTAINER_ADAPTER_COPY_TIMEOUT_SECONDS", "600")
                ),
                env=self._runtime_environment(),
            )
            if copy_result.return_code != 0:
                raise RuntimeError(
                    "could not stage raw task SIF for service adaptation: "
                    + copy_result.output.strip()
                )
            if await asyncio.to_thread(_sha256_file, raw_local) != raw_sha256:
                raise RuntimeError("staged raw task SIF digest changed")
            definition.write_text(
                "Bootstrap: localimage\n"
                f"From: {raw_local}\n\n"
                "%labels\n"
                "    org.openreward.swe-service-adapter "
                f"{self._SERVICE_ADAPTER_VERSION}\n"
                f"    org.openreward.swe-adapter-key {adapter_key}\n"
                f"    org.openreward.swe-raw-sha256 {raw_sha256}\n\n"
                "%startscript\n"
                f"    {self._SERVICE_STARTSCRIPT}\n"
            )
            definition.chmod(0o600)
            build_timeout = float(
                os.getenv("SWE_APPTAINER_ADAPTER_BUILD_TIMEOUT_SECONDS", "1800")
            )
            build = await _run_process(
                [
                    self._resolve_runtime_bin(),
                    "build",
                    "--fakeroot",
                    str(built_image),
                    str(definition),
                ],
                timeout=build_timeout,
                env=self._runtime_environment(),
            )
            if build.return_code != 0 or not await self._sif_is_valid(built_image):
                raise RuntimeError(
                    "Singularity service-adapter build failed: "
                    + build.output.strip()
                )

            cache_partial = self.image_cache / (
                f".{image_path.name}.partial-{os.getpid()}-{uuid4().hex}"
            )
            publish_copy = await _run_process(
                ["/bin/cp", "--", str(built_image), str(cache_partial)],
                timeout=float(
                    os.getenv("SWE_APPTAINER_ADAPTER_COPY_TIMEOUT_SECONDS", "600")
                ),
                env=self._runtime_environment(),
            )
            if publish_copy.return_code != 0:
                raise RuntimeError(
                    "could not stage adapted SIF for atomic publication: "
                    + publish_copy.output.strip()
                )
            adapted_sha256 = await asyncio.to_thread(_sha256_file, cache_partial)
            runtime_version = await _run_process(
                [self._resolve_runtime_bin(), "--version"],
                timeout=30,
                env=self._runtime_environment(),
            )
            if runtime_version.return_code != 0:
                raise RuntimeError(
                    "could not record Singularity builder version: "
                    + runtime_version.output.strip()
                )
            os.chmod(cache_partial, 0o444)
            provenance = {
                "schema_version": 1,
                "adapter_key": adapter_key,
                "adapter_content": json.loads(canonical),
                "adapter_content_sha256": content_sha256,
                "adapter_version": self._SERVICE_ADAPTER_VERSION,
                "adapted_image_path": str(image_path),
                "adapted_image_sha256": adapted_sha256,
                "builder_version": runtime_version.output.strip(),
                "raw_image_path": str(raw_image_path),
                "raw_image_sha256": raw_sha256,
                "source_uri": _singularity_pull_uri(self.image),
            }
            provenance_partial = provenance_path.with_name(
                f".{provenance_path.name}.partial-{os.getpid()}-{uuid4().hex}"
            )
            provenance_partial.write_text(
                json.dumps(provenance, indent=2, sort_keys=True) + "\n"
            )
            provenance_partial.chmod(0o444)
            os.replace(cache_partial, image_path)
            cache_partial = None
            os.replace(provenance_partial, provenance_path)
            provenance_partial = None
            valid, verified_sha256 = await self._service_image_is_valid(
                image_path,
                adapter_key=adapter_key,
                adapter_content_sha256=content_sha256,
                raw_sha256=raw_sha256,
            )
            if not valid or verified_sha256 != adapted_sha256:
                image_path.unlink(missing_ok=True)
                provenance_path.unlink(missing_ok=True)
                raise RuntimeError("published service-adapter SIF failed validation")
            self.image_sha256 = adapted_sha256
            return image_path
        finally:
            if cache_partial is not None:
                cache_partial.unlink(missing_ok=True)
            if provenance_partial is not None:
                provenance_partial.unlink(missing_ok=True)
            if build_dir is not None:
                shutil.rmtree(build_dir, ignore_errors=True)
            if lock_acquired:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            lock_file.close()

    def _instance_start_args(self) -> list[str]:
        if self.image_path is None or (self.overlay_path is None and self.writable_rootfs_path is None):
            raise RuntimeError("Singularity sandbox image/writable storage is missing")
        if self.session_tmp_dir is None or self.session_var_tmp_dir is None:
            raise RuntimeError("Singularity sandbox private tmp is missing")
        if self.instance_pid_path is None:
            raise RuntimeError("Singularity sandbox PID path is missing")

        args = [
            self._resolve_runtime_bin(),
            "instance",
            "start",
            "--cleanenv",
            "--containall",
            "--no-home",
            "--no-eval",
            "--no-mount",
            "home,cwd,bind-paths",
            "--bind",
            f"{self.session_tmp_dir}:/tmp:rw",
            "--bind",
            f"{self.session_var_tmp_dir}:/var/tmp:rw",
            "--env",
            "GIT_CONFIG_GLOBAL=/tmp/.gitconfig-openreward",
            "--pid-file",
            str(self.instance_pid_path),
        ]
        if self.writable_rootfs_path is not None:
            args.append("--writable")
        else:
            args += ["--overlay", str(self.overlay_path)]
        if self.fakeroot:
            args.append("--fakeroot")
        network = os.getenv("SWE_APPTAINER_NETWORK", "host").strip().lower()
        if network not in {"", "host", "none"}:
            raise ValueError("SWE_APPTAINER_NETWORK must be 'host' or 'none'")
        if network == "none":
            # This is opt-in because many HPC sites do not permit users to
            # create a network namespace. Host networking is otherwise used.
            args += ["--net", "--network", "none"]
        args += [str(self.writable_rootfs_path or self.image_path), self.name]
        return args

    async def _create_writable_directory(self) -> None:
        """Extract a private rootfs to avoid limited host loop devices.

        Extraction runs as the service UID. Normalize owner permissions only
        in this session's copy; task images can contain root-private build
        caches that cannot be copied by a non-root process from a mounted SIF.
        """
        if self.session_dir is None or self.image_path is None:
            raise RuntimeError("Singularity writable rootfs is missing session state")
        self.writable_rootfs_path = self.session_dir / "rootfs"
        result = await _run_process(
            [self._resolve_runtime_bin(), "build", "--sandbox", "--fix-perms",
             str(self.writable_rootfs_path), str(self.image_path)],
            timeout=float(os.getenv("SWE_APPTAINER_REPOSITORY_SEED_TIMEOUT_SECONDS", "900")),
            env=self._runtime_environment(),
        )
        if result.return_code != 0:
            raise RuntimeError("could not extract a writable task rootfs: " + result.output.strip())
        await asyncio.to_thread(self._make_rootfs_owner_writable)

    def _make_rootfs_owner_writable(self) -> None:
        assert self.writable_rootfs_path is not None
        for directory, directories, files in os.walk(self.writable_rootfs_path, followlinks=False):
            for path in [Path(directory), *(Path(directory) / name for name in directories + files)]:
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode):
                    continue
                if info.st_uid != os.getuid():
                    raise RuntimeError(f"extracted task rootfs contains a foreign-owned path: {path}")
                if stat.S_ISDIR(info.st_mode):
                    path.chmod(stat.S_IMODE(info.st_mode) | 0o700)
                elif stat.S_ISREG(info.st_mode):
                    path.chmod(stat.S_IMODE(info.st_mode) | 0o600)

    async def _discover_image_workdir(self) -> str:
        if self.image_path is None:
            raise RuntimeError("Singularity service-adapted image is missing")
        marker = f"__OPENREWARD_IMAGE_WORKDIR_{uuid4().hex}__"
        configured = os.getenv("SWE_APPTAINER_CONTAINER_WORKDIR", "").strip()
        if configured:
            command = (
                f"test -d {shlex.quote(configured)} && "
                f"printf '%s%s\\n' {shlex.quote(marker)} "
                f"{shlex.quote(configured)}"
            )
        else:
            command = (
                "found=''; count=0; "
                "for candidate in /*; do "
                "if [ -e \"$candidate/.git\" ]; then "
                "found=\"$found$candidate\\n\"; count=$((count + 1)); fi; done; "
                "if [ \"$count\" -eq 0 ]; then "
                "found=$(find / -xdev -mindepth 2 -maxdepth 5 -name .git "
                "-print 2>/dev/null | sed 's#/.git$##'); fi; "
                "printf '%b' \"$found\" | "
                f"sed 's#^#{marker}#'"
            )
        result = await _run_process(
            [
                self._resolve_runtime_bin(),
                "exec",
                "--cleanenv",
                "--containall",
                "--no-home",
                "--no-mount",
                "home,cwd,bind-paths",
                "--cwd",
                "/",
                str(self.image_path),
                "/bin/sh",
                "-c",
                command,
            ],
            timeout=float(os.getenv("SWE_APPTAINER_PROBE_TIMEOUT_SECONDS", "60")),
            env=self._runtime_environment(),
        )
        candidates = [
            line.removeprefix(marker).strip()
            for line in result.output.splitlines()
            if line.startswith(marker) and line.removeprefix(marker).strip()
        ]
        if result.return_code != 0 or len(candidates) != 1:
            raise RuntimeError(
                "Could not determine the task repository WORKDIR in the raw "
                f"task filesystem (found {len(candidates)} candidates): "
                f"{result.output.strip()}"
            )
        workdir = PurePosixPath(candidates[0])
        if (
            not workdir.is_absolute()
            or workdir == PurePosixPath("/")
            or ".." in workdir.parts
        ):
            raise RuntimeError(f"refusing unsafe task repository path: {workdir}")
        return str(workdir)

    async def _seed_writable_repository(self, upper: Path) -> None:
        """Copy the lower root-owned checkout into the uid-owned upper layer."""
        if self.session_dir is None or self.image_path is None:
            raise RuntimeError("Singularity repository seed is missing session state")
        if self.container_workdir is None:
            self.container_workdir = await self._discover_image_workdir()
        seed_root = self.session_dir / "repository-seed"
        seed_repository = seed_root / "repository"
        seed_root.mkdir(mode=0o700)
        seed_repository.mkdir(mode=0o700)
        try:
            source = self.container_workdir.rstrip("/") + "/."
            result = await _run_process(
                [
                    self._resolve_runtime_bin(),
                    "exec",
                    "--cleanenv",
                    "--containall",
                    "--no-home",
                    "--no-mount",
                    "home,cwd,bind-paths",
                    "--cwd",
                    "/",
                    "--bind",
                    f"{seed_root}:/openreward-seed:rw",
                    str(self.image_path),
                    "/bin/sh",
                    "-c",
                    "umask 077; cp -a --no-preserve=ownership -- "
                    f"{shlex.quote(source)} /openreward-seed/repository/",
                ],
                timeout=float(
                    os.getenv("SWE_APPTAINER_REPOSITORY_SEED_TIMEOUT_SECONDS", "900")
                ),
                env=self._runtime_environment(),
            )
            if result.return_code != 0:
                raise RuntimeError(
                    "could not seed a uid-owned task checkout: "
                    + result.output.strip()
                )
            if not (seed_repository / ".git").exists():
                raise RuntimeError("seeded task checkout has no .git metadata")
            allocated_bytes = 0
            for directory, directories, files in os.walk(
                seed_repository,
                followlinks=False,
            ):
                for entry in [*directories, *files]:
                    entry_path = Path(directory) / entry
                    entry_stat = os.lstat(entry_path)
                    if entry_stat.st_uid != os.getuid():
                        raise RuntimeError(
                            "seeded task checkout contains a foreign-owned path: "
                            f"{entry_path}"
                        )
                    allocated_bytes += entry_stat.st_blocks * 512
            overlay_bytes = self.overlay_size_mb * 1024 * 1024
            if allocated_bytes > overlay_bytes * 0.8:
                raise RuntimeError(
                    "task checkout seed consumes more than 80% of the writable "
                    f"overlay ({allocated_bytes} of {overlay_bytes} bytes)"
                )
            relative = PurePosixPath(self.container_workdir).relative_to("/")
            destination = upper.joinpath(*relative.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            os.replace(seed_repository, destination)
        finally:
            shutil.rmtree(seed_root, ignore_errors=True)

    async def _create_overlay(self) -> None:
        """Create an ABCI-compatible EXT3 overlay owned by the calling UID.

        Singularity CE's ``overlay create`` creates ``upper`` and ``work`` as
        real UID 0 on this setuid installation. Under ``--fakeroot`` that UID
        is unmapped and the overlay is effectively read-only. Seeding ext3 via
        ``mkfs.ext3 -d`` preserves our real UID, which maps to container UID 0.
        """
        if self.session_dir is None or self.overlay_path is None:
            raise RuntimeError("Singularity sandbox session state is missing")

        layout = self.session_dir / "overlay-layout"
        upper = layout / "upper"
        work = layout / "work"
        upper.mkdir(parents=True)
        work.mkdir()
        layout.chmod(0o700)
        upper.chmod(0o700)
        work.chmod(0o700)
        for path in (upper, work):
            if path.stat().st_uid != os.getuid():
                raise RuntimeError(
                    f"overlay seed directory is not owned by uid {os.getuid()}: "
                    f"{path}"
                )

        await self._seed_writable_repository(upper)

        size_bytes = self.overlay_size_mb * 1024 * 1024
        try:
            with self.overlay_path.open("xb") as overlay_file:
                overlay_file.truncate(size_bytes)
                if not self.sparse_overlay:
                    try:
                        os.posix_fallocate(overlay_file.fileno(), 0, size_bytes)
                    except AttributeError as error:
                        raise RuntimeError(
                            "non-sparse overlays require os.posix_fallocate"
                        ) from error

            result = await _run_process(
                [
                    self._resolve_mkfs_bin(),
                    "-q",
                    "-F",
                    "-d",
                    str(layout),
                    str(self.overlay_path),
                ],
                timeout=float(
                    os.getenv(
                        "SWE_APPTAINER_OVERLAY_CREATE_TIMEOUT_SECONDS", "300"
                    )
                ),
                env=self._runtime_environment(),
            )
            if result.return_code != 0:
                raise RuntimeError(
                    "container EXT3 overlay creation failed: "
                    + result.output.strip()
                )
        finally:
            shutil.rmtree(layout, ignore_errors=True)

    def _exec_args(self, command: str, *, cwd: str | None = None) -> list[str]:
        return [
            self._resolve_runtime_bin(),
            "exec",
            "--cleanenv",
            "--env",
            "GIT_CONFIG_GLOBAL=/tmp/.gitconfig-openreward",
            "--cwd",
            cwd or self.container_workdir or "/",
            f"instance://{self.name}",
            "/bin/sh",
            "-c",
            command,
        ]

    def _write_container_git_config(self) -> None:
        if self.session_tmp_dir is None or self.container_workdir is None:
            raise RuntimeError("Singularity task Git configuration is missing state")
        config_path = self.session_tmp_dir / ".gitconfig-openreward"
        # Git's quoted config values use the same escaping needed here for an
        # absolute path. Trust only this session's discovered task checkout,
        # rather than disabling ownership checks globally with '*'.
        config_path.write_text(
            "[safe]\n\tdirectory = "
            + json.dumps(self.container_workdir)
            + "\n"
        )
        config_path.chmod(0o600)

    async def _start_instance(self) -> None:
        # Mark the name as needing cleanup before spawning. Cancellation can
        # arrive after the runtime creates the instance but before its result
        # is delivered to this coroutine.
        self._instance_may_exist = True
        control_lock = await self._acquire_instance_control_lock()
        try:
            result = await _run_process(
                self._instance_start_args(),
                timeout=float(
                    os.getenv("SWE_SANDBOX_CREATE_TIMEOUT_SECONDS", "1800")
                ),
                env=self._instance_environment(),
            )
            if result.return_code != 0:
                raise RuntimeError(
                    f"container instance start failed for {self.image}: "
                    f"{result.output.strip()}"
                )
            if self.instance_pid_path is None:
                raise RuntimeError("Singularity instance PID path is missing")
            pid_from_file: int | None = None
            deadline = time.monotonic() + 5
            while pid_from_file is None and time.monotonic() < deadline:
                pid_from_file = self._read_instance_pid_file(self.instance_pid_path)
                if pid_from_file is None:
                    await asyncio.sleep(0.05)
            if pid_from_file is None:
                raise RuntimeError(
                    f"instance {self.name!r} did not publish its required PID file"
                )
            self.instance_pid_path.chmod(0o600)
            instance_record = await self._instance_record_async_unlocked()
            if instance_record is None:
                raise RuntimeError(
                    "container instance exited immediately after a successful "
                    f"start for {self.image}"
                )
            runtime_pid = self._instance_pid_from_record(instance_record)
            if runtime_pid != pid_from_file:
                raise RuntimeError(
                    f"instance {self.name!r} PID file and metadata disagree"
                )
            process_start_time: str | None = None
            deadline = time.monotonic() + 5
            while process_start_time is None and time.monotonic() < deadline:
                process_start_time = self._matching_instance_start_time(runtime_pid)
                if process_start_time is None:
                    await asyncio.sleep(0.05)
            if process_start_time is None:
                raise RuntimeError(
                    f"could not prove process identity for instance {self.name!r}"
                )
            self.instance_pid = runtime_pid
            self.instance_start_time = process_start_time
            self.instance_hostname = socket.gethostname()
            self._write_session_owner_record()
        finally:
            fcntl.flock(control_lock.fileno(), fcntl.LOCK_UN)
            control_lock.close()

    async def _discover_container_workdir(self) -> str:
        marker = f"__OPENREWARD_WORKDIR_{uuid4().hex}__"
        configured = os.getenv("SWE_APPTAINER_CONTAINER_WORKDIR", "").strip()
        if configured:
            command = (
                f"test -d {shlex.quote(configured)} && "
                f"printf '%s%s\\n' {shlex.quote(marker)} \"$(pwd -P)\""
            )
            cwd = configured
        else:
            command = (
                "found=''; count=0; "
                "for candidate in /*; do "
                "if [ -e \"$candidate/.git\" ]; then "
                "found=\"$found$candidate\\n\"; count=$((count + 1)); fi; done; "
                "if [ \"$count\" -eq 0 ]; then "
                "found=$(find / -xdev -mindepth 2 -maxdepth 5 -name .git "
                "-print 2>/dev/null | sed 's#/.git$##'); fi; "
                "printf '%b' \"$found\" | "
                f"sed 's#^#{marker}#'"
            )
            cwd = "/"
        result = await _run_process(
            self._exec_args(command, cwd=cwd),
            timeout=float(os.getenv("SWE_APPTAINER_PROBE_TIMEOUT_SECONDS", "60")),
            env=self._instance_environment(),
        )
        candidates = [
            line.removeprefix(marker).strip()
            for line in result.output.splitlines()
            if line.startswith(marker) and line.removeprefix(marker).strip()
        ]
        if result.return_code != 0 or len(candidates) != 1:
            detail = result.output.strip()
            suffix = f": {detail}" if detail else ""
            raise RuntimeError(
                "Could not determine the task repository WORKDIR inside the "
                f"container (found {len(candidates)} root Git checkouts){suffix}"
            )
        return candidates[0]

    async def _instance_record_async_unlocked(self) -> dict[str, object] | None:
        result = await _run_process(
            [
                self._resolve_runtime_bin(),
                "instance",
                "list",
                "--json",
                self.name,
            ],
            timeout=30,
            env=self._instance_environment(),
        )
        if result.return_code != 0:
            raise RuntimeError(
                f"could not query Singularity instance {self.name!r}: "
                f"{result.output.strip()}"
            )
        try:
            payload = json.loads(result.output or "{}")
        except json.JSONDecodeError as error:
            raise RuntimeError(
                f"invalid Singularity instance JSON for {self.name!r}: "
                f"{result.output!r}"
            ) from error
        return self._instance_record_in_list_payload(payload, self.name)

    async def _instance_exists(self) -> bool:
        control_lock = await self._acquire_instance_control_lock()
        try:
            try:
                return await self._instance_record_async_unlocked() is not None
            except RuntimeError:
                # A failed query cannot prove cleanup or absence.
                return True
        finally:
            fcntl.flock(control_lock.fileno(), fcntl.LOCK_UN)
            control_lock.close()

    async def _stop_instance(self, *, force: bool = False) -> None:
        if not self._instance_may_exist:
            return
        control_lock = await self._acquire_instance_control_lock()
        try:
            record = await self._instance_record_async_unlocked()
            pid_from_file = (
                self._read_instance_pid_file(self.instance_pid_path)
                if self.instance_pid_path is not None
                else None
            )
            if record is not None:
                runtime_pid = self._instance_pid_from_record(record)
                if pid_from_file != runtime_pid:
                    raise RuntimeError(
                        f"refusing to stop instance {self.name!r}: PID file and "
                        "runtime metadata disagree"
                    )
                process_start_time = self._matching_instance_start_time(runtime_pid)
                if process_start_time is None:
                    raise RuntimeError(
                        f"refusing to stop instance {self.name!r}: process identity "
                        "cannot be proved"
                    )
                if self.instance_pid is not None and self.instance_pid != runtime_pid:
                    raise RuntimeError(
                        f"refusing to stop instance {self.name!r}: recorded PID changed"
                    )
                if (
                    self.instance_start_time is not None
                    and self.instance_start_time != process_start_time
                ):
                    raise RuntimeError(
                        f"refusing to stop instance {self.name!r}: PID was reused"
                    )
                self.instance_pid = runtime_pid
                self.instance_start_time = process_start_time
                self.instance_hostname = socket.gethostname()
                self._write_session_owner_record()
                result = await _run_process(
                    [
                        self._resolve_runtime_bin(),
                        "instance",
                        "stop",
                        *(["--force"] if force else [
                            "--timeout",
                            os.getenv("SWE_APPTAINER_INSTANCE_STOP_GRACE_SECONDS", "10"),
                        ]),
                        self.name,
                    ],
                    timeout=float(
                        os.getenv(
                            "SWE_APPTAINER_INSTANCE_STOP_TIMEOUT_SECONDS",
                            "60",
                        )
                    ),
                    env=self._instance_environment(),
                )
                remaining = await self._instance_record_async_unlocked()
                if remaining is not None:
                    raise RuntimeError(
                        "container instance stop failed: " + result.output.strip()
                    )
                if _process_identity_matches(runtime_pid, process_start_time):
                    await asyncio.to_thread(
                        self._terminate_exact_instance_process,
                        runtime_pid,
                        self.name,
                        process_start_time,
                        0 if force else 2,
                    )
            elif (
                self.instance_pid is not None
                and self.instance_start_time is not None
                and _process_identity_matches(
                    self.instance_pid,
                    self.instance_start_time,
                )
            ):
                if pid_from_file != self.instance_pid:
                    raise RuntimeError(
                        f"refusing direct cleanup of {self.name!r}: PID file changed"
                    )
                await asyncio.to_thread(
                    self._terminate_exact_instance_process,
                    self.instance_pid,
                    self.name,
                    self.instance_start_time,
                    0 if force else 2,
                )
            elif pid_from_file is not None:
                current_start = self._matching_instance_start_time(pid_from_file)
                if current_start is not None:
                    raise RuntimeError(
                        f"unowned live instance process remains for {self.name!r}"
                    )
            self._instance_may_exist = False
            if self.instance_pid_path is not None:
                self.instance_pid_path.unlink(missing_ok=True)
            self.instance_pid = None
            self.instance_start_time = None
            if self.session_dir is not None:
                self._write_session_owner_record()
        finally:
            fcntl.flock(control_lock.fileno(), fcntl.LOCK_UN)
            control_lock.close()

    async def _probe_instance(self) -> None:
        if self.container_workdir is None:
            raise RuntimeError("Singularity task repository WORKDIR is missing")
        overlay_probe = f"/.openreward-overlay-probe-{self.name}"
        repository_probe = f".openreward-repository-probe-{self.name}"
        probe_command = (
            f"overlay_probe={shlex.quote(overlay_probe)}; "
            f"repository_probe={shlex.quote(repository_probe)}; "
            "umask 077; "
            "mkdir -- \"$overlay_probe\" && rmdir -- \"$overlay_probe\" && "
            "( : > \"$repository_probe\" ) && rm -- \"$repository_probe\""
        )
        result = await _run_process(
            self._exec_args(probe_command, cwd=self.container_workdir),
            timeout=float(os.getenv("SWE_APPTAINER_PROBE_TIMEOUT_SECONDS", "60")),
            env=self._instance_environment(),
        )
        if result.return_code != 0:
            raise RuntimeError(
                "container instance writable-overlay/repository probe failed. "
                f"The task checkout {self.container_workdir!r} must be writable. On ABCI, "
                "do not enable SWE_APPTAINER_FAKEROOT because Singularity's "
                "squashfuse fallback makes the root filesystem read-only: "
                + result.output.strip()
            )

    async def _restart_after_interrupted_command(self, *, force: bool = False) -> None:
        if self._lifecycle_lock is None:
            self._lifecycle_lock = asyncio.Lock()
        async with self._lifecycle_lock:
            if self._stopping:
                return
            self.started = False
            try:
                await self._stop_instance(force=force)
                await self._start_instance()
                await self._probe_instance()
            except BaseException:
                # A failed restart must not leave an instance using an overlay
                # that the caller might later delete.
                try:
                    await self._stop_instance(force=force)
                finally:
                    self.started = False
                raise
            self.started = True

    async def start(self) -> None:
        self._resolve_runtime_bin()
        if self.started or self.session_dir is not None or self._instance_may_exist:
            raise RuntimeError("Singularity sandbox has already been started")

        try:
            await asyncio.to_thread(self._cleanup_stale_sessions_sync)
            self.raw_image_path = await self._ensure_image()
            self.image_path = await self._ensure_service_image(self.raw_image_path)
            self.session_dir, self._session_lock_file = (
                self._create_leased_session_dir()
            )
            self.instance_hostname = socket.gethostname()
            self.instance_pid_path = self.session_dir / self._INSTANCE_PID_FILE
            self._write_session_owner_record()
            self.session_tmp_dir = self.session_dir / "tmp"
            self.session_var_tmp_dir = self.session_dir / "var-tmp"
            for tmp_dir in (self.session_tmp_dir, self.session_var_tmp_dir):
                tmp_dir.mkdir()
                tmp_dir.chmod(0o1777)
            if self.writable_directory:
                await self._create_writable_directory()
            else:
                self.overlay_path = self.session_dir / "writable-overlay.img"
                await self._create_overlay()

            await self._start_instance()
            seeded_workdir = self.container_workdir
            running_workdir = await self._discover_container_workdir()
            if not self.writable_directory and running_workdir != seeded_workdir:
                raise RuntimeError(
                    "task repository WORKDIR changed after overlay mount: "
                    f"{seeded_workdir!r} -> {running_workdir!r}"
                )
            self.container_workdir = running_workdir
            self._write_container_git_config()
            await self._probe_instance()
            self.started = True
        except BaseException as start_error:
            try:
                await self.stop()
            except BaseException as cleanup_error:
                raise RuntimeError(
                    "Singularity sandbox startup failed and cleanup did not "
                    f"complete: {cleanup_error}"
                ) from start_error
            raise

    async def run(
        self,
        command: str,
        timeout: float | None = None,
        stdin_data: bytes | None = None,
    ) -> LocalRunResult:
        if not self.started or self._stopping:
            raise RuntimeError("Singularity sandbox has not been started")
        try:
            result = await _run_process(
                self._exec_args(command),
                timeout=self.default_timeout if timeout is None else timeout,
                env=self._instance_environment(),
                stdin_data=stdin_data,
                memory_limit_bytes=max(
                    0, int(os.getenv("SWE_SINGULARITY_MEMORY_LIMIT_BYTES", "0"))
                ),
                memory_root_pid=self.instance_pid,
            )
        except asyncio.CancelledError:
            current_task = asyncio.current_task()
            if current_task is not None and hasattr(current_task, "uncancel"):
                # Consume the delivered cancellation while the instance is
                # restored. A manual CancelledError below preserves the public
                # cancellation contract after cleanup is complete.
                current_task.uncancel()
            self.started = False
            recovery_task = asyncio.create_task(
                self._restart_after_interrupted_command()
            )
            while not recovery_task.done():
                try:
                    await asyncio.shield(recovery_task)
                except asyncio.CancelledError:
                    if current_task is not None and hasattr(current_task, "uncancel"):
                        current_task.uncancel()
            # Surface cleanup failures through exception chaining while
            # retaining cancellation as the externally visible outcome.
            try:
                recovery_task.result()
            except BaseException as recovery_error:
                raise asyncio.CancelledError() from recovery_error
            raise

        if result.return_code in (124, 137):
            self.started = False
            try:
                await self._restart_after_interrupted_command()
            except BaseException as recovery_error:
                detail = str(recovery_error).strip()
                result.output += (
                    ("\n" if result.output else "")
                    + "Sandbox recovery after interrupted command failed"
                    + (f": {detail}" if detail else "")
                )
        return result

    def _remove_session_directory_sync(self) -> None:
        # rmtree unlinks the lease before the directory disappears. Hold the
        # discovery lock so a concurrent janitor cannot create a new lease
        # inode and start removing the same tree while we still own the old one.
        lock_path = self.session_root / ".openreward-session-janitor.lock"
        with lock_path.open("a+") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            if self.session_dir is not None:
                remove_session_tree(self.session_dir)

    async def _cleanup_resources(self) -> None:
        self.started = False
        await self._stop_instance()
        try:
            if self.session_dir is not None:
                try:
                    await asyncio.to_thread(self._remove_session_directory_sync)
                except FileNotFoundError:
                    pass
        finally:
            if self._session_lock_file is not None:
                self._session_lock_file.close()
                self._session_lock_file = None
        self.raw_image_path = None
        self.raw_image_sha256 = None
        self.image_path = None
        self.image_sha256 = None
        self.service_adapter_key = None
        self.session_dir = None
        self.session_tmp_dir = None
        self.session_var_tmp_dir = None
        self.instance_pid_path = None
        self.instance_pid = None
        self.instance_start_time = None
        self.instance_hostname = None
        self.overlay_path = None
        self.writable_rootfs_path = None
        self.container_workdir = None
        self._stopping = False

    async def stop(self) -> None:
        if self._stop_task is None or self._stop_task.done():
            self._stopping = True
            self._stop_task = asyncio.create_task(self._cleanup_resources())
        stop_task = self._stop_task
        was_cancelled = False
        current_task = asyncio.current_task()
        try:
            while not stop_task.done():
                try:
                    await asyncio.shield(stop_task)
                except asyncio.CancelledError:
                    was_cancelled = True
                    if current_task is not None and hasattr(current_task, "uncancel"):
                        # Do not busy-loop on the task's pending cancellation;
                        # cleanup owns a live instance and writable filesystem.
                        current_task.uncancel()
            stop_task.result()
            if was_cancelled:
                raise asyncio.CancelledError()
        finally:
            if stop_task.done() and self._stop_task is stop_task:
                self._stop_task = None


# Apptainer is the community continuation of Singularity and retains the CLI
# used above. Export both names for callers and tests that prefer either term.
ApptainerSandbox = SingularitySandbox


def create_local_sandbox(runtime: str, image: str) -> SandboxBackend:
    if runtime == "docker":
        return DockerSandbox(image)
    if runtime == "enroot":
        return EnrootSandbox(image)
    if runtime in {"singularity", "apptainer"}:
        return SingularitySandbox(image)
    raise ValueError(
        f"Unsupported local sandbox runtime {runtime!r}; expected 'docker', "
        "'enroot', 'singularity', or 'apptainer'"
    )
