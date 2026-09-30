"""Private official Frontier-CS 2.0 judges and per-episode public workspaces."""
from __future__ import annotations

import asyncio
import base64
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import tarfile
import tempfile
import time
import uuid

from aiohttp import web

from .catalog import require_full_harness, task_requirements
from .contracts import EvaluationResult, InfrastructureError
from .runtime import Sandbox, Service, finish_cleanup, request_json, reserve_port

_POOL = None
_PUBLIC_FILES = (
    "readme", "submission_config.json", "AGENT.md", "submit.py", "submit.sh",
    "submissions.py", "submissions.sh", "wait_submission.py", "wait_submission.sh",
    "cancel_submission.py", "cancel_submission.sh",
)
_MAX_ARCHIVE_BYTES = 20_000_000
_MAX_SUBMISSION_BYTES = 30_000_000


def private_judge_source(source: str, transport_token: str, final_token: str) -> str:
    """Add transport authentication to a generated copy, preserving evaluation."""
    source, count = re.subn(r'^FINAL_ROLE_TOKEN = "[^"\n]*"$',
                           f'FINAL_ROLE_TOKEN = {json.dumps(final_token)}', source,
                           flags=re.MULTILINE)
    if count != 1:
        raise InfrastructureError("Official judge final-role token anchor changed")
    for method in ("GET", "POST"):
        anchor = f"    def do_{method}(self) -> None:\n"
        if source.count(anchor) != 1:
            raise InfrastructureError("Official judge HTTP entry point changed")
        source = source.replace(anchor, anchor + (
            f'        if not secrets.compare_digest(self.headers.get("Authorization", ""), '
            f'{json.dumps("Bearer " + transport_token)}):\n'
            '            self._write_json(401, {"status": "error", "error": "unauthorized"})\n'
            '            return\n'
        ))
    # No credential is placed in os.environ, which candidate subprocesses inherit.
    return source.replace('ThreadingHTTPServer(("0.0.0.0", port), JudgeHandler)',
                          'ThreadingHTTPServer(("127.0.0.1", port), JudgeHandler)')


def private_evaluator_source(problem_id: str, source: str) -> str:
    """Adapt DuckDB's host allocator and identify pristine baseline failures."""
    if problem_id != "duckdb_e2e_query_optimization":
        return source
    # On large hosts glibc's per-thread arenas exhaust the official 12 GiB
    # virtual-memory limit at <1 GiB RSS, even with eight-core affinity. Apply
    # the same allocator setting to baseline and candidate subprocesses;
    # preserve the native memory limits, workloads, and score calculation.
    anchor = '        "CCACHE_DIR": str(tmp_root / "ccache"),\n'
    if source.count(anchor) != 1 or 'def clean_env(tmp_root: Path)' not in source:
        raise InfrastructureError("Official DuckDB environment anchor changed")
    source = source.replace(anchor, anchor + '        "MALLOC_ARENA_MAX": "2",\n')
    failure = ('    except subprocess.CalledProcessError as exc:\n'
               '        failed_command = safe_failed_command(exc.cmd)\n')
    if source.count(failure) != 1:
        raise InfrastructureError("Official DuckDB failure handler anchor changed")
    # A pristine baseline failure says nothing about the candidate. Let the
    # official judge report an infrastructure error instead of a zero reward.
    replacement = ('    except subprocess.CalledProcessError as exc:\n'
                   '        if (isinstance(exc.cmd, (list, tuple)) and exc.cmd\n'
                   '                and str(exc.cmd[0]).startswith("/opt/duckdb-vanilla/")):\n'
                   '            raise RuntimeError("Pristine DuckDB baseline command failed") from exc\n'
                   '        failed_command = safe_failed_command(exc.cmd)\n')
    return source.replace(failure, replacement)


def artifact_payload(workspace: Path, path: str, config: dict, *, final: bool) -> dict | None:
    """Read only artifacts confined to /app; never follow a link onto the host."""
    public_path = PurePosixPath(path)
    if not public_path.is_absolute() or ".." in public_path.parts:
        raise ValueError("Submission must be an absolute path under /app")
    try:
        relative = public_path.relative_to("/app")
    except ValueError:
        raise ValueError("Submission must be under /app") from None
    candidate = workspace / str(relative)
    root = workspace.resolve()
    if not candidate.resolve().is_relative_to(root):
        raise ValueError("Submission points outside the episode workspace")
    if not candidate.exists():
        return None
    payload = {"submission_uuid": str(uuid.uuid4()),
               "submission_role": "final" if final else "agent",
               "submission_kind": str(config.get("kind", "file"))}
    if payload["submission_kind"] == "directory":
        if not candidate.is_dir():
            raise ValueError("Directory submission is not a directory")
        excluded = [str(p).strip("/") for p in config.get("exclude", []) if str(p).strip("/")]
        buffer = io.BytesIO()
        total_bytes = 0
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for item in sorted(candidate.rglob("*")):
                rel = item.relative_to(candidate)
                if any(rel.as_posix() == p or rel.as_posix().startswith(p + "/")
                       or p in rel.parts for p in excluded):
                    continue
                if not item.resolve().is_relative_to(root):
                    raise ValueError("Submission contains a link outside its workspace")
                if item.is_symlink():
                    raise ValueError("Directory submissions cannot contain symlinks")
                if item.is_file():
                    total_bytes += item.stat().st_size
                    if total_bytes > _MAX_SUBMISSION_BYTES:
                        raise ValueError("Submission is too large")
                    archive.add(item, arcname=rel.as_posix())
                    if buffer.tell() > _MAX_ARCHIVE_BYTES:
                        raise ValueError("Submission archive is too large")
        if len(buffer.getvalue()) > _MAX_ARCHIVE_BYTES:
            raise ValueError("Submission archive is too large")
        payload["archive_b64"] = base64.b64encode(buffer.getvalue()).decode("ascii")
    else:
        if not candidate.is_file() or candidate.stat().st_size > _MAX_SUBMISSION_BYTES:
            raise ValueError("Submission is not a bounded regular file")
        code = candidate.read_text(encoding="utf-8")
        if not code.strip() and not config.get("allow_empty", False):
            return None
        payload["code"] = code
    if len(json.dumps(payload).encode()) > _MAX_SUBMISSION_BYTES:
        raise ValueError("Encoded submission is too large")
    return payload


def checked_result(result: dict) -> EvaluationResult:
    if result.get("status") != "done":
        raise InfrastructureError("Frontier-CS judge did not complete evaluation")
    require_full_harness(result)
    try:
        score = float(result["score"])
        unbounded = float(result.get("score_unbounded", score))
    except (KeyError, TypeError, ValueError) as exc:
        raise InfrastructureError("Frontier-CS judge returned no numeric score") from exc
    if (isinstance(result["score"], bool) or not math.isfinite(score)
            or not 0 <= score <= 100 or not math.isfinite(unbounded)):
        raise InfrastructureError("Frontier-CS judge returned an invalid bounded score")
    return EvaluationResult(score, str(result.get("message", "")),
                            metadata={"score_unbounded": unbounded,
                                      "metrics": result.get("metrics", {})})


class Frontier20Session:
    def __init__(self, task, images):
        self.task, self.images = task, images
        self.requirements = task_requirements(task)
        self.timeout = float(self.requirements["verifier_timeout_seconds"])
        self.directory = None
        self.agent = self.judge = self.service = self.proxy = None
        self._slot = False
        self._final = False
        self._auth = secrets.token_urlsafe(32)
        self._final_auth = secrets.token_urlsafe(32)
        self._capability = secrets.token_urlsafe(32)
        self._submission_lock = asyncio.Lock()

    async def start(self):
        global _POOL
        if not self.images.get("ready"):
            raise InfrastructureError(f"Image preflight incomplete for {self.task.task_id}")
        if _POOL is None:
            available = tuple(sorted(os.sched_getaffinity(0)))[16:48]
            count = min(max(1, int(os.environ.get("FRONTIER_JUDGE_CONCURRENCY", "4"))), len(available) // 8)
            if not count:
                raise InfrastructureError("Frontier-CS 2.0 needs an eight-core slot beyond the algorithmic judge cores")
            _POOL = asyncio.Queue()
            for index in range(count):
                _POOL.put_nowait(available[index * 8:(index + 1) * 8])
        self._cpus = await _POOL.get()
        self._slot = True
        try:
            await self._start()
        except BaseException:
            self.setup_diagnostics = ""
            if self.service is not None and self.service.log is not None:
                try:
                    detail = Path(self.service.log.name).read_text(errors="replace")[-12000:]
                    for secret in (self._auth, self._final_auth, self._capability):
                        detail = detail.replace(secret, "[redacted]")
                    self.setup_diagnostics = detail
                except OSError:
                    pass
            await self.close()
            raise

    def _prepare_files(self):
        self.directory = Path(tempfile.mkdtemp(prefix="frontier20-", dir=os.environ.get("FRONTIER_SESSION_ROOT")))
        workspace = self.directory / "app"
        workspace.mkdir()
        self.workspace = workspace
        environment = self.task.task_dir / "environment"
        if self.images.get("agent_app"):
            shutil.copytree(self.images["agent_app"], workspace, dirs_exist_ok=True, symlinks=True)
        for name in _PUBLIC_FILES:
            shutil.copy2(environment / name, workspace / name)
        shutil.copytree(environment / "harbor_app", workspace, dirs_exist_ok=True, symlinks=True)
        for name in _PUBLIC_FILES:
            if name.endswith(".sh"):
                (workspace / name).chmod(0o755)
        for asset in self.images.get("visible_inputs", []) + self.images.get("public_files", []):
            dest = workspace / str(PurePosixPath(asset["destination"]).relative_to("/app"))
            dest.parent.mkdir(parents=True, exist_ok=True)
            source = Path(asset["host_path"])
            if source.is_dir():
                shutil.copytree(source, dest, dirs_exist_ok=True, symlinks=True)
            else:
                shutil.copy2(source, dest)
        private = self.directory / "private"
        private.mkdir(mode=0o700)
        (private / "judge_server.py").write_text(private_judge_source(
            (environment / "judge_server.py").read_text(), self._auth, self._final_auth))
        (private / "problem_evaluator.py").write_text(private_evaluator_source(
            self.task.problem_id, (environment / "problem_evaluator.py").read_text()))
        shutil.copy2(environment / "task_config.json", private / "task_config.json")
        for path in private.iterdir():
            path.chmod(0o600)
        logs = self.directory / "judge-logs"
        logs.mkdir(mode=0o700)
        mounts = [(private / name, "/judge/" + name, True)
                  for name in ("judge_server.py", "problem_evaluator.py", "task_config.json")]
        mounts.append((logs, "/logs/judge", False))
        mounts.extend((Path(item["host_path"]), item["destination"], True)
                      for item in self.images.get("private_mounts", []))
        for index, item in enumerate(self.images.get("private_copies", [])):
            # Disk ANN loads and deletes its small truth/baseline files before
            # executing candidates. Keep the large index shared and immutable.
            destination = self.directory / f"private-assets-{index}"
            source = Path(item["host_path"])
            if source.is_dir():
                shutil.copytree(source, destination)
            else:
                shutil.copy2(source, destination)
            mounts.append((destination, item["destination"], False))
        # LWE's public catalog and library are required by the evaluator too.
        public = environment / "harbor_app/public"
        if public.exists():
            mounts.append((public, "/judge/harbor/app/public", True))
        return workspace, mounts

    async def _start(self):
        # Copying a source checkout must not stall other episodes or the
        # memory monitors. Await completion before cancellation cleanup.
        preparation = asyncio.create_task(asyncio.to_thread(self._prepare_files))
        await finish_cleanup(preparation)
        workspace, mounts = preparation.result()
        cpus = self._cpus[:int(self.requirements["judge_resources"]["cpus"])]
        available = tuple(sorted(os.sched_getaffinity(0)))
        agent_available = available[48:]
        if len(agent_available) < len(cpus):
            raise InfrastructureError("No independent agent CPU range remains beyond judge cores")
        slot_index = (available.index(self._cpus[0]) - 16) // 8
        agent_start = (slot_index * 8) % max(1, len(agent_available) - len(cpus) + 1)
        agent_cpus = agent_available[agent_start:agent_start + len(cpus)]
        reservation = reserve_port()
        port = reservation.getsockname()[1]
        self.judge_url = f"http://127.0.0.1:{port}"
        self.judge = Sandbox(self.images["judge_image"], mounts=mounts,
                             env={"PORT": str(port), "JUDGE_TIMEOUT_SECONDS": str(int(self.timeout))},
                             cpus=cpus, workdir="/judge",
                             memory_limit_bytes=int(self.requirements["judge_resources"]["memory_mb"]) * 1024 ** 2)
        try:
            await self.judge.start()
        finally:
            reservation.close()
        self.service = Service(self.judge, "python3 /judge/judge_server.py")
        await self.service.start()
        await self._wait_ready()
        app = web.Application(client_max_size=_MAX_SUBMISSION_BYTES)
        app.router.add_route("*", "/{capability}/{tail:.*}", self._proxy_request)
        self.proxy = web.AppRunner(app, access_log=None)
        await self.proxy.setup()
        reservation = reserve_port()
        proxy_port = reservation.getsockname()[1]
        await web.SockSite(self.proxy, reservation).start()
        self.agent = Sandbox(self.images["agent_image"], mounts=[(workspace, "/app", False)],
                             env={"JUDGE_URL": f"http://127.0.0.1:{proxy_port}/{self._capability}",
                                  "JUDGE_TIMEOUT_SECONDS": str(int(self.timeout))},
                             cpus=agent_cpus, workdir="/app",
                             memory_limit_bytes=int(self.requirements["agent_resources"]["memory_mb"]) * 1024 ** 2)
        await self.agent.start()

    async def _request(self, path, *, payload=None, final=False, timeout=None):
        headers = {"Authorization": "Bearer " + self._auth}
        if final:
            headers["X-Frontier-CS-Role-Token"] = self._final_auth
        return await request_json(self.judge_url + path, method="POST" if payload is not None else "GET",
                                  json=payload, headers=headers, timeout=timeout or self.timeout)

    async def _wait_ready(self):
        import aiohttp
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            if not self.service.alive():
                raise InfrastructureError("Frontier-CS 2.0 judge exited during setup")
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5), trust_env=False) as client:
                    async with client.get(self.judge_url + "/health",
                                          headers={"Authorization": "Bearer " + self._auth}) as response:
                        if response.status not in {200, 503}:
                            raise InfrastructureError("Frontier-CS judge health endpoint rejected authentication")
                        health = await response.json()
            except (aiohttp.ClientError, TimeoutError, ValueError):
                await asyncio.sleep(1)
                continue
            if health.get("ready") is True and health.get("status") == "ok":
                return
            if health.get("status") == "error":
                raise InfrastructureError("Frontier-CS 2.0 judge preparation failed")
            await asyncio.sleep(1)
        raise InfrastructureError("Frontier-CS 2.0 judge preparation timed out")

    async def _proxy_request(self, request):
        if not secrets.compare_digest(request.match_info["capability"], self._capability):
            raise web.HTTPNotFound()
        path = "/" + request.match_info["tail"]
        allowed = (request.method == "GET" and
                   (path in {"/health", "/submissions"} or re.fullmatch(r"/submission/[A-Za-z0-9-]+", path)))
        allowed = allowed or (request.method == "POST" and
                              (path == "/submit" or re.fullmatch(r"/submission/[A-Za-z0-9-]+/cancel", path)))
        if not allowed or self._final:
            raise web.HTTPForbidden()
        try:
            payload = await request.json() if request.method == "POST" else None
        except (ValueError, UnicodeError):
            raise web.HTTPBadRequest(text="Expected a JSON submission") from None
        if path == "/submit" and (not isinstance(payload, dict) or payload.get("submission_role", "agent") != "agent"):
            raise web.HTTPForbidden()
        import aiohttp
        # Preserve 202/429/404 status codes expected by official submit helpers.
        async with self._submission_lock:
            if self._final:
                raise web.HTTPForbidden()
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout), trust_env=False) as client:
                async with client.request(request.method, self.judge_url + path, json=payload,
                                          headers={"Authorization": "Bearer " + self._auth}) as response:
                    body = await response.json()
                    return web.json_response(body, status=response.status)

    async def run(self, command, timeout=None, stdin_data=None):
        if self.agent is None:
            raise InfrastructureError("Frontier-CS agent workspace is not started")
        return await self.agent.run(command, timeout=timeout, stdin_data=stdin_data)

    async def _wait_submissions(self):
        deadline = time.monotonic() + self.timeout
        while True:
            records = (await self._request("/submissions", timeout=30)).get("submissions", [])
            pending = [r for r in records if r.get("status") in {"queued", "running", "cancelling"}]
            if not pending:
                return records
            if time.monotonic() >= deadline:
                raise InfrastructureError("Timed out waiting for Frontier-CS iterative evaluations")
            await asyncio.sleep(1)

    async def evaluate(self, submission_path=None, *, final):
        if final:
            # Let accepted proxy requests finish enqueueing before freezing
            # history; the final wait then sees every accepted submission.
            async with self._submission_lock:
                self._final = True
        config = self.task.config.get("submission", {})
        try:
            snapshot = asyncio.create_task(asyncio.to_thread(
                artifact_payload, self.workspace, submission_path or self.task.submission_path,
                config, final=final))
            await finish_cleanup(snapshot)
            payload = snapshot.result()
        except (ValueError, UnicodeError, FileNotFoundError, PermissionError) as exc:
            payload = None
            absent = str(exc)
        else:
            absent = "Submission artifact is missing or empty"
        if not final:
            if payload is None:
                return EvaluationResult(0.0, absent)
            await self._request("/submit", payload=payload)
            records = await self._wait_submissions()
            result = next((r for r in records if r.get("submission_uuid") == payload["submission_uuid"]), None)
            if result is None:
                raise InfrastructureError("Frontier-CS iterative result is missing")
            return checked_result(result)
        records = await self._wait_submissions()
        candidates, errors = [], []
        if payload is not None:
            try:
                candidates.append((False, checked_result(await self._request("/evaluate", payload=payload, final=True))))
            except InfrastructureError as exc:
                errors.append(exc)
        if any(r.get("submission_role", "agent") == "agent" and r.get("status") == "done" for r in records):
            try:
                best = await self._request("/evaluate_best", payload={"submission_uuid": str(uuid.uuid4()),
                                           "submission_role": "final"}, final=True)
                candidates.append((True, checked_result(best)))
            except InfrastructureError as exc:
                errors.append(exc)
        if errors:
            # A failed full-suite evaluation could have won. Returning the
            # other score would silently bias policy reward downwards.
            raise InfrastructureError("Frontier-CS full-suite evaluation was incomplete")
        if not candidates:
            if any(r.get("status") == "error" for r in records):
                raise InfrastructureError("Frontier-CS final evaluations failed")
            return EvaluationResult(0.0, absent)
        used_best, result = max(candidates, key=lambda c: (c[1].score, c[1].metadata["score_unbounded"]))
        return EvaluationResult(result.score, result.feedback, metadata={**result.metadata,
                                "used_best_agent_artifact": used_best,
                                "alternate_evaluation_errors": len(errors)})

    async def close(self):
        errors = []
        try:
            for operation in (
                self.proxy.cleanup if self.proxy is not None else None,
                self.service.close if self.service is not None else None,
            ):
                if operation is not None:
                    try:
                        await operation()
                    except Exception as exc:
                        errors.append(exc)
            for sandbox in (self.agent, self.judge):
                if sandbox is not None:
                    try:
                        await sandbox.close()
                    except Exception as exc:
                        errors.append(exc)
        finally:
            if self.directory is not None:
                shutil.rmtree(self.directory, ignore_errors=True)
            if self._slot:
                self._slot = False
                _POOL.put_nowait(self._cpus)
        if errors:
            raise InfrastructureError("Frontier-CS container cleanup failed") from errors[0]
