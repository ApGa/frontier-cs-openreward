"""Shared private algorithmic judge and episode-scoped submission proxies."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import importlib.util
import json
import math
import os
from pathlib import Path
import secrets
import shlex
import time
import tomllib

from aiohttp import web

from .contracts import EvaluationResult, InfrastructureError, TaskRecord
from .runtime import HostService, Sandbox, Service, finish_cleanup, request_json, reserve_port

MAX_CODE_BYTES = 10_000_000

_GOJUDGE_STATUS_GUARD = '''
function frontierCheckResults(results) {
    if (!Array.isArray(results) || !results.length) {
        throw new Error('Frontier-CS judge infrastructure: malformed result');
    }
    for (const result of results) {
        if (!result || typeof result.status !== 'string' ||
            ['Internal Error', 'System Error', 'Runner Error'].includes(result.status)) {
            throw new Error('Frontier-CS judge infrastructure: invalid execution result');
        }
    }
    return results;
}
'''


def guard_gojudge_statuses(source):
    """Keep go-judge setup failures out of ordinary compile/wrong-answer zeros."""
    replacements = {
        "return data[0];": "return frontierCheckResults(data)[0];",
        "return data;\n    }\n\n    // Delete file":
            "return frontierCheckResults(data);\n    }\n\n    // Delete file",
    }
    for original, replacement in replacements.items():
        if source.count(original) != 1:
            raise InfrastructureError("Unexpected pinned GoJudgeClient layout")
        source = source.replace(original, replacement, 1)
    return _GOJUDGE_STATUS_GUARD + source


def bound_submission_storage(source):
    """Publish only complete results, then remove their private disk artifact.

    The authenticated controller consumes each result once and retains only
    sanitized feedback, so completed source/test-output trees need not persist.
    """
    for name in ("final", "err"):
        original = (f"this.results.set(sid, {name});\n"
                    f"            await fs.writeFile(path.join(subDir, 'result.json'), JSON.stringify({name}, null, 2));")
        if source.count(original) != 2:
            raise InfrastructureError("Unexpected pinned judge result publication layout")
        # saveOutputs is disabled by this runtime. Finishing the final write
        # before publishing removes the writer/deletion race in upstream.
        replacement = (f"await fs.writeFile(path.join(subDir, 'result.json'), JSON.stringify({name}, null, 2));\n"
                       "            await fs.rm(subDir, { recursive: true, force: true });\n"
                       f"            this.results.set(sid, {name});")
        source = source.replace(original, replacement)
    return source


def sanitize_grade(raw, sid, sanitizer):
    if raw.get("status") == "error":
        # The upstream engine uses the same status for invalid candidate C++
        # and broken infrastructure. Only candidate compilation is a zero.
        error = str(raw.get("error", ""))
        if error.startswith("Error: compile failed:"):
            return {"status": "done", "score": 0.0, "score_unbounded": 0.0,
                    "message": "Candidate compilation failed", "metrics": {"sid": sid}}
        raise InfrastructureError("Algorithmic judge could not grade the submission")
    if raw.get("status") != "done":
        raise InfrastructureError("Algorithmic judge returned an incomplete result")
    score = raw.get("score")
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score) or not 0 <= score <= 100:
        raise InfrastructureError("Algorithmic judge returned an invalid score")
    return sanitizer(raw, sid)


class AlgorithmicPool:
    def __init__(self, images, source_root):
        self.images = images
        self.source_root = Path(source_root)
        self.lock = asyncio.Lock()
        concurrency = int(os.getenv("FRONTIER_ALGORITHMIC_CONCURRENCY",
                                    os.getenv("FRONTIER_JUDGE_CONCURRENCY", "4")))
        if concurrency < 1:
            raise ValueError("Algorithmic judge concurrency must be positive")
        self.semaphore = asyncio.Semaphore(concurrency)
        self.sandbox = None
        self.services = []
        self.runner = None
        self.sessions = {}
        self.base_url = None
        self.proxy_url = None
        self.token = None

    async def start(self):
        async with self.lock:
            if self.services and all(service.alive() for service in self.services):
                return
            await self._close_engine()
            self.token = secrets.token_urlsafe(32)
            go_token = secrets.token_urlsafe(32)
            # Holding both sockets avoids selecting the same port twice.
            ports = [reserve_port(), reserve_port()]
            node_port, go_port = [sock.getsockname()[1] for sock in ports]
            cpu_set = tuple(sorted(os.sched_getaffinity(0)))[:16]
            self.sandbox = Sandbox(
                self.images["judge_image"],
                mounts=[(self.source_root / "algorithmic/problems", "/app/problems", True)],
                env={"PORT": str(node_port), "GJ_ADDR": f"http://127.0.0.1:{go_port}",
                     "FRONTIER_ENGINE_AUTH_TOKEN": self.token, "GJ_AUTH_TOKEN": go_token,
                     "JUDGE_WORKERS": "4", "SAVE_OUTPUTS": "false"}, cpus=cpu_set,
            )
            try:
                await self.sandbox.start()
                client = self.sandbox.backend.writable_rootfs_path / "app/src/gojudge.js"
                client.write_text(guard_gojudge_statuses(client.read_text()))
                engine = self.sandbox.backend.writable_rootfs_path / "app/src/judge_engine.js"
                engine.write_text(bound_submission_storage(engine.read_text()))
                for sock in ports:
                    sock.close()
                native_mounts = self._native_mount_config()
                file_store = self.sandbox.backend.session_dir / "gojudge-files"
                file_store.mkdir(mode=0o700)
                go_args = [self.images["go_judge_binary"], "-http-addr", f"127.0.0.1:{go_port}",
                           "-auth-token", go_token, "-silent", "-parallelism", "8",
                           "-mount-conf", str(native_mounts), "-dir", str(file_store)]
                self.services = [
                    HostService(self.sandbox, go_args, expected_sha256=self.images["go_judge_sha256"]),
                    Service(self.sandbox, "exec node /app/server.js"),
                ]
                await self.services[0].start()
                await self.services[1].start()
                self.base_url = f"http://127.0.0.1:{node_port}"
                deadline = time.monotonic() + 120
                while True:
                    if not all(service.alive() for service in self.services):
                        raise InfrastructureError("Algorithmic judge exited during startup")
                    try:
                        await request_json(self.base_url + "/problems", headers=self.headers, timeout=5)
                        break
                    except InfrastructureError:
                        if time.monotonic() >= deadline:
                            raise
                        await asyncio.sleep(1)
                if self.runner is None:
                    app = web.Application(client_max_size=MAX_CODE_BYTES + 100_000)
                    app.router.add_route("*", "/{session}/{operation}", self._proxy_request)
                    self.runner = web.AppRunner(app, access_log=None)
                    await self.runner.setup()
                    site = web.TCPSite(self.runner, "127.0.0.1", 0)
                    await site.start()
                    port = self.runner.addresses[0][1]
                    self.proxy_url = f"http://127.0.0.1:{port}"
            except BaseException:
                for sock in ports:
                    sock.close()
                await self._close_engine()
                raise

    def _native_mount_config(self):
        root = self.sandbox.backend.writable_rootfs_path.resolve(strict=True)
        original = self.images.get("go_judge_mount_config", "/usr/local/share/frontiercs/gojudge-mount.yaml")
        config = json.loads((root / original.lstrip("/")).read_text())
        for entry in config["mount"]:
            if entry.get("type") == "bind" and not entry["source"].startswith("/dev/"):
                relative = Path(entry["source"]).relative_to("/")
                if ".." in relative.parts:
                    raise InfrastructureError("Invalid go-judge toolchain mount")
                entry["source"] = str(root / relative)
        destination = self.sandbox.backend.session_dir / "native-gojudge-mount.json"
        destination.write_text(json.dumps(config))
        destination.chmod(0o600)
        return destination

    @property
    def headers(self):
        return {"Authorization": "Bearer " + self.token}

    async def _close_engine(self):
        services, self.services = self.services, []
        sandbox, self.sandbox = self.sandbox, None
        failures = await asyncio.gather(*(service.close() for service in reversed(services)),
                                        return_exceptions=True)
        try:
            if sandbox is not None:
                await sandbox.close()
        finally:
            for failure in failures:
                if isinstance(failure, BaseException):
                    raise failure

    async def _invalidate_engine(self, base_url):
        async with self.lock:
            if self.base_url == base_url:
                # Node has no per-submission cancellation API. An uncertain or
                # expired grading request must stop its engine generation
                # before its concurrency slot can be reused.
                await self._close_engine()

    async def close(self):
        if self.runner is not None:
            await self.runner.cleanup()
            self.runner = None
        await self._close_engine()

    async def _proxy_request(self, request):
        session = self.sessions.get(request.match_info["session"])
        if session is None or session.closed:
            raise web.HTTPNotFound()
        operation = request.match_info["operation"]
        if request.method == "GET" and operation == "health":
            alive = bool(self.services) and all(service.alive() for service in self.services)
            return web.json_response({"status": "ok" if alive else "error", "ready": alive}, status=200 if alive else 503)
        if request.method == "GET" and operation == "submissions":
            return web.json_response({"status": "ok", "submissions": session.records})
        if request.method != "POST" or operation != "evaluate":
            raise web.HTTPNotFound()
        if session.finalized:
            raise web.HTTPConflict(text="Episode has completed")
        try:
            payload = await request.json()
            if not isinstance(payload, dict) or str(payload.get("problem_id", session.task.problem_id)) != session.task.problem_id:
                raise ValueError("Submission must target the current task")
            code = payload.get("code")
            if not isinstance(code, str) or not code.strip() or len(code.encode()) > MAX_CODE_BYTES:
                raise ValueError("Expected nonempty C++ source within the size limit")
            if session.closed or session.finalized:
                raise web.HTTPConflict(text="Episode has completed")
            result = await session.grade(code, role="agent", submission_uuid=str(payload.get("submission_uuid", ""))[:200])
            return web.json_response(result)
        except (ValueError, json.JSONDecodeError) as exc:
            raise web.HTTPBadRequest(text=str(exc)) from exc
        except InfrastructureError:
            session.infrastructure_failed = True
            return web.json_response({"status": "error", "message": "Judge infrastructure unavailable",
                                      "invalid": True, "score": None}, status=503)

    async def grade(self, task, code, sanitizer):
        settings = tomllib.loads((task.task_dir / "task.toml").read_text())
        timeout = float(settings["verifier"]["env"]["MAX_POLL_TIME"])
        if not math.isfinite(timeout) or timeout <= 0:
            raise InfrastructureError("Invalid algorithmic grading budget")
        async with self.semaphore:
            await self.start()
            base_url, headers = self.base_url, self.headers
            try:
                payload = await request_json(base_url + "/submit", method="POST",
                                             data={"pid": task.problem_id, "lang": "cpp", "code": code}, headers=headers)
                sid = payload.get("sid")
                if not isinstance(sid, int) or isinstance(sid, bool):
                    raise InfrastructureError("Algorithmic judge did not return a submission ID")
                # Waiting for a slot is outside the official grading deadline.
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    if (self.base_url != base_url or not self.services
                            or not all(service.alive() for service in self.services)):
                        raise InfrastructureError("Algorithmic judge exited during grading")
                    raw = await request_json(base_url + f"/result/{sid}", headers=headers)
                    if raw.get("status") in ("done", "error"):
                        return sanitize_grade(raw, sid, sanitizer)
                    await asyncio.sleep(0.5)
                raise InfrastructureError("Algorithmic grading exceeded its task-specific budget")
            except BaseException:
                cleanup = asyncio.create_task(self._invalidate_engine(base_url))
                await finish_cleanup(cleanup)
                raise


_READ_SOLUTION = '''import json, sys
from pathlib import Path
path = Path(json.load(sys.stdin)["path"])
try:
    with path.open() as stream:
        code = stream.read(10000001)
    print(json.dumps({"code": code}))
except (OSError, UnicodeError):
    print(json.dumps({"code": ""}))
'''


class AlgorithmicSession:
    def __init__(self, task: TaskRecord, pool: AlgorithmicPool):
        self.task, self.pool = task, pool
        self.session_key = secrets.token_urlsafe(32)
        self.sandbox = None
        self.records = []
        self.best = None
        self.closed = False
        self.finalized = False
        self.infrastructure_failed = False
        self.grade_lock = asyncio.Lock()
        self.pending_grades = set()
        spec = importlib.util.spec_from_file_location("frontier_algorithm_sanitizer", task.task_dir / "environment/judge_proxy.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.sanitize = module.sanitize_result

    async def start(self):
        await self.pool.start()
        self.pool.sessions[self.session_key] = self
        public = self.task.task_dir / "environment"
        mounts = [(public / name, f"/app/{name}", True) for name in
                  ("AGENT.md", "submit.sh", "submit.py", "statement.txt", "config.yaml")]
        self.sandbox = Sandbox(
            self.pool.images["agent_image"], mounts=mounts,
            env={"PROBLEM_ID": self.task.problem_id,
                 "JUDGE_URL": self.pool.proxy_url + "/" + self.session_key,
                 "SUBMIT_MAX_POLL_TIME": "10800"},
        )
        try:
            await self.sandbox.start()
        except BaseException:
            await self.close()
            raise

    async def run(self, command, timeout=None, stdin_data=None):
        if self.closed or self.finalized:
            raise InfrastructureError("Episode has completed")
        return await self.sandbox.run(command, timeout, stdin_data)

    async def _grade(self, code, *, role, submission_uuid=""):
        async with self.grade_lock:
            if self.closed:
                raise InfrastructureError("Episode has closed")
            result = await self.pool.grade(self.task, code, self.sanitize)
            record = {**result, "submission_role": role, "problem_id": self.task.problem_id,
                      "submission_uuid": submission_uuid, "ts": datetime.now(timezone.utc).isoformat()}
            self.records.append(record)
            if role == "agent" and (self.best is None or result["score"] > self.best["score"]):
                self.best = result
            return result

    async def grade(self, code, *, role, submission_uuid=""):
        task = asyncio.create_task(self._grade(code, role=role, submission_uuid=submission_uuid))
        self.pending_grades.add(task)
        def completed(done):
            self.pending_grades.discard(done)
            if not done.cancelled() and done.exception() is not None:
                self.infrastructure_failed = True
        task.add_done_callback(completed)
        # A disconnected submit.sh must not release the shared judge slot while
        # the Node engine is still executing that submission.
        return await asyncio.shield(task)

    async def evaluate(self, submission_path=None, *, final):
        if self.infrastructure_failed:
            raise InfrastructureError("An iterative submission encountered an infrastructure failure")
        if final:
            self.finalized = True
            if self.pending_grades:
                await asyncio.gather(*(asyncio.shield(task) for task in tuple(self.pending_grades)))
        command = "python3 -c " + shlex.quote(_READ_SOLUTION)
        response = await self.sandbox.run(command, timeout=30, stdin_data=json.dumps({
            "path": submission_path or self.task.submission_path,
        }).encode())
        if response.exit_code:
            raise InfrastructureError("Could not read the final submission from its container")
        try:
            code = json.loads(response.output)["code"]
        except (ValueError, KeyError) as exc:
            raise InfrastructureError("Malformed submission snapshot") from exc
        if len(code.encode()) > MAX_CODE_BYTES:
            result = {"score": 0.0, "message": "Submission exceeds size limit"}
        elif code.strip():
            result = await self.grade(code, role="final" if final else "agent")
        else:
            result = {"score": 0.0, "message": "Submission is missing or empty"}
        if final and self.best is not None and self.best["score"] > result["score"]:
            result = {**self.best, "used_best_submission": True}
        return EvaluationResult(float(result["score"]), str(result.get("message", "")), metadata={
            "task_id": self.task.task_id, "suite": self.task.suite,
            "submission_count": len(self.records), "used_best_submission": bool(result.get("used_best_submission")),
            "metrics": result.get("metrics", {}),
        })

    async def close(self):
        self.closed = True
        self.pool.sessions.pop(self.session_key, None)
        if self.sandbox is not None:
            await self.sandbox.close()
