"""Runtime ownership, grading isolation, and infrastructure failure contracts."""

import asyncio
import json
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace

import aiohttp
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
import pytest

from frontier_cs_openreward import algorithmic_runtime as algorithmic
from frontier_cs_openreward import runtime
from frontier_cs_openreward.contracts import CommandResult, InfrastructureError, TaskRecord


@pytest.fixture
def task(tmp_path):
    context = tmp_path / "task"
    (context / "environment").mkdir(parents=True)
    original = (Path(__file__).resolve().parents[3] / "adapters/frontier-cs-algorithm/src/"
                "frontier_cs_algorithm/task-template/environment/judge_proxy.py")
    (context / "environment/judge_proxy.py").write_bytes(original.read_bytes())
    (context / "task.toml").write_text('[verifier.env]\nMAX_POLL_TIME="10"\n')
    return TaskRecord("algorithmic/0", "algorithmic", "0", tmp_path / "problem", "Prompt",
                      "/app/solution.cpp", task_dir=context)


class FakeSandbox:
    def __init__(self, code="current solution"):
        self.code = code
        self.closed = 0

    async def run(self, command, timeout=None, stdin_data=None):
        return CommandResult(json.dumps({"code": self.code}), 0)

    async def close(self):
        self.closed += 1


def ready_pool(monkeypatch, *, concurrency=1):
    monkeypatch.setenv("FRONTIER_JUDGE_CONCURRENCY", str(concurrency))
    monkeypatch.delenv("FRONTIER_ALGORITHMIC_CONCURRENCY", raising=False)
    pool = algorithmic.AlgorithmicPool({}, Path("/unused"))
    pool.base_url = "http://private-engine"
    pool.token = "private-engine-token"
    pool.services = [SimpleNamespace(alive=lambda: True)]

    async def start():
        pass

    pool.start = start
    return pool


def make_session(task, pool, *, code="current solution"):
    session = algorithmic.AlgorithmicSession(task, pool)
    session.sandbox = FakeSandbox(code)
    pool.sessions[session.session_key] = session
    return session


def test_sanitizer_keeps_scores_but_hides_test_contents(task, monkeypatch):
    session = make_session(task, ready_pool(monkeypatch))
    raw = {"status": "done", "score": 12.5, "scoreUnbounded": 20,
           "result": "Wrong Answer", "cases": [{"scoreRatio": 0, "input": "HIDDEN INPUT"}],
           "error": "private diagnostic", "code": "OTHER SESSION CODE"}
    result = algorithmic.sanitize_grade(raw, 7, session.sanitize)
    assert result["score"] == 12.5 and result["score_unbounded"] == 20
    assert result["metrics"]["total_cases"] == 1
    assert "HIDDEN" not in json.dumps(result) and "OTHER SESSION" not in json.dumps(result)


@pytest.mark.parametrize("error,valid_zero", [
    ("Error: compile failed: expected ';'", True),
    ("Error: checker compile failed: missing library", False),
    ("Error: interactor compile failed: missing library", False),
    ("Error: connect ECONNREFUSED", False),
])
def test_only_candidate_compilation_failure_is_valid_zero(task, monkeypatch, error, valid_zero):
    session = make_session(task, ready_pool(monkeypatch))
    if valid_zero:
        result = algorithmic.sanitize_grade({"status": "error", "error": error}, 1, session.sanitize)
        assert result["score"] == 0 and result["status"] == "done"
    else:
        with pytest.raises(InfrastructureError):
            algorithmic.sanitize_grade({"status": "error", "error": error}, 1, session.sanitize)


def test_cancelled_public_caller_keeps_judge_slot_until_completion(task, monkeypatch):
    async def check():
        pool = ready_pool(monkeypatch)
        session, other = make_session(task, pool), make_session(task, pool)
        submitted, finish = asyncio.Event(), asyncio.Event()
        submissions = []

        async def request(url, **kwargs):
            if url.endswith("/submit"):
                assert kwargs["headers"] == {"Authorization": "Bearer private-engine-token"}
                submissions.append(kwargs["data"])
                return {"sid": len(submissions)}
            submitted.set()
            await finish.wait()
            return {"status": "done", "score": 40}

        monkeypatch.setattr(algorithmic, "request_json", request)
        caller = asyncio.create_task(session.grade("first", role="agent"))
        await submitted.wait()
        caller.cancel()
        with pytest.raises(asyncio.CancelledError):
            await caller
        second = asyncio.create_task(other.grade("second", role="agent"))
        await asyncio.sleep(0)
        assert pool.semaphore.locked() and len(submissions) == 1
        assert len(session.pending_grades) == 1
        finish.set()
        assert (await second)["score"] == 40
        assert [item["code"] for item in submissions] == ["first", "second"]
        assert not pool.semaphore.locked()

    asyncio.run(check())


def test_final_waits_for_inflight_submission_before_selecting_best(task, monkeypatch):
    async def check():
        pool = ready_pool(monkeypatch)
        session = make_session(task, pool, code="weaker final")
        started, finish = asyncio.Event(), asyncio.Event()
        calls = []

        async def grade(task, code, sanitizer):
            calls.append(code)
            if code == "better public":
                started.set()
                await finish.wait()
            return {"score": 90 if code == "better public" else 20, "status": "done"}

        pool.grade = grade
        public = asyncio.create_task(session.grade("better public", role="agent"))
        await started.wait()
        final = asyncio.create_task(session.evaluate(final=True))
        await asyncio.sleep(0)
        assert session.finalized and not final.done() and calls == ["better public"]
        finish.set()
        result = await final
        await public
        assert result.score == 90 and result.metadata["used_best_submission"]
        assert calls == ["better public", "weaker final"]
        assert [record["submission_role"] for record in session.records] == ["agent", "final"]

    asyncio.run(check())


def test_uncertain_engine_is_stopped_before_concurrency_slot_is_reused(task, monkeypatch):
    async def check():
        pool = ready_pool(monkeypatch)
        session = make_session(task, pool)
        closing, stopped = asyncio.Event(), asyncio.Event()

        async def request(url, **kwargs):
            if url.endswith("/submit"):
                return {"sid": 1}
            raise InfrastructureError("connection lost while engine still running")

        async def close_engine():
            closing.set()
            await stopped.wait()
            pool.services = []

        pool._close_engine = close_engine
        monkeypatch.setattr(algorithmic, "request_json", request)
        grade = asyncio.create_task(pool.grade(task, "code", session.sanitize))
        await closing.wait()
        assert pool.semaphore.locked()
        grade.cancel()
        await asyncio.sleep(0)
        assert not grade.done() and pool.semaphore.locked()
        stopped.set()
        with pytest.raises(asyncio.CancelledError):
            await grade
        assert not pool.semaphore.locked() and not pool.services

    asyncio.run(check())


def test_grading_deadline_stops_engine_instead_of_leaking_running_work(task, monkeypatch):
    (task.task_dir / "task.toml").write_text('[verifier.env]\nMAX_POLL_TIME="0.01"\n')

    async def check():
        pool = ready_pool(monkeypatch)
        session = make_session(task, pool)
        closed = []

        async def request(url, **kwargs):
            return {"sid": 1} if url.endswith("/submit") else {"status": "running"}

        async def close_engine():
            closed.append(True)
            pool.services = []

        pool._close_engine = close_engine
        monkeypatch.setattr(algorithmic, "request_json", request)
        with pytest.raises(InfrastructureError, match="budget"):
            await pool.grade(task, "code", session.sanitize)
        assert closed == [True] and not pool.semaphore.locked()

    asyncio.run(check())


def test_proxy_isolates_records_tasks_and_finalization(task, monkeypatch):
    async def check():
        pool = ready_pool(monkeypatch)
        first, second = make_session(task, pool), make_session(task, pool)

        async def grade(task, code, sanitizer):
            return {"status": "done", "score": 60, "message": "sanitized"}

        pool.grade = grade
        app = web.Application()
        app.router.add_route("*", "/{session}/{operation}", pool._proxy_request)
        async with TestClient(TestServer(app)) as client:
            response = await client.post(f"/{first.session_key}/evaluate", json={"code": "C++"})
            assert response.status == 200 and (await response.json())["score"] == 60
            own = await client.get(f"/{first.session_key}/submissions")
            other = await client.get(f"/{second.session_key}/submissions")
            assert len((await own.json())["submissions"]) == 1
            assert (await other.json())["submissions"] == []
            forged = await client.post(f"/{second.session_key}/evaluate",
                                       json={"code": "C++", "problem_id": "999"})
            assert forged.status == 400
            assert (await client.get("/unknown/submissions")).status == 404
            first.finalized = True
            late = await client.post(f"/{first.session_key}/evaluate", json={"code": "late"})
            assert late.status == 409 and not first.infrastructure_failed
            await second.close()
            assert (await client.get(f"/{second.session_key}/submissions")).status == 404

    asyncio.run(check())


def test_proxy_rechecks_finalization_after_receiving_request_body(task, monkeypatch):
    async def check():
        pool = ready_pool(monkeypatch)
        session = make_session(task, pool)

        async def receive_body():
            session.finalized = True
            return {"code": "too late"}

        request = SimpleNamespace(match_info={"session": session.session_key, "operation": "evaluate"},
                                  method="POST", json=receive_body)
        with pytest.raises(web.HTTPConflict):
            await pool._proxy_request(request)
        assert not session.pending_grades and not session.infrastructure_failed

    asyncio.run(check())


def test_service_cancelled_cleanup_reaps_process_and_closes_log(tmp_path, monkeypatch):
    async def check():
        waiting, stopped = asyncio.Event(), asyncio.Event()
        signals = []

        class Process:
            pid = 123456789
            returncode = None

            async def wait(self):
                waiting.set()
                await stopped.wait()
                self.returncode = 0

        service = runtime.Service(None, "unused")
        service.process = Process()
        service.log = (tmp_path / "service.log").open("wb")
        monkeypatch.setattr(runtime.os, "killpg", lambda pid, sig: signals.append((pid, sig)))
        closing = asyncio.create_task(service.close())
        await waiting.wait()
        closing.cancel()
        await asyncio.sleep(0)
        assert not closing.done() and not service.log.closed
        stopped.set()
        with pytest.raises(asyncio.CancelledError):
            await closing
        await service.close()
        assert service.log.closed and len(signals) == 1

    asyncio.run(check())


def test_service_start_failure_closes_unique_log(tmp_path, monkeypatch):
    backend = SimpleNamespace(session_dir=tmp_path, _exec_args=lambda command: ["false"],
                              _instance_environment=lambda: {})

    async def cannot_start(*args, **kwargs):
        raise OSError("spawn failed")

    monkeypatch.setattr(runtime.asyncio, "create_subprocess_exec", cannot_start)
    service = runtime.Service(SimpleNamespace(backend=backend), "unused")
    with pytest.raises(OSError, match="spawn failed"):
        asyncio.run(service.start())
    assert service.log.closed and len(list(tmp_path.glob("service-*.log"))) == 1


def test_transport_error_does_not_expose_capability_token(monkeypatch):
    class BrokenClient:
        def __init__(self, **kwargs):
            assert kwargs["trust_env"] is False

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        def request(self, *args, **kwargs):
            raise aiohttp.ClientConnectionError("http://judge/SECRET-CAPABILITY/evaluate unavailable")

    monkeypatch.setattr(aiohttp, "ClientSession", BrokenClient)
    with pytest.raises(InfrastructureError) as result:
        asyncio.run(runtime.request_json("http://judge/SECRET-CAPABILITY/evaluate"))
    assert "SECRET-CAPABILITY" not in str(result.value)


def test_private_container_environment_is_stable_and_not_world_readable(tmp_path, monkeypatch):
    class Backend:
        def __init__(self, image):
            self.session_dir = tmp_path

    monkeypatch.setattr(runtime, "_backend_module", lambda: SimpleNamespace(SingularitySandbox=Backend))
    sandbox = runtime.Sandbox("unused", env={"AUTH_TOKEN": "secret-token"})
    path = Path(sandbox.backend._environment_file())
    modified = path.stat().st_mtime_ns
    assert path.read_text() == "AUTH_TOKEN=secret-token\n"
    assert path.stat().st_mode & 0o777 == 0o600
    assert sandbox.backend._environment_file() == str(path)
    assert path.stat().st_mtime_ns == modified


def test_manifest_must_pass_preflight_before_runtime_factory(tmp_path, monkeypatch):
    manifest = tmp_path / "images.json"
    manifest.write_text(json.dumps({"version": 1, "ready": False}))
    monkeypatch.setenv("FRONTIER_IMAGE_MANIFEST", str(manifest))
    monkeypatch.setenv("FRONTIER_SOURCE_ROOT", str(tmp_path))
    with pytest.raises(InfrastructureError, match="preflight"):
        runtime.create_runtime_factory()


def test_two_reserved_ports_are_distinct():
    first, second = runtime.reserve_port(), runtime.reserve_port()
    try:
        assert first.getsockname()[1] != second.getsockname()[1]
    finally:
        first.close()
        second.close()


def test_local_sif_uses_validation_and_never_pulls_as_oci(tmp_path, monkeypatch):
    image = tmp_path / "image.sif"
    image.write_bytes(b"fake SIF for validator test")
    validated = []

    class Backend:
        def __init__(self, image):
            pass

        async def _sif_is_valid(self, path):
            validated.append(path)
            return True

        async def _ensure_image(self):
            raise AssertionError("Local SIF reached OCI pull")

    monkeypatch.setattr(runtime, "_backend_module", lambda: SimpleNamespace(SingularitySandbox=Backend))
    for reference in (str(image), "file://" + str(image)):
        sandbox = runtime.Sandbox(reference)
        assert asyncio.run(sandbox.backend._ensure_image()) == image
    assert validated == [image, image]


def test_private_bind_placeholders_exist_before_writable_start(tmp_path, monkeypatch):
    root = tmp_path / "rootfs"
    root.mkdir()
    source = tmp_path / "source.py"
    source.write_text("# judge")
    source_dir = tmp_path / "data"
    source_dir.mkdir()

    class Backend:
        def __init__(self, image):
            self.writable_rootfs_path = root

        async def _create_writable_directory(self):
            pass

    monkeypatch.setattr(runtime, "_backend_module", lambda: SimpleNamespace(SingularitySandbox=Backend))
    sandbox = runtime.Sandbox("image", mounts=[(source, "/judge/judge.py", True),
                                               (source_dir, "/data/public", True)])
    asyncio.run(sandbox.backend._create_writable_directory())
    assert (root / "judge/judge.py").is_file() and (root / "data/public").is_dir()
    assert (root / "etc/resolv.conf").is_file()
    assert (Path("/etc/resolv.conf"), "/etc/resolv.conf", True) in sandbox.mounts
    (root / "escape").symlink_to(tmp_path, target_is_directory=True)
    escaped = runtime.Sandbox("image", mounts=[(source, "/escape/wrong.py", True)])
    with pytest.raises(ValueError, match="symlink"):
        asyncio.run(escaped.backend._create_writable_directory())
    assert not (tmp_path / "wrong.py").exists()


def test_pss_guard_cancels_and_reaps_command_before_reporting_limit(monkeypatch):
    async def check():
        started, cleaned = asyncio.Event(), asyncio.Event()

        async def command():
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                cleaned.set()

        monkeypatch.setattr(runtime, "process_tree_pss_bytes", lambda pid: 1025)
        with pytest.raises(runtime.MemoryLimitExceeded, match="PSS"):
            await runtime._guard_memory(command(), 123, 1024)
        assert started.is_set() and cleaned.is_set()

    asyncio.run(check())


def test_status_guard_is_applied_to_both_single_and_interactive_runs():
    original = (Path(__file__).resolve().parents[3] / "algorithmic/judge/src/gojudge.js").read_text()
    patched = algorithmic.guard_gojudge_statuses(original)
    assert "return frontierCheckResults(data)[0]" in patched
    assert "return frontierCheckResults(data);" in patched
    with pytest.raises(InfrastructureError, match="layout"):
        algorithmic.guard_gojudge_statuses(patched)


def test_native_service_has_owned_marker_and_cleans_process_group(tmp_path, monkeypatch):
    monkeypatch.setenv("FRONTIER_SESSION_ROOT", str(tmp_path))
    session = tmp_path / "session"
    (session / "tmp").mkdir(parents=True)
    executable = Path("/usr/bin/sleep").resolve()
    sandbox = SimpleNamespace(backend=SimpleNamespace(session_dir=session), cpus=(), memory_limit_bytes=0)
    service = runtime.HostService(sandbox, [str(executable), "30"],
                                  expected_sha256=hashlib.sha256(executable.read_bytes()).hexdigest())

    async def check():
        await service.start()
        try:
            record = json.loads(service.marker.read_text())
            assert record["pid"] == record["pgid"] == service.process.pid
            assert record["uid"] == os.getuid() and record["executable"] == str(executable)
            assert service.marker.stat().st_mode & 0o777 == 0o600
            environment = Path(f"/proc/{service.process.pid}/environ").read_bytes()
            assert b"FRONTIER_NATIVE_SERVICE_ID=" + service.service_id.encode() in environment
            assert b"WANDB_API_KEY" not in environment and b"HF_TOKEN" not in environment
        finally:
            await service.close()
        assert not service.marker.exists() and not service.alive()

    asyncio.run(check())


def test_unreadable_supervisor_uses_rss_without_ignoring_memory(tmp_path, monkeypatch, caplog):
    process = tmp_path / "1234567"
    process.mkdir()
    (process / "status").write_text("Name:\tstarter-suid\nVmRSS:\t123 kB\n")
    read_text = Path.read_text

    def read(path, *args, **kwargs):
        if path == process / "smaps_rollup":
            raise PermissionError("Non-dumpable supervisor")
        return read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    assert runtime._resident_bytes(process) == 123 * 1024
    assert "frontier_memory_accounting_fallback" in caplog.text


def test_memory_sample_ignores_exited_process_without_losing_live_memory(monkeypatch):
    """A /proc entry can vanish between discovery and reading smaps_rollup."""
    def resident(process):
        if process.name == "987654321":
            raise ProcessLookupError("Process exited during memory sampling")
        return 8192

    monkeypatch.setattr(runtime, "_resident_bytes", resident)
    monkeypatch.setattr(Path, "iterdir", lambda path: iter(()))
    assert runtime.process_tree_pss_bytes((987654321, 987654322)) == 8192


def test_finish_cleanup_returns_preparation_result():
    async def check():
        async def prepare():
            await asyncio.sleep(0)
            return "workspace", ["mount"]

        assert await runtime.finish_cleanup(asyncio.create_task(prepare())) == ("workspace", ["mount"])

    asyncio.run(check())


def test_factory_refuses_an_unready_task_despite_selected_manifest_ready(task):
    factory = runtime.FrontierRuntimeFactory({"ready": True, "algorithmic": {"ready": False}}, Path("/unused"))
    with pytest.raises(InfrastructureError, match="preflight"):
        factory.create(task)


def test_submission_storage_patch_publishes_only_after_complete_write():
    original = (Path(__file__).resolve().parents[3] / "algorithmic/judge/src/judge_engine.js").read_text()
    patched = algorithmic.bound_submission_storage(original)
    assert patched.count("await fs.rm(subDir, { recursive: true, force: true });") == 4
    assert patched.index("await fs.rm(subDir") < patched.index("this.results.set(sid, final)")
