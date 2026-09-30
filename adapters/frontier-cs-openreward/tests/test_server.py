"""Frontend contract tests without a container engine or an external judge."""

import asyncio
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
import httpx
from openreward.environments import Server

from frontier_cs_openreward.contracts import (
    CommandResult, EvaluationResult, InfrastructureError, TaskRecord,
)
from frontier_cs_openreward.server import (
    BashInput, CreateFileInput, EvaluationInput, StrReplaceInput, ViewInput, build_environment, main,
)


class FakeRuntime:
    def __init__(self, evaluations=(), *, local_commands=False):
        self.evaluations = iter(evaluations)
        self.local_commands = local_commands
        self.evaluation_calls = []
        self.command_calls = []
        self.started = False
        self.closed = 0
        self.start_error = None
        self.command_result = CommandResult("ok", 0)

    async def start(self):
        self.started = True
        if self.start_error:
            raise self.start_error

    async def run(self, command, timeout=None, stdin_data=None):
        self.command_calls.append((command, timeout, stdin_data))
        if self.local_commands:
            process = await asyncio.create_subprocess_shell(
                command, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            stdout, _ = await process.communicate(stdin_data)
            return CommandResult(stdout.decode(), process.returncode)
        if isinstance(self.command_result, Exception):
            raise self.command_result
        return self.command_result

    async def evaluate(self, submission_path=None, *, final):
        self.evaluation_calls.append((submission_path, final))
        await asyncio.sleep(0)
        result = next(self.evaluations)
        if isinstance(result, Exception):
            raise result
        return result

    async def close(self):
        await asyncio.sleep(0)
        self.closed += 1


class FakeFactory:
    def __init__(self, runtime):
        self.runtime = runtime
        self.tasks = []

    def create(self, task):
        self.tasks.append(task)
        return self.runtime

    async def close(self):
        pass


@pytest.fixture
def task(tmp_path):
    return TaskRecord(
        task_id="algorithmic/0", suite="algorithmic", problem_id="0",
        problem_dir=tmp_path / "private-problem", prompt="Solve the public problem.",
        submission_path="/app/solution.cpp", config={"hidden_test_path": "/private/tests"},
        task_dir=tmp_path / "private-context",
    )


def make_env(task, runtime=None, **kwargs):
    runtime = runtime or FakeRuntime()
    factory = FakeFactory(runtime)
    cls = build_environment(SimpleNamespace(tasks=(task,)), factory, suite=task.suite, **kwargs)
    return cls({"task_id": task.task_id}), factory


def content(output):
    return "\n".join(block.text for block in output.blocks)


def test_public_catalog_and_runtime_use_authoritative_task(task):
    runtime = FakeRuntime()
    factory = FakeFactory(runtime)
    second = replace(task, task_id="2.0/demo", suite="2.0")
    catalog = SimpleNamespace(tasks=(task, second))
    algorithmic = build_environment(catalog, factory, suite="algorithmic")
    v2 = build_environment(catalog, factory, suite="2.0")

    async def check():
        assert await algorithmic.get_task("train", 0) == {"task_id": "algorithmic/0"}
        assert await v2.get_task("train", 0) == {"task_id": "2.0/demo"}
        assert await algorithmic.num_tasks("train") == 1

    asyncio.run(check())
    assert algorithmic.name() == "frontier_cs_algorithmic"
    assert v2.name() == "frontier_cs_2_0"
    env = algorithmic({"task_id": task.task_id, "problem_dir": "/attacker", "config": {}})
    assert factory.tasks[-1] is task
    prompt = "\n".join(block.text for block in env.get_prompt())
    assert task.prompt in prompt and task.submission_path in prompt
    assert "hidden_test_path" not in prompt and str(task.problem_dir) not in prompt
    with pytest.raises(ValueError, match="Unknown task_id"):
        algorithmic({"task_id": "algorithmic/missing"})
    with pytest.raises(ValueError, match="Unknown split"):
        algorithmic.list_tasks("test")


def test_openreward_tool_discovery_and_input_dispatch(task):
    env, _ = make_env(task, FakeRuntime([EvaluationResult(25)]))
    tools = {spec.name: spec for spec in type(env).list_tools().tools}
    assert set(tools) == {"bash", "view", "create_file", "str_replace", "evaluate",
                          "submit_answer", "claim_done"}
    routing = tools["submit_answer"].input_schema["x-openhands-tool-routing"]
    assert routing["capabilities"] == ["task.submit"]

    async def check():
        valid = await env._call_tool("submit_answer", {})
        assert valid.root.output.reward == 0.25
        invalid = await env._call_tool("view", {"path": "/tmp/a", "view_range": [0, 5]})
        assert "validation error" in invalid.root.error

    asyncio.run(check())


@pytest.mark.parametrize("description", [{}, {"description": ""}, {"description": None}])
@pytest.mark.parametrize("tool_name", ["bash", "view"])
def test_ignored_description_allows_omission_empty_or_mcp_null(task, tmp_path, description, tool_name):
    """The MCP bridge fills omitted optional arguments with None."""
    env, _ = make_env(task, FakeRuntime(local_commands=True))
    path = tmp_path / "input.txt"
    path.write_text("CONTENT_OK\n")
    required = {"command": "printf CONTENT_OK"} if tool_name == "bash" else {"path": str(path)}

    async def check():
        result = await env._call_tool(tool_name, {**required, **description})
        assert "CONTENT_OK" in content(result.root.output)
        missing_required = await env._call_tool(tool_name, description)
        assert "validation error" in missing_required.root.error

    asyncio.run(check())


def test_both_environment_names_work_through_openreward_http(task):
    second = replace(task, task_id="2.0/demo", suite="2.0")
    catalog = SimpleNamespace(tasks=(task, second))
    factory = FakeFactory(FakeRuntime())
    classes = [build_environment(catalog, factory, suite=suite) for suite in ("algorithmic", "2.0")]
    server = Server(environments=classes)

    async def check():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=server.app), base_url="http://local"
        ) as client:
            names = (await client.get("/list_environments")).json()
            assert names == ["frontier_cs_algorithmic", "frontier_cs_2_0"]
            for name, expected in zip(names, (task.task_id, second.task_id)):
                tools = await client.get(f"/{name}/tools")
                assert tools.status_code == 200
                assert "submit_answer" in {spec["name"] for spec in tools.json()["tools"]}
                result = await client.post(f"/{name}/task", json={"split": "train", "index": 0})
                assert result.status_code == 200 and result.json()["task"] == {"task_id": expected}

    asyncio.run(check())
    with pytest.raises(ValueError, match="URL path segment"):
        build_environment(catalog, factory, suite="algorithmic", name="frontier_cs/algorithmic")


def test_iterative_score_is_feedback_final_runtime_score_is_authoritative(task):
    runtime = FakeRuntime([
        EvaluationResult(90, "public feedback"),
        EvaluationResult(25, "final evaluation", metadata={"unbounded_score": 123.5}),
    ])
    env, _ = make_env(task, runtime)

    async def check():
        public = await env.evaluate(EvaluationInput(submission_path="/app/candidate.cpp"))
        assert public.reward is None and not public.finished
        assert public.metadata["score"] == 90
        final = await env.submit_answer(EvaluationInput())
        assert final.reward == 0.25 and final.finished
        assert final.metadata["unbounded_score"] == 123.5
        assert final.metadata["evaluation_mode"] == "final"
        assert final.metadata["invalid"] is False
        assert await env.claim_done(EvaluationInput()) is final
        assert await env.bash(BashInput(command="echo too-late")) is final

    asyncio.run(check())
    assert runtime.evaluation_calls == [("/app/candidate.cpp", False), (None, True)]
    assert runtime.command_calls == []


def test_zero_is_a_valid_native_score(task):
    env, _ = make_env(task, FakeRuntime([EvaluationResult(0, "Compilation failed")]))
    result = asyncio.run(env.submit_answer(EvaluationInput()))
    assert result.finished and result.reward == 0
    assert result.metadata["ok"] and result.metadata["invalid"] is False


@pytest.mark.parametrize("evaluation", [
    EvaluationResult(None, "judge unavailable", invalid=True, metadata={"judge_stage": "prepare"}),
    InfrastructureError("judge exited unexpectedly"),
    EvaluationResult(None), EvaluationResult(float("nan")),
    EvaluationResult(float("inf")), EvaluationResult(-1), EvaluationResult(101),
    EvaluationResult(True),
])
def test_invalid_judge_results_are_not_trainable_zero(task, evaluation):
    runtime = FakeRuntime([evaluation])
    env, _ = make_env(task, runtime)
    result = asyncio.run(env.submit_answer(EvaluationInput()))
    assert result.finished and result.reward is None
    assert result.metadata["invalid"] is True
    assert result.metadata["failure_class"] == "infrastructure"
    if isinstance(evaluation, EvaluationResult) and evaluation.invalid:
        assert result.metadata["judge_stage"] == "prepare"


def test_command_error_is_feedback_but_runtime_failure_invalidates_episode(task):
    runtime = FakeRuntime()
    env, _ = make_env(task, runtime)

    async def check():
        runtime.command_result = CommandResult("compiler error", 1)
        ordinary = await env.bash(BashInput(command="compile", timeout=12))
        assert not ordinary.finished and ordinary.reward is None
        assert ordinary.metadata["exit_code"] == 1
        assert not ordinary.metadata.get("invalid", False)
        runtime.command_result = InfrastructureError("sandbox disappeared")
        invalid = await env.bash(BashInput(command="compile"))
        assert invalid.finished and invalid.reward is None
        assert invalid.metadata["invalid"]

    asyncio.run(check())
    assert runtime.command_calls[0] == ("compile", 12, None)


def test_concurrent_terminal_aliases_grade_once(task):
    runtime = FakeRuntime([EvaluationResult(60)])
    env, _ = make_env(task, runtime)

    async def check():
        first, second = await asyncio.gather(
            env.submit_answer(EvaluationInput()), env.claim_done(EvaluationInput())
        )
        assert first is second and first.reward == 0.6

    asyncio.run(check())
    assert len(runtime.evaluation_calls) == 1


def test_setup_failure_cleans_allocated_runtime_and_close_is_idempotent(task):
    runtime = FakeRuntime()
    runtime.start_error = InfrastructureError("prepare failed after allocation")
    env, _ = make_env(task, runtime)

    async def check():
        with pytest.raises(InfrastructureError, match="prepare failed"):
            await env.setup()
        await env.teardown()

    asyncio.run(check())
    assert runtime.started and runtime.closed == 1


def test_cancelled_teardown_still_finishes_cleanup(task):
    async def check():
        runtime = FakeRuntime()
        entered, release = asyncio.Event(), asyncio.Event()

        async def slow_close():
            entered.set()
            await release.wait()
            runtime.closed += 1

        runtime.close = slow_close
        env, _ = make_env(task, runtime)
        cleanup = asyncio.create_task(env.teardown())
        await entered.wait()
        cleanup.cancel()
        await asyncio.sleep(0)
        assert not cleanup.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await cleanup
        await env.teardown()
        assert runtime.closed == 1

    asyncio.run(check())


def test_file_tools_treat_shell_metacharacters_as_data_and_replace_uniquely(task, tmp_path):
    runtime = FakeRuntime(local_commands=True)
    env, _ = make_env(task, runtime)
    path = tmp_path / "$(touch hacked) ' file.txt"
    payload = "first\n$HOME `touch hacked`\nlast\n"

    async def check():
        created = await env.create_file(CreateFileInput(path=str(path), file_text=payload))
        assert created.metadata["ok"] and path.read_text() == payload
        viewed = await env.view(ViewInput(path=str(path), view_range=(2, 2)))
        assert "2: $HOME `touch hacked`" in content(viewed)
        assert "1: first" not in content(viewed) and "3: last" not in content(viewed)
        changed = await env.str_replace(StrReplaceInput(
            path=str(path), old_str="first", new_str="last"
        ))
        assert changed.metadata["ok"]
        before = path.read_text()
        ambiguous = await env.str_replace(StrReplaceInput(
            path=str(path), old_str="last", new_str="oops"
        ))
        assert ambiguous.metadata["exit_code"] == 1 and not ambiguous.finished
        assert path.read_text() == before
        missing = await env.str_replace(StrReplaceInput(
            path=str(path), old_str="absent", new_str="oops"
        ))
        assert missing.metadata["exit_code"] == 1 and path.read_text() == before
        directory = await env.view(ViewInput(path=str(tmp_path)))
        assert path.name in content(directory)

    asyncio.run(check())
    assert all(payload not in command for command, _, _ in runtime.command_calls)


def test_bounded_output_has_explicit_truncation(task):
    runtime = FakeRuntime()
    runtime.command_result = CommandResult("HEAD" + "a" * 1000 + "TAIL", 0)
    env, _ = make_env(task, runtime, output_limit=100)
    text = content(asyncio.run(env.bash(BashInput(command="verbose"))))
    assert "HEAD" in text and "TAIL" in text and "truncated" in text
    assert len(text) < 150


def test_duplicate_task_ids_fail_closed(task):
    with pytest.raises(ValueError, match="Duplicate task IDs"):
        build_environment(SimpleNamespace(tasks=(task, task)), FakeFactory(FakeRuntime()),
                          suite=task.suite)


def test_cli_exclusion_is_strict_and_applies_before_serving(task, monkeypatch):
    from frontier_cs_openreward import catalog, server
    import uvicorn

    second = replace(task, task_id="2.0/demo", suite="2.0")
    monkeypatch.setattr(catalog, "load_catalog", lambda *args, **kwargs: catalog.TaskCatalog([task, second]))
    served = []
    started = []

    class FakeServer(Server):
        def __init__(self, environments):
            super().__init__(environments=environments)
            served.extend(environments)

    monkeypatch.setattr(server, "Server", FakeServer)
    monkeypatch.setattr(uvicorn, "run", lambda app, **kwargs: started.append(kwargs))
    monkeypatch.setattr(server.importlib, "import_module", lambda name: SimpleNamespace(
        create_runtime_factory=lambda: FakeFactory(FakeRuntime())
    ))
    main(["--root", "/unused", "--exclude-task-id", "2.0/demo"])
    assert [cls.name() for cls in served] == ["frontier_cs_algorithmic"]
    assert started[0]["loop"] == "asyncio"
    with pytest.raises(SystemExit) as result:
        main(["--root", "/unused", "--exclude-task-id", "2.0/typo"])
    assert result.value.code == 2
