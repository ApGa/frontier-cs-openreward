"""OpenReward frontend; task execution and grading belong to the runtime.

OpenReward's class-level get_task serves catalog records. Platoon's MCP bridge
provides the agent-facing get_task tool from get_prompt, avoiding a conflicting
instance tool with the same name.
"""

from __future__ import annotations

import argparse
import asyncio
from contextlib import asynccontextmanager
import functools
import importlib
import json
import math
import os
import re
import shlex
from pathlib import Path
from typing import Any, Protocol, Sequence

from openreward.environments import Environment, Server, tool
from openreward.environments.types import Blocks, JSONObject, ListToolsOutput, TextBlock, ToolOutput
from pydantic import BaseModel, Field, field_validator

from .contracts import EvaluationResult, InfrastructureError, RuntimeFactory, TaskRecord


class Catalog(Protocol):
    tasks: Sequence[TaskRecord]


class BashInput(BaseModel):
    command: str = Field(min_length=1, description="Shell command in the task workspace")
    description: str | None = ""
    timeout: float | None = Field(default=None, gt=0, description="Optional timeout in seconds")


class FileInput(BaseModel):
    path: str = Field(min_length=1, description="Path inside the task environment")
    description: str | None = ""


class CreateFileInput(FileInput):
    file_text: str


class StrReplaceInput(FileInput):
    old_str: str = Field(min_length=1)
    new_str: str = ""


class ViewInput(FileInput):
    view_range: tuple[int, int] | None = None

    @field_validator("view_range")
    @classmethod
    def validate_range(cls, value: tuple[int, int] | None) -> tuple[int, int] | None:
        if value is not None:
            start, end = value
            if start < 1 or (end != -1 and end < start):
                raise ValueError("view_range must be [start>=1, end>=start or -1]")
        return value


class EvaluationInput(BaseModel):
    submission_path: str | None = Field(
        default=None, description="Task submission path; omit to use the task default"
    )


# All agent-provided paths and contents travel on stdin, never in shell code.
_FILE_COMMAND = r'''
import itertools, json, sys
from pathlib import Path
data = json.load(sys.stdin)
path = Path(data["path"])
operation = data["operation"]
try:
    if operation == "create":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data["file_text"], encoding="utf-8")
        print("File written.")
    elif operation == "replace":
        text = path.read_text(encoding="utf-8")
        count = text.count(data["old_str"])
        if count != 1:
            raise ValueError(f"old_str must match exactly once; found {count} matches")
        path.write_text(text.replace(data["old_str"], data["new_str"], 1), encoding="utf-8")
        print("Replacement applied.")
    elif path.is_dir():
        entries = list(itertools.islice(path.iterdir(), 1001))
        for entry in sorted(entries[:1000], key=lambda item: item.name):
            print(entry.name + ("/" if entry.is_dir() else ""))
        if len(entries) > 1000:
            print("[Directory listing truncated at 1000 entries]")
    else:
        limit = data["max_chars"]
        with path.open(encoding="utf-8", errors="replace") as source:
            text = source.read(limit + 1)
        start, end = data.get("view_range") or (1, -1)
        for number, line in enumerate(text[:limit].splitlines(), 1):
            if number >= start and (end == -1 or number <= end):
                print(f"{number}: {line}")
        if len(text) > limit:
            print(f"[File view truncated after {limit} characters]")
except (OSError, ValueError) as error:
    print(f"{type(error).__name__}: {error}")
    sys.exit(1)
'''


def _bounded(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    half = limit // 2
    return f"{text[:half]}\n[Tool output truncated]\n{text[-half:]}"


class FrontierCSEnvironment(Environment):
    """One episode; recursive agents share this same isolated runtime session."""

    _records: dict[str, TaskRecord] = {}
    _factory: RuntimeFactory
    _environment_name = "frontier_cs"
    _output_limit = 50000
    _capabilities = {
        "bash": ["filesystem.read", "filesystem.write", "system.execute", "python.execute"],
        "view": ["filesystem.read"],
        "create_file": ["filesystem.write"],
        "str_replace": ["filesystem.read", "filesystem.write"],
        "evaluate": ["system.execute"],
        "submit_answer": ["task.submit"],
        "claim_done": ["task.submit"],
    }

    @classmethod
    def name(cls) -> str:
        return cls._environment_name

    @classmethod
    def list_splits(cls) -> list[str]:
        return ["train"]

    @classmethod
    def list_tasks(cls, split: str) -> list[JSONObject]:
        if split != "train":
            raise ValueError(f"Unknown split: {split!r}")
        return [{"task_id": task_id} for task_id in cls._records]

    @classmethod
    @functools.cache
    def list_tools(cls) -> ListToolsOutput:
        tools = super().list_tools()
        return ListToolsOutput(tools=[
            spec.model_copy(update={"input_schema": {
                **(spec.input_schema or {"type": "object", "properties": {}}),
                "x-openhands-tool-routing": {
                    "version": 1,
                    "execution_domain": "task",
                    "capabilities": cls._capabilities[spec.name],
                    "invocation": {"kind": "direct"},
                },
            }})
            for spec in tools.tools
        ])

    def __init__(self, task_spec: JSONObject, secrets: dict[str, str] | None = None) -> None:
        super().__init__(task_spec)
        task_id = task_spec.get("task_id")
        if not isinstance(task_id, str) or task_id not in self._records:
            raise ValueError(f"Unknown task_id: {task_id!r}")
        self.task = self._records[task_id]
        self.runtime = self._factory.create(self.task)
        self._terminal_output: ToolOutput | None = None
        self._grading_lock = asyncio.Lock()
        self._close_task: asyncio.Task[None] | None = None

    async def setup(self) -> None:
        try:
            await self.runtime.start()
        except BaseException:
            await self.teardown()
            raise

    async def teardown(self) -> None:
        if self._close_task is None:
            self._close_task = asyncio.create_task(self.runtime.close())
        cancelled = False
        while not self._close_task.done():
            try:
                await asyncio.shield(self._close_task)
            except asyncio.CancelledError:
                cancelled = True
        self._close_task.result()
        if cancelled:
            raise asyncio.CancelledError

    def get_prompt(self) -> Blocks:
        return [TextBlock(text=(
            f"{self.task.prompt}\n\n"
            f"Workspace: `{self.task.workdir}`. Final submission: `{self.task.submission_path}`.\n"
            "Use `evaluate` for non-terminal judge feedback. When your solution is ready, "
            "call `submit_answer` or `claim_done` to finish and receive its final score. "
            "An ordinary assistant message does not submit the solution."
        ))]

    def _output(self, text: str, **kwargs: Any) -> ToolOutput:
        return ToolOutput(blocks=[TextBlock(text=_bounded(text, self._output_limit))], **kwargs)

    def _invalid(
        self, tool_name: str, error: BaseException | str,
        metadata: dict[str, Any] | None = None,
    ) -> ToolOutput:
        output = self._output(
            f"Environment infrastructure failure during {tool_name}: {error}",
            finished=True,
            reward=None,
            metadata={**(metadata or {}), "ok": False, "invalid": True,
                      "failure_class": "infrastructure", "task_id": self.task.task_id,
                      "suite": self.task.suite, "tool": tool_name,
                      "error_type": type(error).__name__},
        )
        self._terminal_output = output
        return output

    async def _run(
        self, tool_name: str, command: str, *, timeout: float | None = None,
        stdin_data: bytes | None = None,
    ) -> ToolOutput:
        if self._terminal_output is not None:
            return self._terminal_output
        try:
            result = await self.runtime.run(command, timeout=timeout, stdin_data=stdin_data)
            return self._output(
                f"{result.output}\nExit code: {result.exit_code}",
                finished=False,
                metadata={"ok": result.exit_code == 0, "exit_code": result.exit_code,
                          "tool": tool_name},
            )
        except Exception as error:
            return self._invalid(tool_name, error)

    @tool
    async def bash(self, input: BashInput) -> ToolOutput:
        """Run a shell command inside this task's workspace."""
        return await self._run("bash", input.command, timeout=input.timeout)

    async def _file_tool(self, name: str, operation: str, input: FileInput) -> ToolOutput:
        data = {**input.model_dump(), "operation": operation, "max_chars": self._output_limit}
        return await self._run(
            name, "python3 -c " + shlex.quote(_FILE_COMMAND),
            stdin_data=json.dumps(data).encode("utf-8"),
        )

    @tool
    async def create_file(self, input: CreateFileInput) -> ToolOutput:
        """Create or overwrite a UTF-8 file inside the task environment."""
        return await self._file_tool("create_file", "create", input)

    @tool
    async def str_replace(self, input: StrReplaceInput) -> ToolOutput:
        """Replace one exact, unique occurrence in a UTF-8 task file."""
        return await self._file_tool("str_replace", "replace", input)

    @tool
    async def view(self, input: ViewInput) -> ToolOutput:
        """View a task file with line numbers or list a directory; output is bounded."""
        return await self._file_tool("view", "view", input)

    async def _evaluate(self, input: EvaluationInput, *, final: bool) -> ToolOutput:
        tool_name = "submit_answer" if final else "evaluate"
        async with self._grading_lock:
            if self._terminal_output is not None:
                return self._terminal_output
            try:
                result: EvaluationResult = await self.runtime.evaluate(
                    input.submission_path, final=final
                )
                if result.invalid:
                    return self._invalid(
                        tool_name, result.feedback or "The judge is unavailable", result.metadata
                    )
                score = result.score
                if (isinstance(score, bool) or not isinstance(score, (int, float))
                        or not math.isfinite(score) or not 0 <= score <= 100):
                    raise InfrastructureError(f"Judge returned an invalid bounded score: {score!r}")
                metadata = {**result.metadata, "ok": True, "invalid": False,
                            "score": float(score),
                            "task_id": self.task.task_id, "suite": self.task.suite,
                            "evaluation_mode": "final" if final else "iterative"}
                # Only terminal grading contributes policy reward. Iterative
                # scores remain feedback, including any higher public score.
                output = self._output(
                    f"{result.feedback}\nScore: {score:g}/100",
                    finished=final, reward=float(score) / 100 if final else None,
                    metadata=metadata,
                )
                if final:
                    self._terminal_output = output
                return output
            except Exception as error:
                return self._invalid(tool_name, error)

    @tool
    async def evaluate(self, input: EvaluationInput) -> ToolOutput:
        """Evaluate a solution for iterative judge feedback without ending the task."""
        return await self._evaluate(input, final=False)

    @tool
    async def submit_answer(self, input: EvaluationInput) -> ToolOutput:
        """Submit the solution for authoritative final grading and end the task."""
        return await self._evaluate(input, final=True)

    @tool
    async def claim_done(self, input: EvaluationInput) -> ToolOutput:
        """Submit the solution for final grading; alias of submit_answer."""
        return await self._evaluate(input, final=True)


def build_environment(
    catalog: Catalog, factory: RuntimeFactory, *, suite: str,
    name: str | None = None, output_limit: int = 50000,
) -> type[FrontierCSEnvironment]:
    if suite not in {"algorithmic", "2.0"}:
        raise ValueError(f"Unknown Frontier-CS suite: {suite!r}")
    selected = [task for task in catalog.tasks if task.suite == suite]
    records = {task.task_id: task for task in selected}
    if len(records) != len(selected):
        raise ValueError(f"Duplicate task IDs in suite {suite!r}")
    if not records:
        raise ValueError(f"No tasks available for suite {suite!r}")
    if output_limit < 100:
        raise ValueError("output_limit must be at least 100 characters")
    environment_name = name or f"frontier_cs_{suite.replace('.', '_')}"
    if not re.fullmatch(r"[a-zA-Z0-9_-]+", environment_name):
        raise ValueError("Environment names must fit one OpenReward URL path segment")
    return type("ConfiguredFrontierCS", (FrontierCSEnvironment,), {
        "_records": records, "_factory": factory, "_output_limit": output_limit,
        "_environment_name": environment_name,
    })


def main(argv: list[str] | None = None) -> None:
    from .catalog import TaskCatalog, load_catalog
    import uvicorn

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=os.getenv("FRONTIER_CS_ROOT"))
    parser.add_argument("--materialized-root", type=Path)
    parser.add_argument("--suite", choices=["all", "algorithmic", "2.0"], default="all")
    parser.add_argument("--task-id", action="append")
    parser.add_argument("--exclude-task-id", action="append", default=[])
    parser.add_argument("--host", default=os.getenv("OPENREWARD_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.getenv("OPENREWARD_PORT", "8085")))
    parser.add_argument("--runtime-factory", default=os.getenv(
        "FRONTIER_RUNTIME_FACTORY", "frontier_cs_openreward.runtime:create_runtime_factory"
    ))
    args = parser.parse_args(argv)
    if args.root is None:
        parser.error("--root or FRONTIER_CS_ROOT is required")
    suites = ("algorithmic", "2.0") if args.suite == "all" else (args.suite,)
    catalog = load_catalog(args.root, materialized_root=args.materialized_root,
                           task_ids=args.task_id, suites=suites)
    excluded = set(args.exclude_task_id)
    unknown = excluded - {task.task_id for task in catalog.tasks}
    if unknown:
        parser.error(f"Excluded tasks are not in the selected catalog: {sorted(unknown)}")
    catalog = TaskCatalog([task for task in catalog.tasks if task.task_id not in excluded])
    module_name, separator, attribute = args.runtime_factory.partition(":")
    if not separator:
        parser.error("--runtime-factory must be module:callable")
    factory = getattr(importlib.import_module(module_name), attribute)()
    environments = [build_environment(catalog, factory, suite=suite) for suite in suites
                    if any(task.suite == suite for task in catalog.tasks)]
    if not environments:
        parser.error("The selected catalog contains no tasks")
    server = Server(environments=environments)
    original_lifespan = server.app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(app):
        try:
            async with original_lifespan(app):
                yield
        finally:
            await factory.close()

    server.app.router.lifespan_context = lifespan
    # uvloop retains the daemonized Singularity instance's stdout pipe on
    # this platform; the standard asyncio loop correctly completes startup.
    uvicorn.run(server.app, host=args.host, port=args.port,
                loop="asyncio", timeout_keep_alive=60, access_log=False)


if __name__ == "__main__":
    main()
