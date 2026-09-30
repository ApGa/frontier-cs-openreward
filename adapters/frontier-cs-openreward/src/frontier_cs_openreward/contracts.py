"""Boundary between the OpenReward frontend and its isolated task runtime."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol


@dataclass(frozen=True)
class TaskRecord:
    task_id: str
    suite: str
    problem_id: str
    problem_dir: Path
    prompt: str
    submission_path: str
    submission_kind: str = "file"
    config: dict[str, Any] = field(default_factory=dict)
    workdir: str = "/app"
    task_dir: Path | None = None


@dataclass(frozen=True)
class CommandResult:
    output: str
    exit_code: int


@dataclass(frozen=True)
class EvaluationResult:
    """Native bounded score, or an invalid infrastructure outcome.

    The runtime owns submission history and upstream final-mode semantics.
    In particular, final evaluation must re-evaluate the appropriate artifact;
    the frontend never substitutes a cached public-submission score.
    """

    score: float | None
    feedback: str = ""
    invalid: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


class InfrastructureError(RuntimeError):
    """The runtime could not execute or grade the task reliably."""


class RuntimeSession(Protocol):
    async def start(self) -> None: ...

    async def run(
        self,
        command: str,
        timeout: float | None = None,
        stdin_data: bytes | None = None,
    ) -> CommandResult: ...

    async def evaluate(
        self, submission_path: str | None = None, *, final: bool
    ) -> EvaluationResult: ...

    async def close(self) -> None: ...


class RuntimeFactory(Protocol):
    def create(self, task: TaskRecord) -> RuntimeSession:
        """Construct a session; allocate resources only inside start()."""
        ...

    async def close(self) -> None:
        """Release shared services after all episode sessions have closed."""
        ...
