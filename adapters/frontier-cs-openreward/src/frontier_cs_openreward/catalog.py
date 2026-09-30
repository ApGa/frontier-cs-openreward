"""Pinned task discovery and official Harbor-context materialization.

The catalog is operator metadata. Only task IDs and the public prompt should be
sent to agents; ``config``, requirements and generated tests are judge-private.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tomllib
from typing import Any, Sequence

import yaml

from .contracts import InfrastructureError, TaskRecord

UPSTREAM_REVISION = "ede1b44d2fe22a65320c5e36b1014b3defc03671"
_ADAPTERS = {
    "algorithmic": ("frontier-cs-algorithm", "frontier_cs_algorithm", "FrontierCSAdapter"),
    "2.0": ("frontier-cs-2.0", "frontier_cs_2_0", "FrontierCS20Adapter"),
}
_PINNED_PATHS = ("algorithmic", "2.0", "adapters/frontier-cs-algorithm", "adapters/frontier-cs-2.0")


class UnsupportedTaskError(ValueError):
    pass


class TaskCatalog:
    def __init__(self, tasks: Sequence[TaskRecord], *, materialization_manifest: dict | None = None):
        self.tasks = tuple(tasks)
        self._by_id = {task.task_id: task for task in self.tasks}
        if len(self._by_id) != len(self.tasks):
            raise ValueError("Duplicate Frontier-CS task IDs")
        self.materialization_manifest = materialization_manifest or {}

    def get(self, task_id: str) -> TaskRecord:
        try:
            return self._by_id[task_id]
        except KeyError:
            raise KeyError(f"Unknown or unavailable Frontier-CS task: {task_id}") from None


def _official_adapter(root: Path, suite: str):
    directory, package, _ = _ADAPTERS[suite]
    package_dir = root / "adapters" / directory / "src" / package
    # Give each checkout a distinct package namespace; do not alter sys.path or
    # accidentally reuse an adapter imported from another upstream revision.
    name = "_frontier_official_" + hashlib.sha256(str(package_dir).encode()).hexdigest()[:16]
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            name, package_dir / "__init__.py", submodule_search_locations=[str(package_dir)]
        )
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot load official adapter from {package_dir}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


def _cpu_exclusion(config: dict[str, Any]) -> str | None:
    runtime = config.get("runtime", {}) or {}
    docker = runtime.get("docker", {}) or {}
    resources = runtime.get("resources", {}) or {}
    environment = config.get("environment", {}) or {}
    evaluation = config.get("evaluation", {}) or {}
    if "modal" in runtime.get("judge_pip_packages", []):
        return "Remote Modal GPU evaluation is outside the local CPU task set"
    if (docker.get("gpu") or runtime.get("requires_gpu") or resources.get("accelerators")
            or environment.get("gpus") or evaluation.get("gpu")):
        return "GPU evaluation is outside the local CPU task set"
    if docker.get("dind"):
        return "Nested Docker evaluation is outside the local CPU task set"
    return None


def _verify_source_pin(root: Path, revision: str) -> None:
    """Allow integration-only commits while keeping benchmark inputs pinned."""
    ancestor = subprocess.run(
        ["git", "-C", str(root), "merge-base", "--is-ancestor", revision, "HEAD"],
        capture_output=True, text=True,
    )
    if ancestor.returncode != 0:
        raise ValueError(f"Frontier-CS checkout does not contain pinned revision {revision}")
    changed = subprocess.check_output(
        ["git", "-C", str(root), "diff", "--name-only", revision, "--", *_PINNED_PATHS], text=True,
    ).splitlines()
    untracked = subprocess.check_output(
        ["git", "-C", str(root), "ls-files", "--others", "--exclude-standard", "--", *_PINNED_PATHS], text=True,
    ).splitlines()
    if changed or untracked:
        raise ValueError(f"Benchmark files differ from pinned revision {revision}: {(changed + untracked)[:5]}")


def _asset_requirements(task: TaskRecord) -> tuple[list[str], list[str], int | None]:
    problem = task.problem_id
    if task.suite == "algorithmic":
        return [f"/app/problems/{problem}/config.yaml", f"/app/problems/{problem}/testdata"], [], None
    if problem.startswith("bboplace_"):
        suite = "iccad2015" if problem.endswith("iccad2015") else "ispd2005"
        return ["/opt/bboplace-bench/src", "/opt/bboplace-bench/config", f"/opt/bboplace-bench/benchmarks/{suite}"], ["numpy"], None
    if problem == "duckdb_e2e_query_optimization":
        return ["/opt/duckdb-clean", "/opt/duckdb-vanilla"], [], None
    if problem == "rocksdb_native_compaction_policy":
        return ["/opt/rocksdb-clean", "/opt/rocksdb-vanilla", "/judge/harness/lsm_policy_harness.cc"], [], None
    if problem == "generals_io_bot":
        return ["/opt/generals-agent-clean"], ["generals", "jax"], None
    if problem == "vector_db_ann_disk":
        return [
            "/data/index_100M/100M.u8bin", "/data/index_100M/100M_disk.index",
            "/data/index_100M/100M_pq_pivots.bin", "/data/index_100M/100M_pq_compressed.bin",
            "/data/index_100M/query.bin", "/data/private_100M/truth.bin", "/data/private_100M/baseline.json",
        ], ["numpy", "faiss"], 100_000_000 * 128
    if problem in {"vector_db_ann", "vector_db_ann_relaxed"}:
        return [], ["numpy", "faiss"], 1_000_000 * 128 * 4
    return [], [], None


def task_requirements(task: TaskRecord) -> dict[str, Any]:
    """Return deployment/preflight requirements, without claiming readiness."""
    runtime = task.config.get("runtime", {}) or {}
    docker = runtime.get("docker", {}) or {}
    environment = task.config.get("environment", {}) or {}
    generated = {}
    if task.task_dir is not None:
        generated = tomllib.loads((task.task_dir / "task.toml").read_text())
    default_env = {"cpus": 2, "memory_mb": 4096, "storage_mb": 4096, "gpus": 0}
    agent_resources = {**default_env, **environment, **generated.get("environment", {})}
    judge_paths, modules, data_bytes = _asset_requirements(task)
    timeout = generated.get("verifier", {}).get("timeout_sec", runtime.get("timeout_seconds", 10800))
    source_bytes = sum(p.stat().st_size for p in task.problem_dir.rglob("*") if p.is_file())
    return {
        "task_id": task.task_id, "suite": task.suite, "problem_id": task.problem_id,
        "harbor_task_dir": str(task.task_dir) if task.task_dir else None,
        "source_bytes": source_bytes,
        "agent_base_image": "ubuntu:24.04" if task.suite == "algorithmic" else docker.get("image", "ubuntu:24.04"),
        "judge_base_image": "ubuntu:22.04" if task.suite == "algorithmic" else docker.get("judge_image", docker.get("image", "ubuntu:24.04")),
        "agent_resources": agent_resources,
        "judge_resources": ({"workers": 8, "go_judge_parallelism": 8, "shm_mb": 4096}
                            if task.suite == "algorithmic" else
                            {"cpus": int(environment.get("cpus", 2)), "memory_mb": int(environment.get("memory_mb", 4096))}),
        "requires_privileged_judge": task.suite == "algorithmic",
        "required_judge_paths": judge_paths, "required_judge_python_modules": modules,
        "visible_inputs": runtime.get("visible_inputs", []),
        "apt_packages": runtime.get("apt_packages", []),
        "judge_apt_packages": runtime.get("judge_apt_packages", []),
        "judge_pip_packages": runtime.get("judge_pip_packages", []),
        "data_payload_lower_bound_bytes": data_bytes,
        "image_size_bytes": None,
        "image_size_note": "Measure built/pulled image; declared agent storage excludes judge assets and indexes.",
        "agent_timeout_seconds": generated.get("agent", {}).get("timeout_sec", max(10800, timeout)),
        "verifier_timeout_seconds": timeout,
        "submission": {"kind": task.submission_kind, "path": task.submission_path},
        "reward": {"native_range": [0, 100], "normalized_range": [0, 1], "divisor": 100,
                   "final_rule": "max(final_score, best_iterative_score)" if task.suite == "algorithmic" else "max(final_artifact_full_suite, best_iterative_artifact_full_suite)"},
        "preflight_required": True, "reject_smoke_only_results": True,
        "smoke_fallback_metric": "full_benchmark" if task.problem_id == "duckdb_e2e_query_optimization" else None,
    }


def require_full_harness(result: dict[str, Any]) -> None:
    """Reject upstream CI-only smoke credit before converting it to RL reward.

    Ordinary invalid candidate/patch scores remain valid zero rewards. This
    check is additional to runtime transport/setup/status failure handling.
    """
    metrics = result.get("metrics", {}) or {}
    message = str(result.get("message", "")).lower()
    if ("patch policy smoke passed" in message or metrics.get("full_benchmark") == 0
            or metrics.get("serving_harness") == "unconfigured"
            or metrics.get("gpu_harness") == "unavailable"
            or metrics.get("smoke_only") is True):
        raise InfrastructureError("Frontier-CS full evaluation harness is unavailable; smoke credit is not a reward")


def _load_catalog(
    root: Path, *, materialized_root: Path | None = None,
    task_ids: Sequence[str] | None = None, suites: Sequence[str] = ("algorithmic", "2.0"),
    expected_revision: str = UPSTREAM_REVISION,
) -> TaskCatalog:
    """Materialize official task contexts and return the local CPU catalog.

    IDs are ``algorithmic/0`` and ``2.0/erdos_demo``. Explicitly requested
    unsupported IDs fail rather than disappearing from a training dataset.
    Contexts are cached only when their source pin and problem ID match.
    """
    root = Path(root).resolve()
    unknown_suites = set(suites) - _ADAPTERS.keys()
    if unknown_suites:
        raise UnsupportedTaskError(f"Unsupported suites: {sorted(unknown_suites)}")
    _verify_source_pin(root, expected_revision)
    revision = expected_revision
    destination = Path(materialized_root) if materialized_root else root / ".frontier-cs/openreward-tasks"
    requested = set(task_ids) if task_ids is not None else None
    candidates, excluded = [], {}
    adapters = {}
    for suite in suites:
        module = _official_adapter(root, suite)
        adapters[suite] = getattr(module, _ADAPTERS[suite][2])(root, destination / suite)
        for problem in module.discover_problems(root):
            task_id = f"{suite}/{problem.problem_id}"
            config = yaml.safe_load((problem.problem_dir / "config.yaml").read_text()) or {}
            reason = _cpu_exclusion(config) if suite == "2.0" else None
            if reason:
                excluded[task_id] = reason
                continue
            candidates.append((suite, problem, config, task_id))
    available = {row[3] for row in candidates}
    if requested is not None:
        unavailable = requested - available
        if unavailable:
            reasons = {key: excluded.get(key, "Unknown task or excluded suite") for key in sorted(unavailable)}
            raise UnsupportedTaskError(f"Requested tasks unavailable: {reasons}")
        candidates = [row for row in candidates if row[3] in requested]
    destination.mkdir(parents=True, exist_ok=True)
    records = []
    for suite, problem, config, task_id in candidates:
        harbor_id = f"frontier-cs-algorithm-{problem.problem_id}" if suite == "algorithmic" else problem.task_id
        task_dir = destination / suite / harbor_id
        marker = task_dir / ".openreward-source.json"
        origin = {"revision": revision, "task_id": task_id}
        if task_dir.exists():
            if not marker.is_file() or json.loads(marker.read_text()) != origin:
                raise ValueError(f"Existing context has no matching source pin: {task_dir}")
        else:
            adapters[suite].generate_task(problem)
            marker.write_text(json.dumps(origin, indent=2) + "\n")
        for required in ["instruction.md", "task.toml", "environment/docker-compose.yaml", "tests/evaluate.py"]:
            if not (task_dir / required).is_file():
                raise ValueError(f"Incomplete generated context: {task_dir / required}")
        submission = config.get("submission", {}) or {}
        records.append(TaskRecord(
            task_id=task_id, suite=suite, problem_id=str(problem.problem_id),
            problem_dir=problem.problem_dir, prompt=(task_dir / "instruction.md").read_text(),
            submission_path=submission.get("path", "/app/solution.cpp" if suite == "algorithmic" else "/app/solution.py"),
            submission_kind=submission.get("kind", "file"), config=config, task_dir=task_dir,
        ))
    manifest = {
        "revision": revision, "source_root": str(root), "materialized_root": str(destination),
        "task_count": len(records), "excluded_tasks": excluded,
        "excluded_suites": {"research": "Original research is outside the selected algorithmic + local CPU2.0 scope"},
        "tasks": [task_requirements(task) for task in records],
    }
    temporary = destination / ".catalog.json.tmp"
    temporary.write_text(json.dumps(manifest, indent=2) + "\n")
    temporary.replace(destination / "catalog.json")
    return TaskCatalog(records, materialization_manifest=manifest)


def load_catalog(
    root: Path, *, materialized_root: Path | None = None,
    task_ids: Sequence[str] | None = None, suites: Sequence[str] = ("algorithmic", "2.0"),
    expected_revision: str = UPSTREAM_REVISION,
) -> TaskCatalog:
    """Load/cache the official CPU task contexts under a cross-process lock."""
    destination = Path(materialized_root) if materialized_root else Path(root) / ".frontier-cs/openreward-tasks"
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (destination / ".catalog.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return _load_catalog(
            root, materialized_root=destination, task_ids=task_ids,
            suites=suites, expected_revision=expected_revision,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--task-id", action="append")
    args = parser.parse_args()
    catalog = load_catalog(args.source, materialized_root=args.output, task_ids=args.task_id)
    print(json.dumps({"tasks": len(catalog.tasks), "manifest": str(args.output / "catalog.json")}))


if __name__ == "__main__":
    main()
