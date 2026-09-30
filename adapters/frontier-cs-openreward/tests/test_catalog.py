"""Contract tests against the pinned official adapters; no Docker/GPU execution."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from frontier_cs_openreward.catalog import (
    TaskCatalog, UnsupportedTaskError, load_catalog, require_full_harness,
    task_requirements,
    _verify_source_pin,
)
from frontier_cs_openreward.contracts import InfrastructureError

SOURCE = Path(os.environ.get("FRONTIER_CS_TEST_ROOT", Path(__file__).resolve().parents[3]))


class CatalogContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.cache = Path(cls.temporary.name)
        cls.catalog = load_catalog(SOURCE, materialized_root=cls.cache)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_selected_scope_preserves_every_algorithmic_and_cpu_task(self):
        self.assertEqual(len(self.catalog.tasks), 201)
        self.assertEqual(sum(t.suite == "algorithmic" for t in self.catalog.tasks), 188)
        self.assertEqual(sum(t.suite == "2.0" for t in self.catalog.tasks), 13)
        self.assertEqual(sum(t.config.get("type") == "interactive" for t in self.catalog.tasks), 74)
        self.assertEqual(len(self.catalog.materialization_manifest["excluded_tasks"]), 8)

    def test_explicit_gpu_research_or_forged_task_request_fails(self):
        for task_id in ["2.0/knn_gpu_kernel_optimization", "research/flash_attn", "algorithmic/../../secret"]:
            with self.subTest(task_id=task_id), self.assertRaises(UnsupportedTaskError):
                load_catalog(SOURCE, materialized_root=self.cache, task_ids=[task_id])
        with self.assertRaises(UnsupportedTaskError):
            load_catalog(SOURCE, materialized_root=self.cache, suites=["research"])

    def test_contexts_keep_official_prompt_and_submission_contracts(self):
        for task_id, kind, path in [
            ("algorithmic/0", "file", "/app/solution.cpp"),
            ("2.0/erdos_demo", "file", "/app/solution.py"),
            ("2.0/vector_db_ann", "directory", "/app"),
            ("2.0/duckdb_e2e_query_optimization", "file", "/app/solution.patch"),
            ("2.0/lwe_structured_recovery", "file", "/app/solution.json"),
        ]:
            with self.subTest(task_id=task_id):
                task = self.catalog.get(task_id)
                self.assertEqual((task.submission_kind, task.submission_path), (kind, path))
                self.assertEqual(task.prompt, (task.task_dir / "instruction.md").read_text())

    def test_agent_context_does_not_copy_judge_internals(self):
        task = self.catalog.get("2.0/duckdb_e2e_query_optimization")
        dockerfile = (task.task_dir / "environment/Dockerfile").read_text().replace("\\\n", " ")
        copies = [line for line in dockerfile.splitlines() if line.startswith("COPY ")]
        self.assertTrue(copies)
        for source in ["problem_evaluator.py", "task_config.json", "config.yaml", "judge_server.py"]:
            self.assertFalse(any(source in line.split() for line in copies), source)
        self.assertTrue((task.task_dir / "environment/problem_evaluator.py").is_file())
        self.assertTrue((task.task_dir / "environment/task_config.json").is_file())

    def test_native_reward_timeouts_and_large_asset_requirements(self):
        ordinary = task_requirements(self.catalog.get("algorithmic/0"))
        self.assertEqual(ordinary["reward"]["divisor"], 100)
        self.assertEqual(ordinary["verifier_timeout_seconds"], 760)
        self.assertTrue(ordinary["requires_privileged_judge"])
        disk = task_requirements(self.catalog.get("2.0/vector_db_ann_disk"))
        self.assertEqual(disk["data_payload_lower_bound_bytes"], 12_800_000_000)
        self.assertIn("/data/private_100M/truth.bin", disk["required_judge_paths"])
        duckdb = task_requirements(self.catalog.get("2.0/duckdb_e2e_query_optimization"))
        self.assertIn("/opt/duckdb-clean", duckdb["required_judge_paths"])
        self.assertEqual(duckdb["smoke_fallback_metric"], "full_benchmark")

    def test_reject_smoke_credit_but_keep_genuine_zero_quality(self):
        for result in [
            {"score": 1, "message": "patch policy smoke passed; GPU harness not available"},
            {"score": 1, "metrics": {"full_benchmark": 0}},
            {"score": 1, "metrics": {"serving_harness": "unconfigured"}},
            {"score": 20, "metrics": {"smoke_only": True}},
        ]:
            with self.subTest(result=result), self.assertRaises(InfrastructureError):
                require_full_harness(result)
        require_full_harness({"score": 0, "message": "patch validation failed", "metrics": {"patch_valid": False}})
        require_full_harness({"score": 42, "metrics": {"full_benchmark": 1}})

    def test_cached_context_is_not_rewritten_and_wrong_pin_fails(self):
        task = self.catalog.get("2.0/erdos_demo")
        judge = task.task_dir / "environment/judge_server.py"
        contents, modified = judge.read_bytes(), judge.stat().st_mtime_ns
        subset = load_catalog(SOURCE, materialized_root=self.cache, task_ids=[task.task_id])
        self.assertEqual(len(subset.tasks), 1)
        self.assertEqual(judge.read_bytes(), contents)
        self.assertEqual(judge.stat().st_mtime_ns, modified)
        with self.assertRaises(ValueError):
            load_catalog(SOURCE, materialized_root=self.cache, expected_revision="wrong")
        marker = task.task_dir / ".openreward-source.json"
        original = marker.read_text()
        try:
            marker.write_text(json.dumps({"revision": "wrong", "task_id": task.task_id}))
            with self.assertRaises(ValueError):
                load_catalog(SOURCE, materialized_root=self.cache, task_ids=[task.task_id])
        finally:
            marker.write_text(original)

    def test_catalog_rejects_duplicate_or_unknown_ids(self):
        task = self.catalog.get("algorithmic/0")
        with self.assertRaises(ValueError):
            TaskCatalog([task, task])
        with self.assertRaises(KeyError):
            self.catalog.get("not-present")

    def test_integration_commit_does_not_change_benchmark_pin(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def git(*args):
                return subprocess.check_output(
                    ["git", "-C", str(root), "-c", "user.name=Catalog Tests", "-c",
                     "user.email=catalog-tests@example.invalid", *args], text=True,
                    stderr=subprocess.DEVNULL,
                ).strip()

            git("init")
            (root / "algorithmic").mkdir()
            statement = root / "algorithmic/statement.txt"
            statement.write_text("Pinned benchmark input")
            git("add", ".")
            git("commit", "-m", "Pinned inputs")
            revision = git("rev-parse", "HEAD")
            (root / "integration.py").write_text("# New integration outside benchmark paths")
            git("add", ".")
            git("commit", "-m", "Add integration")
            _verify_source_pin(root, revision)
            statement.write_text("Changed benchmark input")
            with self.assertRaises(ValueError):
                _verify_source_pin(root, revision)


if __name__ == "__main__":
    unittest.main()
