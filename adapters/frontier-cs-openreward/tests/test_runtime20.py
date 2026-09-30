"""Exercise official asynchronous judge and final-rerun semantics over HTTP."""
import asyncio
import ast
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest

import aiohttp
from aiohttp import web

from frontier_cs_openreward.contracts import InfrastructureError, TaskRecord
from frontier_cs_openreward.runtime20 import (
    Frontier20Session, artifact_payload, checked_result, private_judge_source,
    private_evaluator_source,
)

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / 'frontier-cs-2.0/src/frontier_cs_2_0/task-template/environment/judge_server.py'


class ArtifactTests(unittest.TestCase):
    def test_duckdb_allocator_environment_preserves_native_evaluation(self):
        source = (ROOT.parent / '2.0/problems/duckdb_e2e_query_optimization/evaluator.py').read_text()
        adapted = private_evaluator_source('duckdb_e2e_query_optimization', source)
        original_tree, adapted_tree = ast.parse(source), ast.parse(adapted)
        def without_environment(tree):
            return [ast.dump(node) for node in tree.body
                    if not isinstance(node, ast.FunctionDef) or node.name not in {'clean_env', 'evaluate'}]
        self.assertEqual(without_environment(original_tree), without_environment(adapted_tree))
        clean_env = next(node for node in adapted_tree.body
                         if isinstance(node, ast.FunctionDef) and node.name == 'clean_env')
        namespace = {'Path': Path}
        exec(compile(ast.Module(body=[clean_env], type_ignores=[]), '<clean_env>', 'exec'), namespace)
        with tempfile.TemporaryDirectory() as name:
            env = namespace['clean_env'](Path(name))
            self.assertEqual(env['MALLOC_ARENA_MAX'], '2')
            self.assertTrue(Path(env['HOME']).is_dir())
            self.assertTrue(Path(env['TMPDIR']).is_dir())
        self.assertEqual(private_evaluator_source('vector_db_ann', source), source)

    def test_duckdb_baseline_failure_is_infrastructure_but_candidate_failure_is_zero(self):
        source = (ROOT.parent / '2.0/problems/duckdb_e2e_query_optimization/evaluator.py').read_text()
        tree = ast.parse(private_evaluator_source('duckdb_e2e_query_optimization', source))
        evaluate = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'evaluate')
        namespace = {'Path': Path, 'Any': object, 'subprocess': subprocess,
                     'validate_patch': lambda path: (True, '', {}),
                     'safe_failed_command': lambda cmd: Path(cmd[0]).name,
                     '_invalid': lambda message, metrics: (0, 0, message, metrics)}
        exec(compile(ast.Module(body=[evaluate], type_ignores=[]), '<evaluate>', 'exec'), namespace)
        def fail(command):
            def run(*args):
                raise subprocess.CalledProcessError(1, [command], stderr='Out of Memory Error')
            return run
        namespace['full_evaluation'] = fail('/opt/duckdb-vanilla/build/release/duckdb')
        with self.assertRaisesRegex(RuntimeError, 'Pristine DuckDB baseline'):
            namespace['evaluate']('/app/solution.patch')
        namespace['full_evaluation'] = fail('/opt/duckdb-clean/build/release/duckdb')
        self.assertEqual(namespace['evaluate']('/app/solution.patch')[0], 0)
        namespace['full_evaluation'] = lambda *args: (73, 73, 'native score', {})
        self.assertEqual(namespace['evaluate']('/app/solution.patch')[0], 73)

    def test_changed_duckdb_environment_contract_fails_closed(self):
        with self.assertRaisesRegex(InfrastructureError, 'anchor changed'):
            private_evaluator_source('duckdb_e2e_query_optimization', 'def clean_env(): return {}')

    def test_workspace_boundary_and_official_directory_exclusions(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            app = root / 'app'
            app.mkdir()
            (root / 'private').write_text('not agent data')
            (app / 'solution.py').symlink_to(root / 'private')
            with self.assertRaisesRegex(ValueError, 'outside'):
                artifact_payload(app, '/app/solution.py', {}, final=True)
            (app / 'solution.py').unlink()
            (app / 'main.rs').write_text('fn main() {}')
            (app / 'target').mkdir()
            (app / 'target/private').symlink_to(root / 'private')
            payload = artifact_payload(app, '/app', {'kind':'directory', 'exclude':['target']}, final=True)
            self.assertEqual(payload['submission_kind'], 'directory')
            self.assertEqual(payload['submission_role'], 'final')
            with self.assertRaisesRegex(ValueError, 'under /app'):
                artifact_payload(app, '/judge/evaluator.py', {}, final=True)

    def test_missing_artifact_and_allow_empty_patch(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.assertIsNone(artifact_payload(root, '/app/no-file', {}, final=True))
            (root / 'solution.patch').write_text('')
            self.assertIsNone(artifact_payload(root, '/app/solution.patch', {}, final=True))
            self.assertEqual(artifact_payload(root, '/app/solution.patch', {'allow_empty':True}, final=True)['code'], '')

    def test_smoke_and_infrastructure_failures_are_never_training_rewards(self):
        for result in (
            {'status':'error', 'score':0},
            {'status':'done', 'score':1, 'metrics':{'full_benchmark':0}},
            {'status':'done', 'score':float('nan')},
            {'status':'done', 'score':101},
        ):
            with self.assertRaises(InfrastructureError):
                checked_result(result)
        self.assertEqual(checked_result({'status':'done','score':0,'message':'invalid candidate'}).score, 0)


class OfficialJudgeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        app = root / 'app'
        app.mkdir()
        task = TaskRecord('2.0/erdos_demo', '2.0', 'erdos_demo', root,
                          'public prompt', '/app/solution.py', config={'runtime':{'timeout_seconds':5}})
        self.session = Frontier20Session(task, {})
        self.session.workspace = app
        self.session.timeout = 5
        self.session._auth = 'private-transport-test'
        self.session._final_auth = 'private-final-test'
        reservation = socket.socket()
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
        self.session.judge_url = f'http://127.0.0.1:{port}'
        source = private_judge_source(TEMPLATE.read_text(), self.session._auth, self.session._final_auth)
        for old, new in (
            ('/judge/problem_evaluator.py', root/'evaluator.py'),
            ('/judge/task_config.json', root/'config.json'),
            ('/logs/judge/', str(root/'logs')+'/'),
        ):
            source = source.replace(old, str(new))
        (root/'judge.py').write_text(source)
        (root/'config.json').write_text('{}')
        (root/'evaluator.py').write_text('''
from pathlib import Path
import os
def evaluate(path):
    code = Path(path).read_text()
    if code == 'BROKEN':
        raise RuntimeError('fixture setup failure')
    score = float(code)
    if os.environ.get('FRONTIER_SUBMISSION_ROLE') == 'final':
        score /= 5
    return score, score, 'fixture score'
''')
        reservation.close()
        self.proc = await asyncio.create_subprocess_exec(
            os.sys.executable, str(root/'judge.py'), env={**os.environ,'PORT':str(port)},
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        for _ in range(100):
            try:
                health = await self.session._request('/health', timeout=1)
                if health.get('ready'):
                    break
            except InfrastructureError:
                pass
            await asyncio.sleep(.02)
        else:
            self.fail('official judge did not start')

    async def asyncTearDown(self):
        if self.proc.returncode is None:
            self.proc.terminate()
        await self.proc.wait()
        self.tmp.cleanup()

    async def test_private_api_requires_authentication(self):
        async with aiohttp.ClientSession() as client:
            async with client.get(self.session.judge_url + '/submissions') as response:
                self.assertEqual(response.status, 401)
        self.assertNotIn('private-transport-test', os.environ.values())

    async def test_final_reruns_best_artifact_instead_of_reusing_public_score(self):
        (self.session.workspace/'solution.py').write_text('75')
        self.assertEqual((await self.session.evaluate(final=False)).score, 75)
        (self.session.workspace/'solution.py').write_text('50')
        result = await self.session.evaluate(final=True)
        self.assertEqual(result.score, 15)
        self.assertTrue(result.metadata['used_best_agent_artifact'])

    async def test_missing_final_can_recover_authoritative_best(self):
        (self.session.workspace/'solution.py').write_text('40')
        await self.session.evaluate(final=False)
        (self.session.workspace/'solution.py').unlink()
        self.assertEqual((await self.session.evaluate(final=True)).score, 8)

    async def test_unavailable_judge_is_invalid_not_a_zero(self):
        (self.session.workspace/'solution.py').write_text('BROKEN')
        with self.assertRaises(InfrastructureError):
            await self.session.evaluate(final=True)

    async def test_broken_current_full_run_does_not_fall_back_to_lower_best(self):
        (self.session.workspace/'solution.py').write_text('40')
        await self.session.evaluate(final=False)
        (self.session.workspace/'solution.py').write_text('BROKEN')
        with self.assertRaisesRegex(InfrastructureError, 'incomplete'):
            await self.session.evaluate(final=True)

    async def test_proxy_refuses_final_routes_and_role_escalation(self):
        app = web.Application()
        app.router.add_route('*', '/{capability}/{tail:.*}', self.session._proxy_request)
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        sock = socket.socket()
        sock.bind(('127.0.0.1',0))
        port = sock.getsockname()[1]
        await web.SockSite(runner, sock).start()
        url = f'http://127.0.0.1:{port}/{self.session._capability}'
        try:
            async with aiohttp.ClientSession() as client:
                async with client.get(url+'/health') as response:
                    self.assertEqual(response.status,200)
                for path in ('/evaluate','/evaluate_best','/submit'):
                    async with client.post(url+path,json={'submission_role':'final'}) as response:
                        self.assertEqual(response.status,403)
                async with client.get(f'http://127.0.0.1:{port}/wrong/health') as response:
                    self.assertEqual(response.status,404)
        finally:
            await runner.cleanup()


if __name__ == '__main__':
    unittest.main()
