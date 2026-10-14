# Frontier-CS OpenReward adapter

`frontier_cs_openreward` serves Frontier-CS tasks, the algorithmic suite and the local CPU 2.0
tasks, through the OpenReward environment protocol. The `frontier-cs-openreward` command starts
the server.

## Sandbox runtime

The sandbox runtime is part of this package, so no external checkout is needed. `runtime.py`
builds each task sandbox on `SingularitySandbox` and the process transport in
`src/frontier_cs_openreward/sandbox_backends.py`. The server no longer reads
`FRONTIER_SANDBOX_BACKEND_ROOT`.

`sandbox_backends.py` and `session_cleanup.py` are vendored from the SWE-rebench V2 OpenReward
environment (`ApGa/SWE-rebench-V2-OpenRewardEnv`) at commit
`ac655366358b891419ba7287f82e69efb21434e2`, and are MIT-licensed.

- `session_cleanup.py` is byte-identical to the source, sha256
  `a1e3ed3590dbd59f813b53d4275ceb5279b7ba174dbe59169bf30401f7f634e1`.
- `sandbox_backends.py` differs in one line: it imports `session_cleanup` relative to this
  package (`from .session_cleanup import remove_session_tree`). With the source line restored,
  its sha256 is `ad07a3bfe1118a45cc3fd6b5ec227041ae98af24691e7938d5c948d4e96dd8da`.

`tests/test_vendored_runtime.py` checks both digests.

## Tests

Run the tests from this directory, with the package dependencies and the `test` extra installed:

```bash
PYTHONPATH=src python -m pytest -q -p no:cacheprovider
```

They need Linux, because they start host processes and read `/proc`.
