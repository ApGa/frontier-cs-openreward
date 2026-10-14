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

## Running on a cluster

The server runs on the host, one per service node, outside any container, and starts its task
sandboxes with SingularityCE as your own user. `scripts/` holds two scheduler-neutral tools.

1. **Probe one compute node** with `scripts/frontier_site_probe.sh`, in the kind of job step the
   service will use. It needs no root and removes what it creates.

   ```bash
   NODE_LOCAL_DIR=/path/to/node-local/scratch bash scripts/frontier_site_probe.sh
   ```

   Without internet access on compute nodes, download go-judge 1.11.1 on a login node and pass
   `GO_JUDGE_TARBALL` (and `FRONTIER_PROBE_SIF` or `FRONTIER_PROBE_SQSH` for the test images). The
   output ends with `KEY=VALUE` lines between `=== FRONTIER_SITE_PROBE BEGIN ===` and
   `=== FRONTIER_SITE_PROBE END ===`. `PATH=A-singularity` means this package runs as is;
   `A-apptainer` and `B` need runtime changes. `CGROUP_TYPE` must be 0, or go-judge's time verdicts
   change.

2. **Build the server venv** with exactly the packages in `server.lock`, and never install `harbor`
   into it:

   ```bash
   uv venv --python 3.12.13 /path/to/venvs/frontier-cs-server
   uv --no-config pip install --python /path/to/venvs/frontier-cs-server/bin/python -r server.lock
   ```

3. **Write a site env file** from `scripts/site.env.example`, outside the checkout.

4. **Check, then serve**, with a clean environment, in a host job step that sees all of the node's
   CPUs and memory (the judge pins CPUs, and the runtime enforces memory itself):

   ```bash
   /usr/bin/env -i PATH=/usr/bin:/bin HOME=$HOME FRONTIER_ENV=/path/to/site.env \
     NODE_LOCAL_DIR=/path/to/node-local/scratch \
     /bin/bash /path/to/checkout/adapters/frontier-cs-openreward/scripts/serve.sh --check
   ```

   `--check` runs the preflight and exits (0 when every check passed, 2 otherwise). Without it,
   `serve.sh` starts the server after the same preflight and restarts it after a crash. The
   preflight checks a clean checkout that contains the pinned upstream revision, the vendored
   runtime's digests, the venv against `server.lock`, the image manifest and go-judge's sha256,
   SingularityCE, CPU affinity (16, or 56 with the 2.0 suite), node-local free space, the bind
   address, and the digest of a freshly materialized catalog.

- **Port 8085 is an unauthenticated shell** that runs as you. `serve.sh` binds `OPENREWARD_HOST`
  and refuses `0.0.0.0` unless `ALLOW_ALL_INTERFACES=1`. Firewall the port to the job's nodes.
- **Node-local state.** Sessions, images, runtime scratch and the catalog live in
  `$NODE_LOCAL_DIR/frontier-cs-serve`. `serve.sh` locks it, and sweeps it at start, between
  restarts and at exit. The catalog holds reference solutions and judge tokens: never share it.
- **`/health` is static.** Clients should also check `/list_environments` and each environment's
  `num_tasks`.

## Tests

Run the tests from this directory, with the package dependencies and the `test` extra installed:

```bash
PYTHONPATH=src python -m pytest -q -p no:cacheprovider
```

They need Linux, because they start host processes and read `/proc`.
