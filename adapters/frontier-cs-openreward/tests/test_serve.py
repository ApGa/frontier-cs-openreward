"""serve.sh's refusals, driven with fakes: a shared sparse clone of this repository, a fake manifest and
the test interpreter as a (wrong) server venv. Nothing here starts a server or a container."""
import fcntl
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys

import pytest

ADAPTER = Path(__file__).resolve().parents[1]
REPO = ADAPTER.parents[1]
SCRIPTS = ADAPTER / "scripts"
SERVE = SCRIPTS / "serve.sh"
UPSTREAM_REVISION = "ede1b44d2fe22a65320c5e36b1014b3defc03671"

pytestmark = pytest.mark.skipif(
    shutil.which("git") is None or not Path("/usr/bin/python3").exists()
    or subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True).returncode != 0,
    reason="needs git, /usr/bin/python3 and this repository's history",
)


def _head():
    return subprocess.check_output(["git", "-C", str(REPO), "rev-parse", "HEAD"], text=True).strip()


@pytest.fixture
def checkout(tmp_path):
    """A clean checkout of this repository's HEAD that shares its objects, with only the adapter checked out."""
    path = tmp_path / "checkout"
    git = ["git", "-c", "advice.detachedHead=false"]
    subprocess.run([*git, "clone", "--quiet", "--shared", "--no-checkout", str(REPO), str(path)], check=True)
    subprocess.run([*git, "-C", str(path), "sparse-checkout", "set", "--cone", "adapters/frontier-cs-openreward"],
                   check=True)
    subprocess.run([*git, "-C", str(path), "checkout", "--quiet", "--detach", _head()], check=True)
    return path


@pytest.fixture
def site(tmp_path, checkout):
    """A site env file whose every setting can be overridden, and an empty node-local directory."""
    node_local = tmp_path / "node-local"
    node_local.mkdir()
    go_judge = tmp_path / "go-judge"
    go_judge.write_bytes(b"not go-judge")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"version": 1, "ready": True, "algorithmic": {
        "ready": True, "go_judge_binary": str(go_judge), "go_judge_sha256": "0" * 64}}))
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    settings = {
        "OPENREWARD_HOST": "127.0.0.1",
        "OPENREWARD_FRONTIER_CS_PORT": str(port),
        "FRONTIER_SOURCE_ROOT": str(checkout),
        "FRONTIER_PYTHON": sys.executable,
        "FRONTIER_IMAGE_MANIFEST": str(manifest),
        "FRONTIER_SUITE": "algorithmic",
        "FRONTIER_MIN_FREE_GB": "0",
        "SWE_CONTAINER_RUNTIME_BIN": str(tmp_path / "no-singularity"),
    }

    def run(**overrides):
        env_file = tmp_path / "site.env"
        lines = [f"{key}={value}" for key, value in {**settings, **overrides}.items() if value is not None]
        env_file.write_text("\n".join(lines) + "\n")
        environment = {"PATH": "/usr/bin:/bin", "HOME": os.environ.get("HOME", "/"),
                       "FRONTIER_ENV": str(env_file), "NODE_LOCAL_DIR": str(node_local)}
        return subprocess.run(["/bin/bash", str(SERVE), "--check"], env=environment, capture_output=True,
                              text=True, timeout=300)

    run.checkout = checkout
    run.node_local = node_local
    return run


def lines(result, status):
    return {line.split()[2]: line for line in result.stdout.splitlines()
            if line.startswith(f"[frontier-cs-serve] {status} ")}


@pytest.mark.parametrize("host", ["0.0.0.0", "::"])
def test_refuses_every_interface(site, host):
    result = site(OPENREWARD_HOST=host)
    assert result.returncode == 2
    assert "binds every interface" in result.stderr
    assert "preflight" not in result.stdout
    assert list(site.node_local.iterdir()) == []


def test_every_interface_needs_the_explicit_opt_in(site):
    result = site(OPENREWARD_HOST="0.0.0.0", ALLOW_ALL_INTERFACES="1")
    assert "WARNING: binding every interface" in result.stdout
    assert "bind_address" in lines(result, "PASS")


def test_refuses_a_missing_bind_address(site):
    result = site(OPENREWARD_HOST=None)
    assert result.returncode == 2
    assert "Set OPENREWARD_HOST" in result.stderr


def test_a_clean_pinned_checkout_passes_the_source_checks(site):
    result = site(FRONTIER_ADAPTER_REVISION=_head())
    passed = lines(result, "PASS")
    for name in ("checkout_clean", "checkout_pin", "checkout_revision", "vendored_runtime", "harbor_absent"):
        assert name in passed, result.stdout
    # The fakes fail the rest, so the preflight as a whole fails and nothing is materialized.
    assert result.returncode == 2
    assert "PREFLIGHT FAILED" in result.stdout


def test_refuses_a_dirty_tree(site):
    (site.checkout / "adapters/frontier-cs-openreward/notes.txt").write_text("scratch\n")
    result = site()
    assert result.returncode == 2
    assert "notes.txt" in lines(result, "FAIL")["checkout_clean"]
    assert "catalog" in lines(result, "SKIP")


def test_refuses_a_modified_vendored_runtime(site):
    path = site.checkout / "adapters/frontier-cs-openreward/src/frontier_cs_openreward/session_cleanup.py"
    path.write_text(path.read_text() + "# local edit\n")
    result = site()
    failed = lines(result, "FAIL")
    assert result.returncode == 2
    assert "checkout_clean" in failed and "vendored_runtime" in failed


@pytest.mark.parametrize("revision", [UPSTREAM_REVISION, "0" * 40])
def test_refuses_a_wrong_revision(site, revision):
    result = site(FRONTIER_ADAPTER_REVISION=revision)
    assert result.returncode == 2
    assert "checkout_revision" in lines(result, "FAIL")
    assert "catalog" in lines(result, "SKIP")


def test_refuses_a_venv_with_extra_packages(site):
    # The test venv holds pytest, which the server venv must not.
    result = site()
    assert result.returncode == 2
    failure = lines(result, "FAIL")["server_venv"]
    assert "not in the lock" in failure and "pytest" in failure


def test_refuses_a_venv_with_missing_packages(site, tmp_path):
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(tmp_path / "empty")], check=True)
    result = site(FRONTIER_PYTHON=str(tmp_path / "empty/bin/python"))
    assert result.returncode == 2
    failure = lines(result, "FAIL")["server_venv"]
    assert "missing aiohttp==3.14.0" in failure and "and 35 more" in failure


def test_refuses_a_go_judge_with_the_wrong_digest(site):
    result = site()
    assert "the manifest pins go-judge" in lines(result, "FAIL")["go_judge"]


def test_state_always_lives_under_node_local_dir(site, tmp_path):
    result = site(FRONTIER_MATERIALIZED_ROOT=str(tmp_path / "shared-catalog"))
    assert "WARNING: ignoring FRONTIER_MATERIALIZED_ROOT" in result.stdout
    assert not (tmp_path / "shared-catalog").exists()


def test_check_leaves_only_the_lock_file(site):
    site()
    assert [path.name for path in site.node_local.iterdir()] == [".frontier-cs-openreward.lock"]


def test_refuses_a_node_local_directory_another_serve_holds(site):
    with open(site.node_local / ".frontier-cs-openreward.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = site()
    assert result.returncode == 2
    assert "Another serve.sh holds" in result.stderr


def test_catalog_digest_matches_the_guide(tmp_path):
    """serve.sh's one-process digest equals the guide's fcs_catalog_digest shell function."""
    root = tmp_path / "materialized"
    task = root / "algorithmic/frontier-cs-algorithm-0"
    (task / "tests").mkdir(parents=True)
    (task / "tests/evaluate.py").write_text('import os\nFINAL_ROLE_TOKEN = "abc123"\nprint(1)\n')
    (task / "tests/tail.py").write_bytes(b'x = 1\nFINAL_ROLE_TOKEN = "no-newline"')
    (task / "name with space.md").write_text("Ünïcode\r\nline\n")
    (task / "empty").write_bytes(b"")
    (task / "link").symlink_to("empty")
    (root / "algorithmic/catalog.json").write_text("{}")
    (root / "algorithmic/.catalog.lock").write_text("")
    text = SERVE.read_text()
    start = text.index("catalog_digest() {")
    start = text.index("\n", text.index("<<'PY'", start)) + 1
    script = tmp_path / "digest.py"
    script.write_text(text[start:text.index("\nPY\n", start)] + "\n")
    ours = subprocess.check_output(["/usr/bin/python3", "-I", str(script), str(root), "algorithmic"], text=True)
    guide = r'''fcs_catalog_digest() { (cd "$1" && find "$2" -type f ! -name catalog.json ! -name .catalog.lock -print0 | LC_ALL=C sort -z |
  while IFS= read -r -d '' f; do printf '%s  %s\n' "$(sed -E 's/^FINAL_ROLE_TOKEN = ".*"$/FINAL_ROLE_TOKEN = "<TOKEN>"/' "$f" |
  sha256sum | cut -c1-64)" "$f"; done) | sha256sum | cut -c1-64; }
fcs_catalog_digest "$1" ./algorithmic'''
    expected = subprocess.check_output(["bash", "-c", guide, "digest", str(root)], text=True).strip()
    assert ours.split() == [expected, "4", "files"]
    (task / "tests/evaluate.py").write_text('import os\nFINAL_ROLE_TOKEN = "other"\nprint(1)\n')
    again = subprocess.check_output(["/usr/bin/python3", "-I", str(script), str(root), "algorithmic"], text=True)
    assert again == ours


@pytest.mark.parametrize("name", ["serve.sh", "frontier_site_probe.sh"])
def test_scripts_parse_and_lint(name):
    subprocess.run(["bash", "-n", str(SCRIPTS / name)], check=True)
    if shutil.which("shellcheck"):
        subprocess.run(["shellcheck", "-x", str(SCRIPTS / name)], check=True)
