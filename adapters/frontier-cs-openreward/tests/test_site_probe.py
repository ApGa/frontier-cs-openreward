"""frontier_site_probe.sh's control flow and verdict, driven with fake singularity, enroot and curl.

The fakes start no container and reach no network; the node checks (CPUs, limits, memory, disk, cgroups)
read this host."""
import io
import os
from pathlib import Path
import subprocess
import tarfile

import pytest

PROBE = Path(__file__).resolve().parents[1] / "scripts/frontier_site_probe.sh"

FAKE_SINGULARITY = r'''#!/bin/bash
state=${FAKE_STATE:?}
fail() { [[ " ${FAKE_FAIL:-} " == *" $1 "* ]]; }
case $1 in
  --version) [[ ${FAKE_FLAVOR:-singularity} == apptainer ]] && echo "apptainer version 1.3.0" \
               || echo "singularity-ce version 4.4.1"; exit 0 ;;
  pull) fail pull && exit 1; touch "$2"; exit 0 ;;
  build)
    if [[ $2 == --fakeroot ]]; then fail build-fakeroot && { echo "fakeroot denied" >&2; exit 255; }; touch "$3"; exit 0; fi
    # A sandbox with a read-only directory, as --fix-perms can leave.
    mkdir -p "$4/etc/private" && chmod 0555 "$4/etc"; exit 0 ;;
  instance)
    case $2 in
      start)
        name=${!#} pidfile=
        while (($#)); do [[ $1 == --pid-file ]] && pidfile=$2; shift; done
        title="Singularity"; [[ ${FAKE_FLAVOR:-singularity} == apptainer ]] && title="Apptainer"
        # As SingularityCE 4.4 does with --containall, the PID file names a child of the titled process.
        (exec -a "$title instance: $(id -un) [$name]" /bin/bash -c 'sleep 300 & echo $! > "$1"; wait' _ "$pidfile") \
          </dev/null >/dev/null 2>&1 &
        for _ in $(seq 50); do [[ -s $pidfile ]] && break; sleep 0.1; done
        cp "$pidfile" "$state/$name"; exit 0 ;;
      list) printf '{"instances": [{"instance": "%s", "pid": 1, "img": "/x"}]}\n' "${!#}"; exit 0 ;;
      stop) kill "$(cat "$state/${!#}")" 2>/dev/null; rm -f "$state/${!#}"; exit 0 ;;
    esac ;;
  exec) printf '%s\nDEV\nnull\nzero\nSHM\ntmpfs 64M 0 64M 0%% /dev/shm\n' "$(id -u)"; exit 0 ;;
esac
exit 1
'''
FAKE_ENROOT = '''#!/bin/bash
[[ $1 == version ]] && { echo 3.5.0; exit 0; }
echo "enroot: no network" >&2
exit 1
'''
FAKE_CURL = '''#!/bin/bash
exit 7
'''


@pytest.fixture
def probe(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, text in (("singularity", FAKE_SINGULARITY), ("enroot", FAKE_ENROOT), ("curl", FAKE_CURL)):
        (bin_dir / name).write_text(text)
        (bin_dir / name).chmod(0o755)
    state = tmp_path / "state"
    state.mkdir()
    node_local = tmp_path / "node-local"
    node_local.mkdir()
    tarball = tmp_path / "go-judge.tar.gz"
    with tarfile.open(tarball, "w:gz") as archive:
        data = b"#!/bin/sh\nexit 0\n"
        info = tarfile.TarInfo("go-judge")
        info.size, info.mode = len(data), 0o755
        archive.addfile(info, io.BytesIO(data))

    def run(**overrides):
        environment = {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": os.environ.get("HOME", "/"),
                       "NODE_LOCAL_DIR": str(node_local), "GO_JUDGE_TARBALL": str(tarball),
                       "FAKE_STATE": str(state), "PROBE_NET_TIMEOUT": "1", **overrides}
        result = subprocess.run(["/bin/bash", str(PROBE)], env=environment, capture_output=True, text=True,
                                timeout=300)
        block = result.stdout.split("=== FRONTIER_SITE_PROBE BEGIN ===\n", 1)[1]
        block = block.split("=== FRONTIER_SITE_PROBE END ===", 1)[0]
        result.verdict = dict(line.split("=", 1) for line in block.splitlines())
        return result

    run.node_local = node_local
    run.state = state
    return run


def test_a_working_singularity_is_path_a_and_failures_do_not_stop_the_probe(probe):
    result = probe()
    verdict = result.verdict
    assert result.returncode == 0, result.stderr
    assert verdict["PATH"] == "A-singularity"
    assert verdict["CPUS"].isdigit()
    for check in ("net_pypi", "net_github", "net_codeforces", "go_judge_sha256", "b_import"):
        assert verdict[f"CHECK_{check}"] == "fail", check
    assert verdict["CHECK_go_judge_rlimit"] == "skip"
    assert verdict["CGROUP_TYPE"] == "unknown" and verdict["STOP"] == "1"
    for check in ("a_pull", "a_build_fakeroot", "a_build_sandbox", "a_instance_start", "a_instance_title",
                  "a_exec", "a_instance_list", "a_instance_stop"):
        assert verdict[f"CHECK_{check}"] == "pass", (check, result.stdout)
    assert verdict["PATH_B_READY"] == "no" and verdict["CHECK_b_create"] == "skip"
    assert verdict["A_PIDFILE_PROCESS"] == "sleep 300"
    assert verdict["A_INSTANCE_TITLE"].startswith("Singularity instance: ")


def test_the_probe_removes_what_it_creates(probe):
    probe()
    assert list(probe.node_local.iterdir()) == []
    assert list(probe.state.iterdir()) == []  # the fake instance was stopped


def test_apptainer_is_path_a_apptainer(probe):
    assert probe(FAKE_FLAVOR="apptainer").verdict["PATH"] == "A-apptainer"


def test_a_failed_fakeroot_build_means_path_b(probe):
    verdict = probe(FAKE_FAIL="build-fakeroot").verdict
    assert verdict["PATH"] == "B"
    assert verdict["CHECK_a_build_fakeroot"] == "fail"
    assert verdict["CHECK_a_build_sandbox"] == "skip" and verdict["CHECK_a_instance_start"] == "skip"
    assert "CHECK_a_instance_stop" not in verdict
    assert list(probe.node_local.iterdir()) == []


def test_the_probe_needs_a_node_local_directory(tmp_path):
    result = subprocess.run(["/bin/bash", str(PROBE)], env={"PATH": "/usr/bin:/bin"}, capture_output=True,
                            text=True, timeout=60)
    assert result.returncode == 2
    assert "NODE_LOCAL_DIR" in result.stderr
