#!/usr/bin/env bash
# serve.sh - preflight, then serve Frontier-CS through OpenReward on this node. Works under any scheduler.
#
# Run one per service node, as your own user, before the trainer starts. Under a scheduler, start it in a
# host job step that sees all of the node's CPUs and memory, with a clean environment, for example:
#   /usr/bin/env -i PATH=/usr/bin:/bin HOME=$HOME FRONTIER_ENV=<site env file> NODE_LOCAL_DIR=<node-local dir> \
#     /bin/bash <checkout>/adapters/frontier-cs-openreward/scripts/serve.sh [--check]
#
#   --check   run the preflight only, remove what it created and exit: 0 if every check passed, 2 if not.
#             It never starts the server.
#
# FRONTIER_ENV is a site env file, sourced with every assignment exported (see site.env.example):
#   OPENREWARD_HOST            required: the address to bind, normally the node's fabric IP. 0.0.0.0 and ::
#                              are refused unless ALLOW_ALL_INTERFACES=1: the port is an unauthenticated shell.
#   FRONTIER_PYTHON            required: the server venv's python, installed from server.lock
#   FRONTIER_IMAGE_MANIFEST    required: the image manifest (version 1, ready)
#   FRONTIER_SOURCE_ROOT       the checkout to serve (default: the checkout holding this script)
#   FRONTIER_ADAPTER_REVISION  if set, the checkout's HEAD must be exactly this commit
#   FRONTIER_SUITE             all (default), algorithmic or 2.0
#   FRONTIER_EXCLUDE_TASK_IDS  space-separated task IDs (default: 2.0/vector_db_ann_disk)
#   FRONTIER_JUDGE_CONCURRENCY judge slots (default 4)
#   FRONTIER_MIN_FREE_GB       node-local free space required (default 100)
#   OPENREWARD_FRONTIER_CS_PORT  port (default 8085)
#   SWE_CONTAINER_RUNTIME_BIN  singularity binary (default: singularity on PATH)
#   OPENREWARD_FRONTIER_SERVER_{MAX_RESTARTS,RESTART_RESET_SECS,BACKOFF_MAX_SECS,SHUTDOWN_SECS}  restart policy
#
# NODE_LOCAL_DIR is a node-local directory outside the checkout. All of the server's state (sessions, images,
# runtime scratch and the materialized catalog, which holds reference solutions and judge tokens) lives in
# $NODE_LOCAL_DIR/frontier-cs-serve. serve.sh locks that directory, sweeps it at start (stopping leftover
# instances and processes first), between restarts (sessions only) and at exit.
#
# Preflight, before the server answers /health: a clean checkout whose HEAD contains the pinned upstream
# revision; the vendored runtime's sha256; the server venv equal to server.lock; harbor not importable; the
# image manifest and go-judge's sha256; SingularityCE; CPU affinity; node-local free space; the bind address;
# and the digest of the catalog materialized into an empty node-local directory.
set -euo pipefail
umask 077

UPSTREAM_REVISION=ede1b44d2fe22a65320c5e36b1014b3defc03671
GO_JUDGE_SHA256=0f7f04a854136f387bc3610963fc30578dd8c9b0a699773c7d83ef09dcffa5a2
SESSION_CLEANUP_SHA256=a1e3ed3590dbd59f813b53d4275ceb5279b7ba174dbe59169bf30401f7f634e1
SANDBOX_BACKENDS_SOURCE_SHA256=ad07a3bfe1118a45cc3fd6b5ec227041ae98af24691e7938d5c948d4e96dd8da
CATALOG_DIGEST_ALGORITHMIC=e83b4cb8681f787a16762137b407747f0e61b277a3ad5dc2e25d21919b776cbc
CATALOG_DIGEST_2_0=58514f390e8556d2d77f02d21adb8b5b38b4a4decc20b13a32ba93ca659da293
HOST_PYTHON=/usr/bin/python3

log() { echo "[frontier-cs-serve] $*"; }
die() { echo "[frontier-cs-serve] ERROR: $*" >&2; exit 2; }

CHECK_ONLY=0
while (($#)); do
  case $1 in
    --check) CHECK_ONLY=1; shift ;;
    -h|--help) awk 'NR > 1 && !/^#/ {exit} NR > 1' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ADAPTER_DIR=$(dirname -- "$SCRIPT_DIR")
LOCK_SPEC=$ADAPTER_DIR/server.lock
[[ -x $HOST_PYTHON ]] || die "$HOST_PYTHON is required"
[[ -r ${FRONTIER_ENV:-} ]] || die "Set FRONTIER_ENV to a readable site env file"
set -a
# shellcheck source=/dev/null
source "$FRONTIER_ENV" || die "Sourcing $FRONTIER_ENV failed"
set +a
for name in FRONTIER_MATERIALIZED_ROOT FRONTIER_SESSION_ROOT SWE_APPTAINER_SESSION_ROOT SWE_SINGULARITY_SESSION_ROOT \
    SWE_APPTAINER_IMAGE_CACHE SWE_SINGULARITY_IMAGE_CACHE SINGULARITY_CACHEDIR SINGULARITY_TMPDIR; do
  [[ -z ${!name:-} ]] || log "WARNING: ignoring $name from $FRONTIER_ENV: serve.sh keeps all state under NODE_LOCAL_DIR"
done
# Credentials never reach the server or its sandboxes.
for secret_name in WANDB_API_KEY OPENAI_API_KEY OPENAI_BASE_URL LITELLM_API_KEY LITELLM_BASE_URL \
    RUBRIC_DEFAULT_LLM HF_TOKEN AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN TINKER_API_KEY; do
  unset "$secret_name"
done

require_uint() {
  local name=$1 value=$2 minimum=$3
  if [[ -z $value || $value == *[!0-9]* ]] || ((10#$value < minimum)); then die "$name must be an integer >= $minimum"; fi
}
SOURCE_ROOT=${FRONTIER_SOURCE_ROOT:-$(cd -- "$ADAPTER_DIR/../.." && pwd)}
[[ -d $SOURCE_ROOT ]] || die "FRONTIER_SOURCE_ROOT is not a directory: $SOURCE_ROOT"
SOURCE_ROOT=$(cd -- "$SOURCE_ROOT" && pwd -P)
ADAPTER_SRC=$SOURCE_ROOT/adapters/frontier-cs-openreward/src
PYTHON=${FRONTIER_PYTHON:?Set FRONTIER_PYTHON in the site env file}
MANIFEST=${FRONTIER_IMAGE_MANIFEST:?Set FRONTIER_IMAGE_MANIFEST in the site env file}
SUITE=${FRONTIER_SUITE:-all}
EXCLUDE_TASK_IDS=${FRONTIER_EXCLUDE_TASK_IDS-2.0/vector_db_ann_disk}
HOST=${OPENREWARD_HOST:-}
PORT=${OPENREWARD_FRONTIER_CS_PORT:-8085}
MIN_FREE_GB=${FRONTIER_MIN_FREE_GB:-100}
MAX_RESTARTS=${OPENREWARD_FRONTIER_SERVER_MAX_RESTARTS:-5}
RESTART_RESET_SECS=${OPENREWARD_FRONTIER_SERVER_RESTART_RESET_SECS:-300}
BACKOFF_MAX_SECS=${OPENREWARD_FRONTIER_SERVER_BACKOFF_MAX_SECS:-30}
SERVER_SHUTDOWN_SECS=${OPENREWARD_FRONTIER_SERVER_SHUTDOWN_SECS:-60}
require_uint OPENREWARD_FRONTIER_CS_PORT "$PORT" 1
((PORT <= 65535)) || die "OPENREWARD_FRONTIER_CS_PORT must be <= 65535"
require_uint FRONTIER_MIN_FREE_GB "$MIN_FREE_GB" 0
require_uint FRONTIER_JUDGE_CONCURRENCY "${FRONTIER_JUDGE_CONCURRENCY:=4}" 1
require_uint OPENREWARD_FRONTIER_SERVER_MAX_RESTARTS "$MAX_RESTARTS" 0
require_uint OPENREWARD_FRONTIER_SERVER_RESTART_RESET_SECS "$RESTART_RESET_SECS" 1
require_uint OPENREWARD_FRONTIER_SERVER_BACKOFF_MAX_SECS "$BACKOFF_MAX_SECS" 0
require_uint OPENREWARD_FRONTIER_SERVER_SHUTDOWN_SECS "$SERVER_SHUTDOWN_SECS" 1
case $SUITE in
  all) SUITES=(algorithmic 2.0); MIN_CPUS=56 ;;
  algorithmic) SUITES=(algorithmic); MIN_CPUS=16 ;;
  2.0) SUITES=(2.0); MIN_CPUS=56 ;;
  *) die "FRONTIER_SUITE must be all, algorithmic or 2.0" ;;
esac

# The port runs an unauthenticated shell as this user: bind one address, never every interface by accident.
[[ -n $HOST ]] || die "Set OPENREWARD_HOST to this node's fabric IP (the address clients reach)"
host_status=0
"$HOST_PYTHON" -I -c '
import ipaddress, socket, sys
try:
    infos = socket.getaddrinfo(sys.argv[1], None, type=socket.SOCK_STREAM)
except OSError as error:
    sys.exit(f"cannot resolve {sys.argv[1]!r}: {error}")
sys.exit(3 if any(ipaddress.ip_address(info[4][0].split("%")[0]).is_unspecified for info in infos) else 0)
' "$HOST" || host_status=$?
case $host_status in
  0) ;;
  3)
    [[ ${ALLOW_ALL_INTERFACES:-0} == 1 ]] || die "OPENREWARD_HOST=$HOST binds every interface. Port $PORT is an" \
      "unauthenticated shell that runs as you: bind the node's fabric IP, or set ALLOW_ALL_INTERFACES=1 if" \
      "the port is firewalled to this job's nodes"
    log "WARNING: binding every interface ($HOST) because ALLOW_ALL_INTERFACES=1" ;;
  *) die "OPENREWARD_HOST=$HOST does not resolve" ;;
esac

[[ ${NODE_LOCAL_DIR:-} == /* && -d $NODE_LOCAL_DIR && -w $NODE_LOCAL_DIR ]] || \
  die "Set NODE_LOCAL_DIR to an absolute, writable node-local directory"
NODE_LOCAL_DIR=$(cd -- "$NODE_LOCAL_DIR" && pwd -P)
case $NODE_LOCAL_DIR/ in
  "$SOURCE_ROOT"/*) die "NODE_LOCAL_DIR must be outside the checkout: the server refuses a dirty tree" ;;
esac
STATE=$NODE_LOCAL_DIR/frontier-cs-serve
STATE_MARKER=$STATE/.created-by-frontier-cs-serve
# The sweep deletes STATE: nothing serve.sh needs may live there.
for path in "$SOURCE_ROOT" "$(dirname -- "$PYTHON")" "$(dirname -- "$MANIFEST")" "$(dirname -- "$FRONTIER_ENV")"; do
  path=$(realpath -m -- "$path")
  case $path/ in "$STATE"/*) die "$path is inside $STATE, which serve.sh deletes" ;; esac
done
RUNTIME=${SWE_CONTAINER_RUNTIME_BIN:-$(command -v singularity || command -v apptainer || true)}

# One serve.sh per NODE_LOCAL_DIR: the sweep below would destroy a running server's state. Children never
# inherit the lock (9>&-), so a crashed launcher's leftovers do not block the next sweep.
exec 9>>"$NODE_LOCAL_DIR/.frontier-cs-serve.lock"
command -v flock >/dev/null 2>&1 || die "flock (util-linux) is required"
flock -n 9 || die "Another serve.sh holds $NODE_LOCAL_DIR; stop it first"

# Stop this state's leftover instances and processes, then remove the directory.
sweep() {
  local dir=$1 name
  [[ -e $dir ]] || return 0
  # Delete only a state directory serve.sh created.
  [[ $dir != "$STATE" || -f $STATE_MARKER ]] || die "Refusing to delete $STATE: serve.sh did not create it"
  if [[ -n $RUNTIME && -x $RUNTIME ]]; then
    while IFS= read -r name; do
      if [[ -n $name ]]; then "$RUNTIME" instance stop --force "$name" >/dev/null 2>&1 || true; fi
    done < <("$RUNTIME" instance list --json 2>/dev/null | "$HOST_PYTHON" -I -c '
import json, os, sys
root = os.path.realpath(sys.argv[1]) + os.sep
try:
    instances = json.load(sys.stdin).get("instances") or []
except ValueError:
    instances = []
for item in instances:
    image = item.get("img") or item.get("image") or ""
    if image and os.path.realpath(image).startswith(root):
        print(item.get("instance") or item.get("name") or "")
' "$dir" 2>/dev/null || true)
  fi
  "$HOST_PYTHON" -I - "$dir" 9>&- <<'PY' || log "WARNING: some processes under $dir survived SIGKILL"
import os, signal, sys, time
root = os.path.realpath(sys.argv[1])
skip = {os.getpid(), os.getppid()}
uid = os.getuid()

def users():
    found = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit() or int(entry) in skip:
            continue
        try:
            if os.stat(f"/proc/{entry}").st_uid != uid:
                continue
            links = [os.readlink(f"/proc/{entry}/{link}") for link in ("cwd", "exe")]
        except OSError:
            continue
        if any(link == root or link.startswith(root + os.sep) for link in links):
            found.append(int(entry))
    return found

for number in (signal.SIGTERM, signal.SIGKILL):
    pids = users()
    if not pids:
        break
    for pid in pids:
        try:
            os.kill(pid, number)
        except OSError:
            pass
    deadline = time.monotonic() + 10
    while users() and time.monotonic() < deadline:
        time.sleep(0.2)
sys.exit(1 if users() else 0)
PY
  chmod -R u+rwX "$dir" 2>/dev/null || true
  rm -rf -- "$dir" || log "WARNING: could not remove $dir"
}

declare -A STATUS=()
CHECKS=()
record() {
  [[ -n ${STATUS[$1]+x} ]] || CHECKS+=("$1")
  STATUS[$1]=$2
  printf '[frontier-cs-serve] %-4s %-18s %s\n' "${2^^}" "$1" "${3:-}"
}
run_check() {  # run_check <name> <function>: record pass or fail from the function's status and output
  local name=$1 output
  if output=$("$2" 2>&1); then record "$name" pass "$output"; else record "$name" fail "$output"; fi
}
passed() { local name; for name; do [[ ${STATUS[$name]:-} == pass ]] || return 1; done; }

# The server's environment, exported before the checks so that they see what the server will see.
export PYTHONPATH=$ADAPTER_SRC
export PYTHONDONTWRITEBYTECODE=1 OPENREWARD_DISABLE_UPDATE_CHECK=1 OPENHANDS_SUPPRESS_BANNER=1
export OPENREWARD_HOST=$HOST OPENREWARD_PORT=$PORT
export FRONTIER_SOURCE_ROOT=$SOURCE_ROOT FRONTIER_IMAGE_MANIFEST=$MANIFEST FRONTIER_JUDGE_CONCURRENCY
export FRONTIER_MATERIALIZED_ROOT=$STATE/catalog FRONTIER_SESSION_ROOT=$STATE/sessions
export SWE_CONTAINER_RUNTIME_BIN=$RUNTIME SWE_SANDBOX_RUNTIME=singularity
export SWE_APPTAINER_SESSION_ROOT=$FRONTIER_SESSION_ROOT SWE_SINGULARITY_SESSION_ROOT=$FRONTIER_SESSION_ROOT
export SWE_APPTAINER_IMAGE_CACHE=$STATE/image-cache SWE_SINGULARITY_IMAGE_CACHE=$STATE/image-cache
export SINGULARITY_CACHEDIR=$STATE/singularity-cache SINGULARITY_TMPDIR=$STATE/singularity-tmp
export APPTAINER_CACHEDIR=$SINGULARITY_CACHEDIR APPTAINER_TMPDIR=$SINGULARITY_TMPDIR
# Parity with v25 (ask the maintainers before changing any of these).
export SWE_APPTAINER_FAKEROOT=0 SWE_APPTAINER_NETWORK=host
export SWE_APPTAINER_OVERLAY_SIZE_MB=8192 SWE_APPTAINER_OVERLAY_SPARSE=1 SWE_SINGULARITY_WRITABLE_DIRECTORY=1
export SWE_SINGULARITY_MEMORY_LIMIT_BYTES=68719476736 SWE_HOST_PROCESS_OUTPUT_MAX_BYTES=16777216

check_checkout_clean() {
  local dirty
  dirty=$(git -C "$SOURCE_ROOT" status --porcelain --untracked-files=all 2>&1) || { echo "$dirty"; return 1; }
  [[ -z $dirty ]] || { echo "$SOURCE_ROOT has changes: $(head -5 <<<"$dirty" | tr '\n' ' ')"; return 1; }
  echo "$SOURCE_ROOT"
}
check_checkout_pin() {
  git -C "$SOURCE_ROOT" merge-base --is-ancestor "$UPSTREAM_REVISION" HEAD 2>/dev/null || {
    echo "HEAD does not contain upstream $UPSTREAM_REVISION (a shallow clone cannot show it)"; return 1; }
  echo "HEAD contains $UPSTREAM_REVISION"
}
check_checkout_revision() {
  local head expected
  head=$(git -C "$SOURCE_ROOT" rev-parse HEAD 2>&1) || { echo "$head"; return 1; }
  if [[ -z ${FRONTIER_ADAPTER_REVISION:-} ]]; then echo "HEAD $head (FRONTIER_ADAPTER_REVISION not set)"; return 0; fi
  expected=$(git -C "$SOURCE_ROOT" rev-parse --verify --quiet "$FRONTIER_ADAPTER_REVISION^{commit}" 2>/dev/null) || {
    echo "FRONTIER_ADAPTER_REVISION $FRONTIER_ADAPTER_REVISION is not a commit here; HEAD is $head"; return 1; }
  [[ $head == "$expected" ]] || { echo "HEAD is $head, FRONTIER_ADAPTER_REVISION is $expected"; return 1; }
  echo "HEAD $head"
}
check_vendored_runtime() {
  "$HOST_PYTHON" -I - "$ADAPTER_SRC/frontier_cs_openreward" "$SESSION_CLEANUP_SHA256" \
      "$SANDBOX_BACKENDS_SOURCE_SHA256" <<'PY'
import hashlib, sys
from pathlib import Path
package = Path(sys.argv[1])
try:
    cleanup = (package / "session_cleanup.py").read_bytes()
    backends = (package / "sandbox_backends.py").read_bytes()
except OSError as error:
    sys.exit(f"no vendored runtime: {error}")
vendored = b"\nfrom .session_cleanup import remove_session_tree\n"
if backends.count(vendored) != 1:
    sys.exit("sandbox_backends.py does not import the vendored session_cleanup exactly once")
backends = backends.replace(vendored, b"\nfrom session_cleanup import remove_session_tree\n")
for name, data, expected in (("session_cleanup.py", cleanup, sys.argv[2]),
                             ("sandbox_backends.py", backends, sys.argv[3])):
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected:
        sys.exit(f"{name} sha256 {digest}, expected {expected}")
print("session_cleanup.py and sandbox_backends.py match the v25 runtime")
PY
}
check_server_venv() {
  [[ -x $PYTHON ]] || { echo "FRONTIER_PYTHON is not executable: $PYTHON"; return 1; }
  [[ -r $LOCK_SPEC ]] || { echo "missing $LOCK_SPEC"; return 1; }
  (cd / && "$PYTHON" - "$LOCK_SPEC" 9>&-) <<'PY'
import collections, importlib.metadata as metadata, re, sys
def normal(name):
    return re.sub(r"[-_.]+", "-", name).lower()
pinned = {}
for line in open(sys.argv[1], encoding="utf-8"):
    line = line.split("#", 1)[0].strip()
    if line:
        name, _, version = line.partition("==")
        pinned[normal(name)] = version.strip()
installed = collections.defaultdict(set)
for dist in metadata.distributions():
    name = dist.metadata["Name"]
    if name:
        installed[normal(name)].add(dist.version)
problems = []
for name, version in sorted(pinned.items()):
    found = installed.get(name)
    if not found:
        problems.append(f"missing {name}=={version}")
    elif found != {version}:
        problems.append(f"{name} {'/'.join(sorted(found))} != {version}")
extra = sorted(set(installed) - set(pinned))
if extra:
    problems.append("not in the lock: " + " ".join(extra))
if problems:
    more = f"; and {len(problems) - 12} more" if len(problems) > 12 else ""
    sys.exit(f"{sys.prefix}: " + "; ".join(problems[:12]) + more)
print(f"{sys.prefix}: {len(pinned)} packages, exactly server.lock (Python {sys.version.split()[0]})")
PY
}
check_harbor_absent() {
  [[ -x $PYTHON ]] || { echo "FRONTIER_PYTHON is not executable: $PYTHON"; return 1; }
  # The upstream algorithmic adapter writes task.toml differently when harbor can be imported.
  (cd / && "$PYTHON" -c 'import importlib.util, sys
spec = importlib.util.find_spec("harbor")
sys.exit(f"harbor is importable from {spec.origin or spec.submodule_search_locations}" if spec else 0)' 9>&-) &&
    echo "harbor is not importable"
}
check_image_manifest() {
  "$HOST_PYTHON" -I - "$MANIFEST" "$GO_JUDGE_SHA256" "${SUITES[@]}" <<'PY'
import hashlib, json, os, sys
path, pinned, suites = sys.argv[1], sys.argv[2], sys.argv[3:]
try:
    manifest = json.load(open(path, encoding="utf-8"))
except (OSError, ValueError) as error:
    sys.exit(f"cannot read {path}: {error}")
if manifest.get("version") != 1 or manifest.get("ready") is not True:
    sys.exit(f"{path}: not a ready version-1 manifest")
entries = []
if "algorithmic" in suites:
    algorithmic = manifest.get("algorithmic") or {}
    if algorithmic.get("ready") is not True:
        sys.exit("the algorithmic runtime is not ready in the manifest")
    entries.append(("algorithmic", algorithmic))
if "2.0" in suites:
    tasks = manifest.get("tasks") or {}
    unready = sorted(task for task, entry in tasks.items() if not entry.get("ready"))
    if not tasks or unready:
        sys.exit(f"2.0 tasks not ready in the manifest: {unready or 'none listed'}")
    entries += sorted(tasks.items())
missing = sorted({value for _, entry in entries for key, value in entry.items()
                  if key.endswith("_image") and isinstance(value, str) and not os.path.isfile(value)})
if missing:
    sys.exit(f"{len(missing)} images missing, e.g. {missing[0]}")
print(f"version 1, ready, images present for {len(entries)} entries")
PY
}
check_go_judge() {
  "$HOST_PYTHON" -I - "$MANIFEST" "$GO_JUDGE_SHA256" <<'PY'
import hashlib, json, sys
algorithmic = (json.load(open(sys.argv[1], encoding="utf-8")).get("algorithmic") or {})
binary, declared, pinned = algorithmic.get("go_judge_binary"), algorithmic.get("go_judge_sha256"), sys.argv[2]
if declared != pinned:
    sys.exit(f"the manifest pins go-judge {declared}, expected {pinned}")
digest = hashlib.sha256()
try:
    with open(binary, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
except (OSError, TypeError) as error:
    sys.exit(f"cannot read go-judge {binary!r}: {error}")
digest = digest.hexdigest()
if digest != pinned:
    sys.exit(f"{binary} sha256 {digest}, expected {pinned}")
print(f"{binary} {digest}")
PY
}
check_container_runtime() {
  local version
  [[ -n $RUNTIME && -x $RUNTIME ]] || { echo "no singularity on PATH; set SWE_CONTAINER_RUNTIME_BIN"; return 1; }
  version=$("$RUNTIME" --version 2>&1 | head -1)
  case $version in
    *apptainer*) echo "$RUNTIME is $version: Apptainer needs the runtime patch (path A, Apptainer)"; return 1 ;;
    *singularity*) echo "$RUNTIME: $version" ;;
    *) echo "$RUNTIME --version printed: $version"; return 1 ;;
  esac
}
check_host_tools() {
  local tool missing=()
  for tool in git /usr/bin/taskset /usr/bin/python3; do command -v "$tool" >/dev/null 2>&1 || missing+=("$tool"); done
  ((${#missing[@]} == 0)) || { echo "missing: ${missing[*]}"; return 1; }
  echo "git /usr/bin/taskset /usr/bin/python3"
}
check_cpus() {
  local cpus
  cpus=$("$HOST_PYTHON" -I -c 'import os; print(len(os.sched_getaffinity(0)))')
  ((cpus >= MIN_CPUS)) || { echo "$cpus CPUs in the affinity mask; suite $SUITE needs $MIN_CPUS"; return 1; }
  echo "$cpus CPUs in the affinity mask (suite $SUITE needs $MIN_CPUS)"
}
check_node_local_disk() {
  local free_gb
  free_gb=$(df -Pk "$NODE_LOCAL_DIR" | awk 'NR == 2 {printf "%d", $4 / 1048576}')
  ((free_gb >= MIN_FREE_GB)) || { echo "$free_gb GiB free in $NODE_LOCAL_DIR; need $MIN_FREE_GB"; return 1; }
  echo "$free_gb GiB free in $NODE_LOCAL_DIR"
}
check_bind() {
  "$HOST_PYTHON" -I -c '
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
try:
    family, kind, proto, _, address = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)[0]
    with socket.socket(family, kind, proto) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(address)
except OSError as error:
    sys.exit(f"cannot bind {host}:{port}: {error}")
print(f"{host}:{port} is free on this node")' "$HOST" "$PORT"
}
check_catalog() {
  local suite digest expected
  # Materialize into an empty node-local directory, exactly as the server will load it.
  [[ ! -e $FRONTIER_MATERIALIZED_ROOT ]] || { echo "$FRONTIER_MATERIALIZED_ROOT is not empty"; return 1; }
  (cd / && "$PYTHON" -c 'import sys
from pathlib import Path
from frontier_cs_openreward.catalog import load_catalog
catalog = load_catalog(Path(sys.argv[1]), materialized_root=Path(sys.argv[2]), suites=sys.argv[3:])
print(f"{len(catalog.tasks)} tasks materialized")' "$SOURCE_ROOT" "$FRONTIER_MATERIALIZED_ROOT" "${SUITES[@]}" 9>&-) ||
    return 1
  for suite in "${SUITES[@]}"; do
    digest=$(catalog_digest "$FRONTIER_MATERIALIZED_ROOT" "$suite") || return 1
    if [[ $suite == algorithmic ]]; then expected=$CATALOG_DIGEST_ALGORITHMIC; else expected=$CATALOG_DIGEST_2_0; fi
    [[ ${digest%% *} == "$expected" ]] || { echo "$suite digest ${digest%% *} ($digest), expected $expected"; return 1; }
    echo "$suite digest $digest"
  done
}
# The guide's fcs_catalog_digest, in one process: per-file sha256 with FINAL_ROLE_TOKEN lines normalized,
# over `find ./<suite> -type f` minus catalog.json and .catalog.lock, sorted bytewise.
catalog_digest() {
  "$HOST_PYTHON" -I - "$1" "$2" <<'PY'
import hashlib, os, re, stat, sys
root, suite = sys.argv[1], sys.argv[2]
token = re.compile(rb'FINAL_ROLE_TOKEN = ".*"')
newline = b"\n"
paths = []
for directory, _, names in os.walk(os.path.join(root, suite)):
    for name in names:
        full = os.path.join(directory, name)
        if name not in ("catalog.json", ".catalog.lock") and stat.S_ISREG(os.lstat(full).st_mode):
            paths.append("./" + os.path.relpath(full, root))
paths.sort(key=os.fsencode)
listing = []
for path in paths:
    with open(os.path.join(root, path), "rb") as stream:
        lines = stream.read().split(b"\n")
    lines = [b'FINAL_ROLE_TOKEN = "<TOKEN>"' if token.fullmatch(line) else line for line in lines]
    listing.append(hashlib.sha256(newline.join(lines)).hexdigest() + "  " + path + "\n")
print(hashlib.sha256("".join(listing).encode("utf-8", "surrogateescape")).hexdigest(), f"{len(paths)} files")
PY
}

server_pid=
stop_requested=0
stop_server() {
  local deadline
  if [[ -n $server_pid ]] && kill -0 "$server_pid" 2>/dev/null; then
    kill -TERM "$server_pid" 2>/dev/null || true
    deadline=$((SECONDS + SERVER_SHUTDOWN_SECS))
    while kill -0 "$server_pid" 2>/dev/null && ((SECONDS < deadline)); do sleep 0.2; done
    kill -0 "$server_pid" 2>/dev/null && kill -KILL "$server_pid" 2>/dev/null
    wait "$server_pid" 2>/dev/null || true
  fi
  server_pid=
}
final_cleanup() {
  local status=$?
  trap - EXIT INT TERM
  stop_server
  sweep "$STATE"
  exit "$status"
}
trap final_cleanup EXIT
trap 'stop_requested=1; stop_server; exit 143' TERM
trap 'stop_requested=1; stop_server; exit 130' INT

log "sweeping $STATE"
sweep "$STATE"
mkdir -p "$STATE" && : > "$STATE_MARKER"
mkdir -p "$STATE/run" "$FRONTIER_SESSION_ROOT" "$SWE_APPTAINER_IMAGE_CACHE" "$SINGULARITY_CACHEDIR" "$SINGULARITY_TMPDIR"
chmod 0700 "$STATE" "$STATE/run" "$FRONTIER_SESSION_ROOT" "$SINGULARITY_CACHEDIR" "$SINGULARITY_TMPDIR"

log "preflight: checkout $SOURCE_ROOT, suite $SUITE, $HOST:$PORT, state $STATE"
run_check bind_address check_bind
run_check checkout_clean check_checkout_clean
run_check checkout_pin check_checkout_pin
run_check checkout_revision check_checkout_revision
run_check vendored_runtime check_vendored_runtime
run_check server_venv check_server_venv
run_check harbor_absent check_harbor_absent
run_check image_manifest check_image_manifest
if [[ " ${SUITES[*]} " == *" algorithmic "* ]]; then run_check go_judge check_go_judge
else record go_judge skip "no algorithmic suite"; fi
run_check container_runtime check_container_runtime
run_check host_tools check_host_tools
run_check cpus check_cpus
run_check node_local_disk check_node_local_disk
if passed checkout_clean checkout_pin checkout_revision vendored_runtime server_venv harbor_absent; then
  run_check catalog check_catalog
else
  record catalog skip "needs a clean, pinned checkout and the exact server venv"
fi
failed=()
for name in "${CHECKS[@]}"; do [[ ${STATUS[$name]} != fail ]] || failed+=("$name"); done
if ((${#failed[@]})); then
  log "PREFLIGHT FAILED: ${failed[*]}"
  exit 2
fi
log "PREFLIGHT PASSED"
((CHECK_ONLY == 0)) || exit 0

SERVER_ARGS=(--root "$SOURCE_ROOT" --materialized-root "$FRONTIER_MATERIALIZED_ROOT" --suite "$SUITE"
  --host "$HOST" --port "$PORT")
read -r -a EXCLUDED <<< "$EXCLUDE_TASK_IDS"
for task_id in "${EXCLUDED[@]}"; do
  # The server refuses an exclusion outside the selected suites.
  if [[ $SUITE == all || ${task_id%%/*} == "$SUITE" ]]; then SERVER_ARGS+=(--exclude-task-id "$task_id"); fi
done
failures=0
cd "$STATE/run"
while ((stop_requested == 0)); do
  started_at=$SECONDS
  log "starting revision=$(git -C "$SOURCE_ROOT" rev-parse HEAD) host=$(hostname) bind=$HOST:$PORT suite=$SUITE"
  "$PYTHON" -m frontier_cs_openreward.server "${SERVER_ARGS[@]}" 9>&- &
  server_pid=$!
  status=0
  wait "$server_pid" || status=$?
  server_pid=
  ((stop_requested == 0)) || break
  ((SECONDS - started_at < RESTART_RESET_SECS)) || failures=0
  failures=$((failures + 1))
  if ((failures > MAX_RESTARTS)); then
    log "exhausted the restart budget; last status=$status" >&2
    exit 1
  fi
  delay=$((1 << (failures - 1)))
  ((delay <= BACKOFF_MAX_SECS)) || delay=$BACKOFF_MAX_SECS
  log "restarting after status=$status ($failures/$MAX_RESTARTS) in ${delay}s" >&2
  # Sessions die with the server: stop their instances and judge processes before the next start.
  sweep "$FRONTIER_SESSION_ROOT"
  mkdir -p "$FRONTIER_SESSION_ROOT" && chmod 0700 "$FRONTIER_SESSION_ROOT"
  sleep "$delay"
done
