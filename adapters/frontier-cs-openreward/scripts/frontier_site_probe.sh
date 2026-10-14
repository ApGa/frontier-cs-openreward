#!/usr/bin/env bash
# frontier_site_probe.sh - the Frontier-CS node probe (F0), for any scheduler.
#
# Run it on one compute node, in the kind of host job step the service will use, as your own user:
#   NODE_LOCAL_DIR=<node-local dir> [GO_JUDGE_TARBALL=<go-judge tarball>] bash frontier_site_probe.sh
# or: bash frontier_site_probe.sh --node-local <dir>
#
# It reports the node's CPUs, limits, memory, disk, cgroups and internet access; runs go-judge as the
# server runs it (rlimit mode); and makes the container runtime calls the server makes: path A
# (SingularityCE or Apptainer, with the production flags) and path B (enroot, without --root). It needs
# no root, keeps going after a failed check, removes everything it creates (temporary directories, the
# probe instance and container, runtime caches) and ends with a machine-readable block between
# "=== FRONTIER_SITE_PROBE BEGIN ===" and "=== FRONTIER_SITE_PROBE END ===" (KEY=VALUE lines).
#
# Environment:
#   NODE_LOCAL_DIR       node-local scratch directory (required); the probe works in a fresh subdirectory
#   GO_JUDGE_TARBALL     go-judge_1.11.1_linux_amd64v2.tar.gz, for nodes without internet access
#   FRONTIER_PROBE_SIF   a local SIF to adapt instead of pulling docker://ubuntu:24.04 (offline nodes)
#   FRONTIER_PROBE_SQSH  a local .sqsh to use instead of importing docker://alpine:3.20 (offline nodes)
#   PROBE_NET_TIMEOUT    seconds per internet request (default 15)
set -uo pipefail
umask 077

GO_JUDGE_VERSION=1.11.1
GO_JUDGE_URL=https://github.com/criyle/go-judge/releases/download/v$GO_JUDGE_VERSION/go-judge_${GO_JUDGE_VERSION}_linux_amd64v2.tar.gz
GO_JUDGE_SHA256=0f7f04a854136f387bc3610963fc30578dd8c9b0a699773c7d83ef09dcffa5a2
MIN_CPUS=16
MIN_CPUS_2_0=56
MIN_FREE_GIB=100
MIN_MEM_GIB=320
NET_TIMEOUT=${PROBE_NET_TIMEOUT:-15}

while (($#)); do
  case $1 in
    --node-local) NODE_LOCAL_DIR=${2:?--node-local needs a directory}; shift 2 ;;
    -h|--help) awk 'NR > 1 && !/^#/ {exit} NR > 1' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
if [[ -z ${NODE_LOCAL_DIR:-} || ! -d $NODE_LOCAL_DIR || ! -w $NODE_LOCAL_DIR ]]; then
  echo "Set NODE_LOCAL_DIR (or --node-local) to a writable node-local directory" >&2
  exit 2
fi

declare -A STATUS=() VALUE=()
CHECKS=()
record() {  # record <check> <pass|fail|skip> [detail]
  [[ -n ${STATUS[$1]+x} ]] || CHECKS+=("$1")
  STATUS[$1]=$2
  printf '[probe] %-22s %-4s %s\n' "$1" "$2" "${3:-}"
}
value() { VALUE[$1]=$2; }
section() { printf '\n[probe] ---- %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }
# Run a command with a time limit when coreutils' timeout exists.
limit() { local seconds=$1; shift; if have timeout; then timeout -k 10 "$seconds" "$@"; else "$@"; fi; }

UID_NOW=$(id -u)
PROBE_ROOT=$(mktemp -d "$NODE_LOCAL_DIR/fcs-probe-XXXXXX") || { echo "cannot create a directory in $NODE_LOCAL_DIR" >&2; exit 2; }
INSTANCE_NAME=fcsprobe-$$-$RANDOM
ENROOT_NAME=fcs-probe-$$-$RANDOM
GJ_PID=
RUNTIME=
INSTANCE_STARTED=0
ENROOT_CREATED=0

cleanup() {
  trap - EXIT INT TERM
  if [[ -n $GJ_PID ]]; then kill "$GJ_PID" 2>/dev/null; wait "$GJ_PID" 2>/dev/null; fi
  if ((INSTANCE_STARTED)) && [[ -n $RUNTIME ]]; then
    limit 60 "$RUNTIME" instance stop --force "$INSTANCE_NAME" >/dev/null 2>&1
  fi
  if ((ENROOT_CREATED)); then
    ENROOT_DATA_PATH=$PROBE_ROOT/enroot/data ENROOT_CACHE_PATH=$PROBE_ROOT/enroot/cache \
      ENROOT_TEMP_PATH=$PROBE_ROOT/enroot/tmp limit 60 enroot remove -f "$ENROOT_NAME" >/dev/null 2>&1
  fi
  # Sandboxes built with --fix-perms can hold read-only directories.
  chmod -R u+rwX "$PROBE_ROOT" 2>/dev/null
  rm -rf "$PROBE_ROOT"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

section "node"
echo "host=$(hostname) uid=$UID_NOW kernel=$(uname -r) date=$(date -u +%FT%TZ)"
[[ -r /etc/os-release ]] && grep -E '^PRETTY_NAME=' /etc/os-release

# CPUs in this process's affinity mask, which is what the server sees.
if have python3; then
  CPUS=$(python3 -I -c 'import os; print(len(os.sched_getaffinity(0)))' 2>/dev/null)
else
  CPUS=$(nproc 2>/dev/null)
fi
value CPUS "${CPUS:-unknown}"
if [[ ${CPUS:-0} =~ ^[0-9]+$ ]] && ((CPUS >= MIN_CPUS)); then
  record cpus pass "$CPUS in the affinity mask (algorithmic needs $MIN_CPUS)"
else
  record cpus fail "${CPUS:-unknown} in the affinity mask (algorithmic needs $MIN_CPUS)"
fi
if [[ ${CPUS:-0} =~ ^[0-9]+$ ]] && ((CPUS >= MIN_CPUS_2_0)); then
  record cpus_2_0 pass "the 2.0 suite needs $MIN_CPUS_2_0"
else
  record cpus_2_0 fail "the 2.0 suite needs $MIN_CPUS_2_0"
fi

section "limits"
ulimit -a
NOFILE=$(ulimit -Sn); NPROC=$(ulimit -Su); VMEM=$(ulimit -Sv)
value ULIMIT_NOFILE "$NOFILE"; value ULIMIT_NPROC "$NPROC"; value ULIMIT_VMEM "$VMEM"
ulimit_ok=1
[[ $VMEM == unlimited ]] || ulimit_ok=0
[[ $NOFILE == unlimited ]] || ((NOFILE >= 4096)) || ulimit_ok=0
[[ $NPROC == unlimited ]] || ((NPROC >= 4096)) || ulimit_ok=0
if ((ulimit_ok)); then record ulimits pass "nofile=$NOFILE nproc=$NPROC vmem=$VMEM"
else record ulimits fail "nofile=$NOFILE nproc=$NPROC vmem=$VMEM (want vmem unlimited, nofile and nproc >= 4096)"; fi

section "cpu model and memory"
CPU_MODEL=$(lscpu 2>/dev/null | sed -n 's/^Model name:[[:space:]]*//p' | head -1)
value CPU_MODEL "${CPU_MODEL:-unknown}"
if [[ -n $CPU_MODEL ]]; then record cpu_model pass "$CPU_MODEL"; else record cpu_model fail "lscpu gave no model name"; fi
free -g 2>/dev/null | head -2
MEM_GIB=$(awk '/^MemTotal:/ {printf "%d", $2 / 1048576}' /proc/meminfo 2>/dev/null)
value MEM_TOTAL_GIB "${MEM_GIB:-unknown}"
if [[ ${MEM_GIB:-0} =~ ^[0-9]+$ ]] && ((MEM_GIB >= MIN_MEM_GIB)); then
  record memory pass "${MEM_GIB} GiB (v25 engine nodes peaked at about 310 GiB)"
else
  record memory fail "${MEM_GIB:-unknown} GiB (v25 engine nodes peaked at about 310 GiB)"
fi

section "node-local disk"
df -h "$NODE_LOCAL_DIR"
FREE_GIB=$(df -Pk "$NODE_LOCAL_DIR" 2>/dev/null | awk 'NR == 2 {printf "%d", $4 / 1048576}')
FS_TYPE=$(stat -fc %T "$NODE_LOCAL_DIR" 2>/dev/null)
value NODE_LOCAL_FREE_GIB "${FREE_GIB:-unknown}"; value NODE_LOCAL_FSTYPE "${FS_TYPE:-unknown}"
if [[ ${FREE_GIB:-0} =~ ^[0-9]+$ ]] && ((FREE_GIB >= MIN_FREE_GIB)); then
  record node_local_disk pass "${FREE_GIB} GiB free on $FS_TYPE"
else
  record node_local_disk fail "${FREE_GIB:-unknown} GiB free on ${FS_TYPE:-unknown} (want >= $MIN_FREE_GIB)"
fi

section "cgroups and user D-Bus"
CGROUP_FS=$(stat -fc %T /sys/fs/cgroup 2>/dev/null)
case $CGROUP_FS in
  cgroup2fs) CGROUP_VERSION=v2 ;;
  tmpfs) CGROUP_VERSION=v1 ;;
  *) CGROUP_VERSION=unknown ;;
esac
value CGROUP_VERSION "$CGROUP_VERSION"
cat /proc/self/cgroup
if [[ $CGROUP_VERSION != unknown ]]; then record cgroup pass "$CGROUP_VERSION ($CGROUP_FS)"
else record cgroup fail "/sys/fs/cgroup is ${CGROUP_FS:-missing}"; fi
# Informational (USER_DBUS): the go-judge check below shows whether it changes go-judge's mode.
if [[ -S /run/user/$UID_NOW/bus ]]; then
  ls -l "/run/user/$UID_NOW/bus"; value USER_DBUS yes; record user_dbus pass "yes: /run/user/$UID_NOW/bus"
else
  value USER_DBUS no; record user_dbus pass "no /run/user/$UID_NOW/bus (no systemd user manager in this step)"
fi

section "host tools"
missing=()
for tool in git /usr/bin/taskset /usr/bin/python3 curl tar sha256sum; do have "$tool" || missing+=("$tool"); done
if ((${#missing[@]} == 0)); then record host_tools pass "git /usr/bin/taskset /usr/bin/python3 curl tar sha256sum"
else record host_tools fail "missing: ${missing[*]}"; fi
missing=()
for tool in unshare nsenter unsquashfs; do have "$tool" || missing+=("$tool"); done
if ((${#missing[@]} == 0)); then record host_tools_b pass "unshare nsenter unsquashfs"
else record host_tools_b fail "missing: ${missing[*]}"; fi

section "internet"
for site in pypi=https://pypi.org/simple/ github=https://github.com codeforces=https://codeforces.com; do
  name=${site%%=*} url=${site#*=}
  code=$(curl -s -o /dev/null -I --max-time "$NET_TIMEOUT" -w '%{http_code}' "$url" 2>/dev/null)
  # Any HTTP answer proves reachability: codeforces answers curl's HEAD with 403.
  if [[ $code =~ ^[1-5][0-9][0-9]$ ]]; then record "net_$name" pass "$url HTTP $code"
  else record "net_$name" fail "$url: no HTTP answer"; fi
done

section "go-judge (rlimit mode)"
GJ_DIR=$PROBE_ROOT/go-judge
mkdir -p "$GJ_DIR"
CGROUP_TYPE=unknown
if [[ -n ${GO_JUDGE_TARBALL:-} ]]; then
  if cp -- "$GO_JUDGE_TARBALL" "$GJ_DIR/go-judge.tar.gz"; then record go_judge_fetch pass "from $GO_JUDGE_TARBALL"
  else record go_judge_fetch fail "cannot read $GO_JUDGE_TARBALL"; fi
elif limit 300 curl -fsSL --max-time 240 -o "$GJ_DIR/go-judge.tar.gz" "$GO_JUDGE_URL"; then
  record go_judge_fetch pass "$GO_JUDGE_URL"
else
  record go_judge_fetch fail "download failed; set GO_JUDGE_TARBALL to a copy fetched on a login node"
fi
if [[ ${STATUS[go_judge_fetch]} == pass ]] && tar -xzf "$GJ_DIR/go-judge.tar.gz" -C "$GJ_DIR" go-judge 2>/dev/null; then
  digest=$(sha256sum "$GJ_DIR/go-judge" | cut -c1-64)
  if [[ $digest == "$GO_JUDGE_SHA256" ]]; then record go_judge_sha256 pass "$digest"
  else record go_judge_sha256 fail "$digest, expected $GO_JUDGE_SHA256"; fi
else
  record go_judge_sha256 fail "no go-judge binary in the tarball"
fi
if [[ ${STATUS[go_judge_sha256]} == pass ]]; then
  GJ_PORT=$(python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])' 2>/dev/null)
  GJ_PORT=${GJ_PORT:-5050}
  mkdir -p "$GJ_DIR/tmp" "$GJ_DIR/files"
  # The server's environment for go-judge: nothing but PATH, LANG and TMPDIR.
  (cd "$GJ_DIR" && exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8 TMPDIR="$GJ_DIR/tmp" \
     ./go-judge -http-addr "127.0.0.1:$GJ_PORT" -silent -dir "$GJ_DIR/files") &
  GJ_PID=$!
  config=
  for _ in $(seq 1 40); do
    config=$(curl -s --noproxy '*' --max-time 2 "http://127.0.0.1:$GJ_PORT/config" 2>/dev/null) && [[ -n $config ]] && break
    kill -0 "$GJ_PID" 2>/dev/null || break
    sleep 0.5
  done
  kill "$GJ_PID" 2>/dev/null; wait "$GJ_PID" 2>/dev/null; GJ_PID=
  CGROUP_TYPE=$(grep -o '"cgroupType":[0-9]*' <<<"$config" | cut -d: -f2)
  CGROUP_TYPE=${CGROUP_TYPE:-unknown}
  if [[ $CGROUP_TYPE == 0 ]]; then record go_judge_rlimit pass "cgroupType 0"
  else record go_judge_rlimit fail "cgroupType $CGROUP_TYPE (must be 0: stop and tell the maintainers)"; fi
else
  record go_judge_rlimit skip "no verified binary"
fi
value CGROUP_TYPE "$CGROUP_TYPE"

section "path A: SingularityCE or Apptainer"
A_DIR=$PROBE_ROOT/path-a
mkdir -p "$A_DIR/tmp" "$A_DIR/vtmp" "$A_DIR/cache" "$A_DIR/build-tmp"
# Keep the runtime's caches inside the probe directory, so cleanup removes them.
export SINGULARITY_CACHEDIR=$A_DIR/cache APPTAINER_CACHEDIR=$A_DIR/cache
export SINGULARITY_TMPDIR=$A_DIR/build-tmp APPTAINER_TMPDIR=$A_DIR/build-tmp
RUNTIME=$(command -v singularity || command -v apptainer || true)
A_FLAVOR=none
A_OK=0
if [[ -z $RUNTIME ]]; then
  record a_runtime fail "neither singularity nor apptainer is on PATH"
else
  version=$("$RUNTIME" --version 2>&1 | head -1)
  case $version in
    *apptainer*) A_FLAVOR=apptainer ;;
    *singularity*) A_FLAVOR=singularity ;;
  esac
  value A_RUNTIME "$RUNTIME"; value A_VERSION "$version"
  record a_runtime pass "$RUNTIME: $version"
  A_OK=1
  step() {  # step <check> <seconds> <command...>: run while every earlier path-A call worked
    local name=$1 seconds=$2 output status
    shift 2
    if ((A_OK == 0)); then record "$name" skip "an earlier path-A call failed"; return 1; fi
    output=$(limit "$seconds" "$@" 2>&1); status=$?
    if ((status == 0)); then record "$name" pass; return 0; fi
    printf '%s\n' "$output" | tail -15
    record "$name" fail "exit $status: $*"
    A_OK=0
    return 1
  }
  if [[ -n ${FRONTIER_PROBE_SIF:-} ]]; then
    if [[ -r $FRONTIER_PROBE_SIF ]]; then BASE_SIF=$FRONTIER_PROBE_SIF; record a_pull pass "local $FRONTIER_PROBE_SIF"
    else record a_pull fail "cannot read $FRONTIER_PROBE_SIF"; A_OK=0; fi
  else
    BASE_SIF=$A_DIR/base.sif
    step a_pull 900 "$RUNTIME" pull "$BASE_SIF" docker://ubuntu:24.04
  fi
  printf 'Bootstrap: localimage\nFrom: %s\n\n%%startscript\n    exec /usr/bin/sleep 2147483647\n' \
    "${BASE_SIF:-}" > "$A_DIR/adapter.def"
  step a_build_fakeroot 1800 "$RUNTIME" build --fakeroot "$A_DIR/adapted.sif" "$A_DIR/adapter.def"
  step a_build_sandbox 900 "$RUNTIME" build --sandbox --fix-perms "$A_DIR/rootfs" "$A_DIR/adapted.sif"
  # The runtime's instance start, with its production flags.
  if step a_instance_start 300 "$RUNTIME" instance start --cleanenv --containall --no-home --no-eval \
      --no-mount home,cwd,bind-paths --bind "$A_DIR/tmp:/tmp:rw" --bind "$A_DIR/vtmp:/var/tmp:rw" \
      --env GIT_CONFIG_GLOBAL=/tmp/.gitconfig-openreward --pid-file "$A_DIR/pid" --writable "$A_DIR/rootfs" \
      "$INSTANCE_NAME"; then
    INSTANCE_STARTED=1
  fi
  if ((INSTANCE_STARTED)); then
    # The PID file can name the container's init (SingularityCE 4.4 with --containall names sinit); the
    # instance's title is on it or on an ancestor.
    pid=$(cat "$A_DIR/pid" 2>/dev/null)
    value A_PIDFILE_PROCESS "$(ps -o args= -p "${pid:-0}" 2>/dev/null)"
    title=
    for _ in 1 2 3 4; do
      if ! [[ $pid =~ ^[0-9]+$ ]] || ((pid <= 1)); then break; fi
      args=$(ps -o args= -p "$pid" 2>/dev/null)
      case $args in "Singularity instance:"*|"Apptainer instance:"*) title=$args; break ;; esac
      pid=$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')
    done
    value A_INSTANCE_TITLE "$title"
    case $title in
      "Singularity instance:"*) A_FLAVOR=singularity; record a_instance_title pass "$title" ;;
      "Apptainer instance:"*) A_FLAVOR=apptainer; record a_instance_title pass "$title" ;;
      *) record a_instance_title fail "no instance title on the PID file's process or its parents"; A_OK=0 ;;
    esac
    exec_out=$(limit 120 "$RUNTIME" exec --cleanenv --env GIT_CONFIG_GLOBAL=/tmp/.gitconfig-openreward --cwd / \
      "instance://$INSTANCE_NAME" /bin/sh -c 'id -u; echo DEV; ls /dev; echo SHM; df -h /dev/shm | tail -1' 2>&1)
    status=$?
    printf '%s\n' "$exec_out"
    inner_uid=$(head -1 <<<"$exec_out")
    if ((status != 0)); then record a_exec fail "exit $status"; A_OK=0
    elif [[ $inner_uid != "$UID_NOW" ]]; then record a_exec fail "uid inside is $inner_uid, expected $UID_NOW"; A_OK=0
    elif grep -q '^nvidia' <<<"$exec_out"; then record a_exec fail "/dev holds nvidia devices"; A_OK=0
    else record a_exec pass "uid $inner_uid, minimal /dev"; fi
    list_out=$(limit 60 "$RUNTIME" instance list --json "$INSTANCE_NAME" 2>&1)
    if python3 -I -c 'import json, sys
names = [i.get("instance", i.get("name")) for i in json.loads(sys.stdin.read()).get("instances", [])]
sys.exit(sys.argv[1] not in names)' "$INSTANCE_NAME" <<<"$list_out" 2>/dev/null; then
      record a_instance_list pass
    else
      printf '%s\n' "$list_out" | tail -5; record a_instance_list fail "the JSON listing does not name the instance"; A_OK=0
    fi
    if limit 120 "$RUNTIME" instance stop --force "$INSTANCE_NAME" >/dev/null 2>&1; then
      INSTANCE_STARTED=0; record a_instance_stop pass
    else
      record a_instance_stop fail "instance stop --force failed"; A_OK=0
    fi
  fi
fi
value A_FLAVOR "$A_FLAVOR"

section "path B: enroot without --root"
B_DIR=$PROBE_ROOT/enroot
mkdir -p "$B_DIR/data" "$B_DIR/cache" "$B_DIR/tmp"
B_OK=0
if ! have enroot; then
  record b_enroot fail "enroot is not on PATH"
else
  record b_enroot pass "$(enroot version 2>/dev/null | head -1)"
  export ENROOT_DATA_PATH=$B_DIR/data ENROOT_CACHE_PATH=$B_DIR/cache ENROOT_TEMP_PATH=$B_DIR/tmp
  B_OK=1
  if [[ -n ${FRONTIER_PROBE_SQSH:-} ]]; then
    SQSH=$FRONTIER_PROBE_SQSH; record b_import pass "local $SQSH"
  else
    SQSH=$B_DIR/p.sqsh
    if out=$(limit 900 enroot import -o "$SQSH" docker://alpine:3.20 2>&1); then record b_import pass
    else printf '%s\n' "$out" | tail -10; record b_import fail "enroot import failed"; B_OK=0; fi
  fi
  if ((B_OK)); then
    if out=$(limit 300 enroot create -n "$ENROOT_NAME" "$SQSH" 2>&1); then ENROOT_CREATED=1; record b_create pass
    else printf '%s\n' "$out" | tail -10; record b_create fail "enroot create failed"; B_OK=0; fi
  else
    record b_create skip
  fi
  if ((B_OK)); then
    inner_uid=$(limit 120 enroot start --rw "$ENROOT_NAME" id -u 2>&1 | tail -1)
    if [[ $inner_uid == "$UID_NOW" ]]; then record b_start pass "uid $inner_uid"
    else record b_start fail "uid inside is ${inner_uid:-none}, expected $UID_NOW"; B_OK=0; fi
    if limit 120 enroot remove -f "$ENROOT_NAME" >/dev/null 2>&1; then ENROOT_CREATED=0; record b_remove pass
    else record b_remove fail "enroot remove failed"; B_OK=0; fi
  else
    record b_start skip; record b_remove skip
  fi
fi

if ((A_OK)) && [[ $A_FLAVOR == singularity ]]; then PATH_VERDICT=A-singularity
elif ((A_OK)) && [[ $A_FLAVOR == apptainer ]]; then PATH_VERDICT=A-apptainer
else PATH_VERDICT=B; fi
STOP=0
[[ $CGROUP_TYPE == 0 ]] || STOP=1

echo
echo "=== FRONTIER_SITE_PROBE BEGIN ==="
echo "PATH=$PATH_VERDICT"
echo "PATH_B_READY=$( ((B_OK)) && echo yes || echo no)"
echo "CGROUP_TYPE=$CGROUP_TYPE"
echo "CPUS=${VALUE[CPUS]}"
echo "STOP=$STOP"
for key in CGROUP_VERSION USER_DBUS CPU_MODEL MEM_TOTAL_GIB NODE_LOCAL_FREE_GIB NODE_LOCAL_FSTYPE ULIMIT_NOFILE \
    ULIMIT_NPROC ULIMIT_VMEM A_RUNTIME A_VERSION A_FLAVOR A_PIDFILE_PROCESS A_INSTANCE_TITLE; do
  [[ -n ${VALUE[$key]+x} ]] && printf '%s=%s\n' "$key" "${VALUE[$key]}"
done
echo "HOST=$(hostname)"
for check in "${CHECKS[@]}"; do printf 'CHECK_%s=%s\n' "$check" "${STATUS[$check]}"; done
echo "=== FRONTIER_SITE_PROBE END ==="
