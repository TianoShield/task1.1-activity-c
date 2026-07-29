#!/usr/bin/env bash
# @file docker_run.sh
#
# Runs pipeline.py (or any AdvisoryPipeline script) *inside* the existing
# hbfa-dev container, from the host, the same way run.sh/build.sh drive
# docker compose for everything else in this repo.
#
# Why this exists: every script under AdvisoryPipeline/ (like every other
# script in HBFAplus/Tools/) assumes `build`, `afl-fuzz`, `codeql`, and a
# configured EDK2/BaseTools environment are already on PATH — i.e. that
# it's running *inside* the dev container. This wrapper is what actually
# talks to Docker, so you can call it straight from the host shell without
# manually `./run.sh`-ing into an interactive session first.
#
# Copyright (c) 2025-2026 TianoShield Contributors.
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# Usage (from the repo root, or anywhere — path is resolved automatically):
#   ./HBFAplus/Tools/AdvisoryPipeline/docker_run.sh scan --out scan_report.json
#   ./HBFAplus/Tools/AdvisoryPipeline/docker_run.sh run \
#       --edk2-checkout edk2-upstream \
#       --seed-dir HBFAplus/Seed/_default/Raw \
#       --advisory GHSA-xxxx-xxxx-xxxx
#
# IMPORTANT — path translation:
#   docker-compose.yml bind-mounts the *repo root* (one level above
#   HBFAplus/) to /home/builder/hbfa_workspace inside the container. Any
#   --edk2-checkout you pass MUST therefore live inside the repo root (e.g.
#   clone upstream edk2 to <repo-root>/edk2-upstream/, which is exactly what
#   the AdvisoryPipeline README recommends) — paths outside the repo root
#   aren't visible inside the container at all. Pass --edk2-checkout as a
#   path relative to the repo root (e.g. `edk2-upstream`), or as an absolute
#   host path under the repo root; this script rewrites it to the
#   container-side path either way. Absolute paths outside the repo root
#   will fail with a clear error rather than silently pointing at nothing.

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <pipeline.py subcommand and args...>" >&2
    echo "e.g.:  $0 scan --out scan_report.json" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# .../HBFAplus/Tools/AdvisoryPipeline -> repo root is three levels up
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/.devcontainer/docker-compose.yml"
CONTAINER_WORKSPACE="/home/builder/hbfa_workspace"

HOST_UID=$(id -u)
HOST_GID=$(id -g)
export HOST_UID HOST_GID

rewrite_edk2_checkout_arg() {
    # Rewrites a host-side path (relative to CWD, or absolute) that points
    # inside REPO_ROOT into the equivalent container-side path. Leaves
    # anything that isn't a path-like value untouched.
    local value="$1"
    local abs_host_path
    if [[ "${value}" = /* ]]; then
        abs_host_path="${value}"
    else
        abs_host_path="$(cd "$(dirname "${value}")" 2>/dev/null && pwd)/$(basename "${value}")" \
            || abs_host_path=""
    fi
    if [[ -z "${abs_host_path}" ]]; then
        echo "${value}"
        return
    fi
    case "${abs_host_path}" in
        "${REPO_ROOT}"/*)
            echo "${CONTAINER_WORKSPACE}/${abs_host_path#"${REPO_ROOT}"/}"
            ;;
        "${REPO_ROOT}")
            echo "${CONTAINER_WORKSPACE}"
            ;;
        *)
            echo "[!] --edk2-checkout (${value}) resolves outside the repo " \
                 "root (${REPO_ROOT}), so it will not be visible inside the " \
                 "container. Clone edk2 under the repo root instead (e.g. " \
                 "${REPO_ROOT}/edk2-upstream) — see AdvisoryPipeline/README.md." \
                 >&2
            exit 1
            ;;
    esac
}

# Rewrite `--edk2-checkout <path>` (and `--edk2-checkout=<path>`) in-place
# among the forwarded arguments; pass everything else through unchanged.
ARGS=()
i=0
while [[ $i -lt $# ]]; do
    arg="${@:$((i+1)):1}"
    if [[ "${arg}" == "--edk2-checkout" ]]; then
        ARGS+=("${arg}")
        i=$((i+1))
        next="${@:$((i+1)):1}"
        ARGS+=("$(rewrite_edk2_checkout_arg "${next}")")
    elif [[ "${arg}" == --edk2-checkout=* ]]; then
        ARGS+=("--edk2-checkout=$(rewrite_edk2_checkout_arg "${arg#--edk2-checkout=}")")
    else
        ARGS+=("${arg}")
    fi
    i=$((i+1))
done

echo "[i] Ensuring hbfa-dev container is up..." >&2
docker compose -f "${COMPOSE_FILE}" up -d hbfa-dev >&2

# Forward whichever of these the pipeline needs, if set on the host.
ENV_FORWARD=()
for var in GITHUB_API_KEY GITHUB_TOKEN OPENAI_API_KEY OPENAI_BASE_URL HBFA_LLM_MODEL; do
    if [[ -n "${!var:-}" ]]; then
        ENV_FORWARD+=(-e "${var}")
    fi
done

# Build the remote command as a single shell string so init_hbfa_env.sh runs
# in the same shell as pipeline.py (needed for WORKSPACE/PACKAGES_PATH/etc.).
printf -v QUOTED_ARGS '%q ' "${ARGS[@]}"
REMOTE_CMD="source ~/init_hbfa_env.sh >/dev/null 2>&1; \
cd HBFAplus/Tools/AdvisoryPipeline && python3 pipeline.py ${QUOTED_ARGS}"

exec docker compose -f "${COMPOSE_FILE}" exec -T "${ENV_FORWARD[@]+"${ENV_FORWARD[@]}"}" \
    hbfa-dev bash --login -c "${REMOTE_CMD}"
