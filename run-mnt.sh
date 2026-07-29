#!/usr/bin/env bash
# @file run-mnt.sh
#
# Disposable, unprivileged container runner for the AdvisoryPipeline —
# directly mirrors PoCGen's run-mnt.sh (see ../../../ or the PoCGen repo):
# one fresh --rm container per invocation, source mounted read-only, only an
# explicit output directory writable, .env for secrets.
#
# THIS is what should actually execute component (iii) (build + AFL++ +
# ASan against LLM-generated candidate harnesses) — not docker_run.sh.
# docker_run.sh execs into the long-lived hbfa-dev service, which runs
# --privileged with NET_ADMIN/SYS_ADMIN and network_mode: host (needed
# elsewhere in this repo for QEMU/TAP-based full-system tests). None of
# that is needed for host-based AFL++ fuzzing of a single native binary,
# and handing an LLM-generated, actively-fuzzed C binary that much
# privilege and host network access is a larger blast radius than the task
# requires. This script deliberately does NOT set --privileged, does NOT
# add NET_ADMIN/SYS_ADMIN, and does NOT use host networking.
#
# Copyright (c) 2025-2026 TianoShield Contributors.
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# Usage:
#   ./run-mnt.sh <output-dir> pipeline.py run \
#       --edk2-checkout /workspace/edk2-upstream \
#       --seed-dir HBFAplus/Seed/_default/Raw \
#       --advisory GHSA-xxxx-xxxx-xxxx \
#       --out-dir-base /output
#
#   ./run-mnt.sh scan_output pipeline.py scan --out /output/scan_report.json
#
# `<output-dir>` is a host path (created if missing); it's the ONLY thing
# mounted read-write besides the repo itself (see caveat below on why the
# repo can't be read-only here the way PoCGen's /app is).
#
# Requires a `.env` file in the repo root (same convention as PoCGen and as
# docker_run.sh's env forwarding):
#   GITHUB_API_KEY=...
#   OPENAI_API_KEY=...
#   OPENAI_BASE_URL=...
#   HBFA_LLM_MODEL=...

set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <output-dir> <command...>" >&2
    echo "e.g.:  $0 output pipeline.py scan --out /output/scan_report.json" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
IMAGE="${HBFA_PIPELINE_IMAGE:-edk2-hbfa:ubuntu22.04}"
ENV_FILE="${REPO_ROOT}/.env"

target_dir="$1"
shift
if [[ ! -d "${target_dir}" ]]; then
    mkdir -p "${target_dir}"
    chmod 777 "${target_dir}"
fi
# realpath needs the path to already exist on macOS/BSD (unlike GNU
# realpath, which tolerates a nonexistent target) — hence creating the
# directory above before resolving it here.
dst_dir="$(realpath "${target_dir}")"

ENV_FILE_ARGS=()
if [[ -f "${ENV_FILE}" ]]; then
    ENV_FILE_ARGS=(--env-file "${ENV_FILE}")
else
    echo "[!] No .env at ${ENV_FILE} — GITHUB_API_KEY/OPENAI_API_KEY/etc. " \
         "won't be available inside the container." >&2
fi

# --- What's genuinely different from run.sh/build.sh/docker_run.sh ---
#
# NOT set here, on purpose (unlike docker-compose.yml's hbfa-dev service):
#   --privileged            (not needed for host-based fuzzing)
#   --cap-add NET_ADMIN     (not needed — no TAP device creation happens here)
#   --cap-add SYS_ADMIN     (not needed)
#   --network host          (not needed — the harness is a plain fuzzed binary,
#                             not a network-facing process)
#   --device /dev/net/tun   (not needed)
#
# Caveat vs. PoCGen's `-v .:/app:ro`: PoCGen's dynamic analysis only ever
# writes to /output, so the source tree stays read-only. HBFAplus's build
# system writes compiled artifacts (Build/), AFL++'s own build
# (AFLplusplus/afl-fuzz), and BaseTools (edk2/BaseTools/Source/C/bin/) back
# into the workspace tree itself — that's how state persists across
# container invocations without a rebuild every time (see
# init_hbfa_env.sh). So the repo mount here has to be read-write. If you
# want PoCGen's stronger read-only-source guarantee, point WORKSPACE at a
# throwaway `git worktree`/copy per run instead of the primary checkout —
# validator.py already does exactly this for the edk2 checkout via git
# worktrees; consider doing the same for the whole workspace if you're
# running this against source you don't want touched.
docker run --rm \
    --name "hbfa_pipeline_$(head /dev/urandom | LC_ALL=C tr -dc A-Za-z0-9 | head -c 16)" \
    "${ENV_FILE_ARGS[@]+"${ENV_FILE_ARGS[@]}"}" \
    -e HOST_UID="$(id -u)" \
    -e HOST_GID="$(id -g)" \
    -v "${dst_dir}:/output:Z" \
    -v "${REPO_ROOT}:/home/builder/hbfa_workspace" \
    --tmpfs /tmp:exec,size=8g \
    --shm-size=1gb \
    --security-opt no-new-privileges \
    -w /home/builder/hbfa_workspace \
    "${IMAGE}" \
    bash --login -c "source ~/init_hbfa_env.sh >/dev/null 2>&1; \
cd HBFAplus/Tools/AdvisoryPipeline && python3 $(printf '%q ' "$@")"
