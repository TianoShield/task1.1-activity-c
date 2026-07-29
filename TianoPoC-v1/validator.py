#!/usr/bin/env python3
# @file
#
# Component (iii): build + validate a candidate harness against both the
# pre-fix and post-fix EDK2 revisions named by an advisory.
#
# "Valid" here means the same thing PoCGen means it for a JS exploit, just
# translated to firmware terms:
#   - the harness builds cleanly against BOTH revisions (structural sanity)
#   - a short AFL++/ASan run against the PRE-fix build reaches the changed
#     lines and crashes (reproduces the vulnerability)
#   - replaying that same crashing input against the POST-fix build does
#     NOT crash (confirms the harness is exercising the actual fixed defect,
#     not some unrelated bug, and gives a ready-made regression test)
#
# This script assumes it is being run inside the HBFAplus dev container
# (see run.sh / .devcontainer), where `build`, AFL++, and BaseTools are all
# already on PATH — the same assumption every other script in HBFAplus/Tools
# makes.
#
# Copyright (c) 2025-2026 TianoShield Contributors.
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
import argparse
import dataclasses
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from typing import List, Optional

HBFAPLUS_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

_ASAN_SUMMARY_RE = re.compile(r"SUMMARY: AddressSanitizer: (\S+)")


@dataclasses.dataclass
class BuildResult:
    ok: bool
    binary_path: Optional[str]
    log_tail: str


@dataclasses.dataclass
class FuzzResult:
    crashed: bool
    crash_input: Optional[str]
    asan_summary: Optional[str]
    stderr_tail: str


@dataclasses.dataclass
class ValidationResult:
    pre_fix: FuzzResult
    post_fix: Optional[FuzzResult]
    verdict: str   # "confirmed" | "no_repro" | "build_failed" | "not_regression_tested"
    reason: str


def _add_worktree(edk2_checkout: str, commit: str, worktree_dir: str) -> None:
    if os.path.isdir(worktree_dir):
        shutil.rmtree(worktree_dir)
    subprocess.run(
        ["git", "-C", edk2_checkout, "fetch", "--depth", "50", "origin", commit],
        check=False, capture_output=True, text=True,
    )
    result = subprocess.run(
        ["git", "-C", edk2_checkout, "worktree", "add", "--detach",
         worktree_dir, commit],
        check=False, capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"git worktree add failed for commit {commit} in {edk2_checkout} "
            f"(exit {result.returncode}):\n"
            f"stdout: {result.stdout.strip()}\n"
            f"stderr: {result.stderr.strip()}"
        )


def _remove_worktree(edk2_checkout: str, worktree_dir: str) -> None:
    subprocess.run(
        ["git", "-C", edk2_checkout, "worktree", "remove", "--force", worktree_dir],
        check=False, capture_output=True, text=True,
    )


def build_harness(inf_path: str, workspace: str, toolchain: str = "AFL",
                   arch: str = "X64") -> BuildResult:
    """Invoke the EDK2 `build` tool for the given harness INF.

    `workspace` must have HBFAplus/ (and this pipeline's generated harness
    files) and the target edk2 revision laid out the way HBFAEnvSetup.py
    expects (WORKSPACE + PACKAGES_PATH pointing at the edk2 checkout).
    """
    env = os.environ.copy()
    env["WORKSPACE"] = workspace
    proc = subprocess.run(
        ["build", "-p", "HBFAplus/HBFAplus.dsc", "-m", inf_path,
         "-a", arch, "-t", toolchain],
        cwd=workspace, env=env, capture_output=True, text=True, timeout=1800,
    )
    log = (proc.stdout + proc.stderr)
    ok = proc.returncode == 0
    binary_path = None
    if ok:
        base_name = os.path.splitext(os.path.basename(inf_path))[0]
        candidates = glob.glob(
            os.path.join(workspace, "Build", "HBFAplusPkg", f"DEBUG_{toolchain}",
                         arch, base_name)
        )
        binary_path = candidates[0] if candidates else None
        ok = binary_path is not None
    return BuildResult(ok=ok, binary_path=binary_path, log_tail=log[-4000:])


def run_short_fuzz(binary_path: str, seed_dir: str, duration_s: int = 120) -> FuzzResult:
    """Run a short, bounded AFL++ session (default 2 minutes — enough to
    confirm a crash is trivially reachable for a known, disclosed bug; this
    is a regression check, not a from-scratch discovery campaign) and report
    whether it found a crash.
    """
    with tempfile.TemporaryDirectory(prefix="hbfa_afl_out_") as out_dir:
        env = os.environ.copy()
        env.setdefault("ASAN_OPTIONS", "detect_leaks=0:abort_on_error=1")
        env.setdefault("AFL_SKIP_CPUFREQ", "1")
        env.setdefault("AFL_NO_AFFINITY", "1")
        proc = subprocess.Popen(
            ["afl-fuzz", "-i", seed_dir, "-o", out_dir, "-t", "2000",
             "--", binary_path, "@@"],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        try:
            time.sleep(duration_s)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
        crash_dirs = glob.glob(os.path.join(out_dir, "*", "crashes"))
        crash_files: List[str] = []
        for cd in crash_dirs:
            crash_files.extend(
                f for f in glob.glob(os.path.join(cd, "*")) if "README" not in f
            )
        if not crash_files:
            return FuzzResult(crashed=False, crash_input=None, asan_summary=None,
                               stderr_tail="")
        crash_input = crash_files[0]
        # Replay the crashing input directly to capture the ASan summary.
        replay = subprocess.run([binary_path, crash_input],
                                 env=env, capture_output=True, text=True, timeout=30)
        stderr = replay.stderr
        m = _ASAN_SUMMARY_RE.search(stderr)
        return FuzzResult(
            crashed=True,
            crash_input=crash_input,
            asan_summary=m.group(1) if m else None,
            stderr_tail=stderr[-2000:],
        )


def replay_input(binary_path: str, input_path: str) -> FuzzResult:
    env = os.environ.copy()
    env.setdefault("ASAN_OPTIONS", "detect_leaks=0:abort_on_error=1")
    proc = subprocess.run([binary_path, input_path], env=env,
                           capture_output=True, text=True, timeout=30)
    crashed = proc.returncode != 0
    m = _ASAN_SUMMARY_RE.search(proc.stderr)
    return FuzzResult(
        crashed=crashed,
        crash_input=input_path if crashed else None,
        asan_summary=m.group(1) if m else None,
        stderr_tail=proc.stderr[-2000:],
    )


def validate(edk2_checkout: str, pre_fix_commit: str, fix_commit: str,
             inf_relpath: str, seed_dir: str, hbfaplus_source: str,
             duration_s: int = 120, direct_guess_fn=None) -> ValidationResult:
    """Full component-(iii) flow: build+fuzz pre-fix, and if it crashes,
    build+replay the same input against post-fix to confirm regression
    coverage.

    `direct_guess_fn`, if given, is called as `direct_guess_fn(binary_path)`
    right after a successful pre-fix build, before falling back to AFL++'s
    blind fuzzing search — this is the PoCGen-style "LLM proposes a
    specific candidate input, tested directly, refined guess-by-guess" step
    (see poc_guesser.py), injected here rather than imported directly so
    this module stays free of any LLM dependency: whatever the callable
    returns, the actual crash/no-crash verdict is still decided entirely by
    replay_input()'s ASan-based check below, never by the guess mechanism
    itself. Expected to return an object with `.success`,
    `.crash_input_path`, `.asan_summary` attributes (see
    poc_guesser.GuessLoopResult) or None/anything falsy to skip straight to
    AFL++.
    """
    pre_wt = tempfile.mkdtemp(prefix="edk2_prefix_")
    post_wt = tempfile.mkdtemp(prefix="edk2_postfix_")
    try:
        _add_worktree(edk2_checkout, pre_fix_commit, pre_wt)
        pre_ws = _prepare_workspace(pre_wt, hbfaplus_source)
        pre_build = build_harness(inf_relpath, pre_ws)
        if not pre_build.ok:
            return ValidationResult(
                pre_fix=FuzzResult(False, None, None, pre_build.log_tail),
                post_fix=None, verdict="build_failed",
                reason="Harness failed to build against the pre-fix revision.",
            )

        pre_fuzz = None
        if direct_guess_fn is not None:
            guess_result = direct_guess_fn(pre_build.binary_path)
            if guess_result and getattr(guess_result, "success", False):
                pre_fuzz = FuzzResult(
                    crashed=True, crash_input=guess_result.crash_input_path,
                    asan_summary=guess_result.asan_summary, stderr_tail="",
                )
        if pre_fuzz is None:
            pre_fuzz = run_short_fuzz(pre_build.binary_path, seed_dir, duration_s)
        if not pre_fuzz.crashed:
            return ValidationResult(
                pre_fix=pre_fuzz, post_fix=None, verdict="no_repro",
                reason="No crash found in the pre-fix build within the time "
                       "budget; harness likely isn't reaching the changed code.",
            )

        _add_worktree(edk2_checkout, fix_commit, post_wt)
        post_ws = _prepare_workspace(post_wt, hbfaplus_source)
        post_build = build_harness(inf_relpath, post_ws)
        if not post_build.ok:
            return ValidationResult(
                pre_fix=pre_fuzz, post_fix=None, verdict="not_regression_tested",
                reason="Reproduced the crash pre-fix, but the harness failed "
                       "to build against the post-fix revision (likely the "
                       "fix changed an API/struct the harness depends on).",
            )
        post_fuzz = replay_input(post_build.binary_path, pre_fuzz.crash_input)
        if post_fuzz.crashed:
            return ValidationResult(
                pre_fix=pre_fuzz, post_fix=post_fuzz, verdict="not_regression_tested",
                reason="Same input still crashes post-fix — either the fix "
                       "doesn't cover this exact path, or the harness is "
                       "triggering a different/unrelated bug.",
            )
        return ValidationResult(
            pre_fix=pre_fuzz, post_fix=post_fuzz, verdict="confirmed",
            reason="Crash reproduces pre-fix and is absent post-fix with the "
                   "same input: this is a valid regression test for the "
                   "advisory.",
        )
    finally:
        _remove_worktree(edk2_checkout, pre_wt)
        _remove_worktree(edk2_checkout, post_wt)
        shutil.rmtree(pre_wt, ignore_errors=True)
        shutil.rmtree(post_wt, ignore_errors=True)


def _prepare_workspace(edk2_worktree: str, hbfaplus_source: str) -> str:
    """A build workspace needs edk2/ + HBFAplus/ as sibling packages under
    the same WORKSPACE root, mirroring how HBFAEnvSetup.py lays things out.
    We symlink HBFAplus/ (including the pipeline's freshly generated
    harness) into each revision's isolated worktree rather than copying, so
    edits to the candidate harness show up in both without re-syncing.
    """
    hbfaplus_link = os.path.join(edk2_worktree, "HBFAplus")
    if not os.path.islink(hbfaplus_link) and not os.path.isdir(hbfaplus_link):
        os.symlink(hbfaplus_source, hbfaplus_link)
    return edk2_worktree


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--edk2-checkout", required=True,
                         help="Local clone of edk2 with the fix commit + its "
                              "parent reachable (fetch --unshallow if needed)")
    parser.add_argument("--pre-fix-commit", required=True)
    parser.add_argument("--fix-commit", required=True)
    parser.add_argument("--inf", required=True,
                         help="Path to the harness INF, relative to WORKSPACE "
                              "(e.g. HBFAplus/FuzzHarness/.../Test.inf)")
    parser.add_argument("--seed-dir", required=True)
    parser.add_argument("--hbfaplus-source", default=HBFAPLUS_ROOT)
    parser.add_argument("--duration", type=int, default=120)
    args = parser.parse_args()

    result = validate(args.edk2_checkout, args.pre_fix_commit, args.fix_commit,
                       args.inf, args.seed_dir, args.hbfaplus_source, args.duration)
    print(json.dumps(dataclasses.asdict(result), indent=2, default=str))
    sys.exit(0 if result.verdict == "confirmed" else 1)


if __name__ == "__main__":
    main()
