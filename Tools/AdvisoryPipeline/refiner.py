#!/usr/bin/env python3
# @file
#
# Component (iv): the refinement loop. Structurally this is PoCGen's Fig. 7
# algorithm (priority queue of prompts, scored by how much new information
# each attempt surfaced, capped at a fixed number of refinements) — reused
# here to drive harness generation instead of exploit generation. Build
# errors, fuzz-reachability, and crash/no-crash feedback stand in for
# PoCGen's error/coverage/debugger refiners.
#
# Copyright (c) 2025-2026 TianoShield Contributors.
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
import dataclasses
import heapq
import itertools
import json
import os
import shutil
import sys
import tempfile
from typing import List, Optional

sys.path.insert(0, os.path.dirname(__file__))
import harness_generator  # noqa: E402
import validator  # noqa: E402
import sanity_check  # noqa: E402
import evaluate_generated as eg  # noqa: E402  -- reuse its harness placement
                                  # + DSC component registration instead of
                                  # duplicating that logic here. Without this,
                                  # refiner.py computed inf_relpath as a
                                  # relative path from the attempt_N/ scratch
                                  # dir (outside the real package tree) and
                                  # never registered the harness in
                                  # HBFAplus.dsc at all -- every attempt
                                  # failed with "file not found in packages
                                  # path" before the LLM's code was ever
                                  # actually compiled.

MAX_ATTEMPTS = 10  # PoCGen used 30; UEFI builds are much slower per-attempt,
                    # so a smaller budget keeps wall-clock time reasonable.


@dataclasses.dataclass
class RefinementOutcome:
    advisory_id: str
    module: str
    attempts: int
    verdict: str          # "confirmed" | "exhausted"
    out_dir: Optional[str]
    final_reason: str
    history: List[dict] = dataclasses.field(default_factory=list)
    # One entry per attempt: {"attempt": N, "out_dir": ..., "verdict": ...,
    # "reason": ...} — "verdict" here includes "generation_error" for a
    # rejected/failed candidate (wrong module, parse failure, etc.), not
    # just validator.py's build/fuzz verdicts. Kept because run_report.json
    # previously only surfaced the *last* attempt's reason, losing exactly
    # the information needed to debug a promising-but-failed earlier
    # attempt once a later, differently-failing attempt overwrote it.
    standalone_poc_c: Optional[str] = None
    standalone_poc_inf: Optional[str] = None
    standalone_poc_build_ok: Optional[bool] = None
    # Only set when verdict == "confirmed" — the final, self-contained
    # single-file PoC from poc_packager.py (harness logic + the winning
    # bytes baked in as a literal array, no AFL++/input-file dependency).
    # standalone_poc_build_ok reflects a real build attempt against a
    # fresh pre-fix worktree (see run_refinement_loop) — None means the
    # build was never attempted (e.g. packaging itself failed first),
    # not "unknown/skipped for no reason."


def _score(build_ok: bool, verdict: str) -> int:
    """Lower score = tried sooner. Prioritize attempts that got further:
    a build failure is the least informative outcome (retry it last), a
    build that succeeds but doesn't reach the crash is more promising, and
    a reproduced-but-not-regression-tested result is nearly done."""
    if not build_ok:
        return 3
    if verdict == "no_repro":
        return 2
    if verdict == "not_regression_tested":
        return 1
    return 0


def run_refinement_loop(advisory: dict, target: dict, edk2_checkout: str,
                         fix_commit: str, seed_dir: str,
                         out_dir_base: str, hbfaplus_source: str,
                         sibling_dir: Optional[str] = None,
                         fuzz_duration_s: int = 120,
                         max_attempts: int = MAX_ATTEMPTS,
                         codeql_db_path: Optional[str] = None,
                         codeql_cache_root: Optional[str] = None,
                         skip_codeql: bool = False,
                         use_afl_fallback: bool = True) -> RefinementOutcome:
    pre_fix_commit = None
    from github_advisories import get_pre_fix_commit  # local import to avoid
    token = os.environ.get("GITHUB_API_KEY") or os.environ.get("GITHUB_TOKEN")
    pre_fix_commit = get_pre_fix_commit(fix_commit, token)
    if not pre_fix_commit:
        return RefinementOutcome(
            advisory_id=advisory.get("ghsa_id", "?"), module=target.get("module", "?"),
            attempts=0, verdict="exhausted",
            out_dir=None, final_reason="Could not resolve the fix commit's parent "
                                        "(pre-fix) revision.",
            history=[],
        )

    # Auto-build (or reuse a cached) CodeQL database instead of requiring a
    # manually-run `codeql_taint.py create-db` beforehand — one build per
    # (package, module, revision), shared across every attempt in this run
    # and across future advisories that touch the same module/revision.
    if not codeql_db_path and edk2_checkout and not skip_codeql:
        import codeql_taint
        cache_root = codeql_cache_root or os.path.join(hbfaplus_source, "output",
                                                         "codeql_dbs")
        codeql_db_path = codeql_taint.get_or_create_database(
            edk2_checkout, target.get("package"), target.get("module"),
            pre_fix_commit, cache_root,
        )  # returns None (never raises) if CodeQL isn't available or the
           # build fails — harness_generator.py falls back to tiers 2/3 or
           # raw source either way.

    counter = itertools.count()
    # Seed queue with an empty feedback string (first, unrefined attempt).
    queue = [(0, next(counter), "")]
    seen_feedback = set()
    attempts = 0
    last_reason = "no attempts made"
    history: List[dict] = []

    while queue and attempts < max_attempts:
        _priority, _tie, feedback = heapq.heappop(queue)
        attempts += 1
        attempt_dir = os.path.join(out_dir_base, f"attempt_{attempts}")

        try:
            gen_result = harness_generator.generate(
                advisory, target, attempt_dir,
                edk2_checkout=edk2_checkout, pre_fix_commit=pre_fix_commit,
                sibling_dir=sibling_dir, extra_context=feedback,
                codeql_db_path=codeql_db_path, fix_commit=fix_commit,
            )
        except Exception as e:  # LLM/parse failure — feed the error back in
            new_feedback = f"Previous attempt failed to generate valid " \
                            f"output: {e}"
            history.append({"attempt": attempts, "out_dir": None,
                             "verdict": "generation_error", "reason": str(e)})
            if new_feedback not in seen_feedback:
                seen_feedback.add(new_feedback)
                heapq.heappush(queue, (3, next(counter), new_feedback))
            last_reason = str(e)
            continue

        inf_relpath = eg._place_harness_for_build(
            gen_result["c_path"], gen_result["inf_path"],
            target.get("package"), target.get("module"))
        eg._ensure_component_registered(inf_relpath)

        with open(gen_result["c_path"]) as f:
            harness_source_for_guessing = f.read()

        def _direct_guess(binary_path, _advisory=advisory, _target=target,
                           _harness_source=harness_source_for_guessing):
            # PoCGen-style: LLM proposes a specific candidate input, tested
            # directly, refined guess-by-guess — tried before falling back
            # to AFL++'s blind search. Best-effort: any failure here (LLM
            # error, parse error, etc.) just means "fall through to AFL++,"
            # never blocks the pipeline.
            try:
                import poc_guesser
                # Reuse harness_generator's already-computed (and memoized)
                # usage-context / source-snippets — these are PoCGen's own
                # usageSnippets/taintPathSnippets prompt slots; without
                # them the guess prompt only had the advisory's prose and
                # the harness's byte-reading shape, with no view of the
                # actual vulnerable code the guess needs to reason about.
                usage_ctx = harness_generator._usage_context_cache.get(
                    (edk2_checkout, pre_fix_commit, fix_commit,
                     _target.get("changed_source_files", [""])[0]),
                    "(not computed for this target)",
                )
                src_snippets = harness_generator.get_source_snippets(
                    _advisory, _target, edk2_checkout, pre_fix_commit,
                    codeql_db_path,
                )
                return poc_guesser.guess_and_test_loop(
                    binary_path, _advisory, _target, _harness_source,
                    max_guesses=4, usage_context=usage_ctx,
                    source_snippets=src_snippets,
                )
            except Exception as e:
                print(f"[!] Direct PoC-guessing unavailable, falling back "
                      f"to AFL++ search: {e}", file=sys.stderr)
                return None

        result = validator.validate(
            edk2_checkout=edk2_checkout, pre_fix_commit=pre_fix_commit,
            fix_commit=fix_commit, inf_relpath=inf_relpath, seed_dir=seed_dir,
            hbfaplus_source=hbfaplus_source, duration_s=fuzz_duration_s,
            direct_guess_fn=_direct_guess, use_afl_fallback=use_afl_fallback,
        )
        last_reason = result.reason

        if result.verdict == "confirmed":
            with open(gen_result["c_path"]) as f:
                harness_source = f.read()
            sanity = sanity_check.check(
                advisory, target, harness_source,
                result.pre_fix.asan_summary, result.pre_fix.stderr_tail,
            )
            if sanity.passed:
                history.append({"attempt": attempts, "out_dir": attempt_dir,
                                 "verdict": "confirmed", "reason": result.reason})

                # Package the final, self-contained single-file PoC — see
                # poc_packager.py. Best-effort: any failure here is logged
                # but never invalidates the confirmed verdict itself, which
                # already stands on the harness+input pair validator.py
                # just checked.
                #
                # To actually verify the standalone file builds, spin up a
                # fresh pre-fix worktree using validator.py's own private
                # helpers (the exact same machinery validate() used
                # internally, already torn down by the time we get here) —
                # rather than duplicating that logic, or modifying
                # validate() to keep its worktree alive past its own
                # return, which would couple two independent verdicts
                # (mechanical confirmation vs. standalone-packaging
                # convenience) together more tightly than they should be.
                standalone_info = {}
                build_wt = tempfile.mkdtemp(prefix="edk2_standalone_")
                try:
                    validator._add_worktree(edk2_checkout, pre_fix_commit, build_wt)
                    build_ws = validator._prepare_workspace(build_wt, hbfaplus_source)
                    import poc_packager
                    standalone_info = poc_packager.package_standalone_poc(
                        attempt_dir=attempt_dir,
                        harness_inf_path=gen_result["inf_path"],
                        harness_c_path=gen_result["c_path"],
                        crash_input_path=result.pre_fix.crash_input,
                        target=target, advisory=advisory,
                        workspace=build_ws, try_build=True,
                    )
                except Exception as e:
                    print(f"[!] Standalone PoC packaging failed (confirmed "
                          f"verdict is unaffected): {e}", file=sys.stderr)
                finally:
                    validator._remove_worktree(edk2_checkout, build_wt)
                    shutil.rmtree(build_wt, ignore_errors=True)

                return RefinementOutcome(
                    advisory_id=advisory.get("ghsa_id", "?"),
                    module=target.get("module", "?"),
                    attempts=attempts, verdict="confirmed",
                    out_dir=attempt_dir, final_reason=result.reason,
                    history=history,
                    standalone_poc_c=standalone_info.get("standalone_c_path"),
                    standalone_poc_inf=standalone_info.get("standalone_inf_path"),
                    standalone_poc_build_ok=standalone_info.get("build_ok"),
                )
            # PoCGen's exact rationale for this step: a mechanically valid
            # result isn't necessarily the *right* result. Treat this like
            # any other refinement signal rather than silently discarding
            # a working harness — feed the LLM's own stated objection back
            # in as feedback for the next attempt.
            last_reason = (f"Sanity check rejected an otherwise-mechanically-"
                            f"valid result: {sanity.reasoning}")
            history.append({"attempt": attempts, "out_dir": attempt_dir,
                             "verdict": "sanity_check_rejected", "reason": last_reason})
            feedback_text = (
                "The previous harness reproduced a crash that passed the "
                "mechanical build/fuzz validator, but a review flagged it as "
                f"likely NOT the advisory's actual vulnerability:\n"
                f"{sanity.reasoning}\n"
                "Adjust the harness so the crash is specific to the "
                "advisory's described defect, not an unrelated bug."
            )
            if feedback_text not in seen_feedback:
                seen_feedback.add(feedback_text)
                heapq.heappush(queue, (0, next(counter), feedback_text))
            continue

        # Build feedback for the next attempt, matching PoCGen's refiners:
        # build errors -> "error refiner"; no-crash -> "coverage refiner"
        # equivalent (tell it what it needs to reach); still-crashing
        # post-fix -> tell it the fix likely touches different logic.
        if result.verdict == "build_failed":
            feedback_text = ("The previous harness failed to build:\n"
                              f"{result.pre_fix.stderr_tail}\n"
                              "Fix the INF's [LibraryClasses]/[Packages] or "
                              "the C source's includes/API usage accordingly.")
        elif result.verdict == "no_repro":
            feedback_text = ("The previous harness built and ran but never "
                              "crashed within the time budget. It likely "
                              "isn't reaching the changed lines — check "
                              "whether the fuzz buffer is actually routed "
                              "into the code path the fix touches, and "
                              "whether any earlier validation in the driver "
                              "is rejecting the input before it gets there.")
        else:  # not_regression_tested
            feedback_text = ("The previous harness reproduced a crash "
                              f"pre-fix ({result.pre_fix.asan_summary}), but "
                              f"{result.reason} Adjust the harness so the "
                              "crash is specific to the lines the fix "
                              "changed.")

        relevant_log = (
            (result.post_fix.stderr_tail if result.post_fix and result.post_fix.stderr_tail
             else None)
            or result.pre_fix.stderr_tail
            or ""
        )
        history.append({"attempt": attempts, "out_dir": attempt_dir,
                         "verdict": result.verdict, "reason": result.reason,
                         "build_or_execution_log": relevant_log[-4000:]})

        if feedback_text not in seen_feedback:
            seen_feedback.add(feedback_text)
            heapq.heappush(queue, (_score(True, result.verdict), next(counter), feedback_text))

    return RefinementOutcome(
        advisory_id=advisory.get("ghsa_id", "?"), module=target.get("module", "?"),
        attempts=attempts, verdict="exhausted", out_dir=None,
        final_reason=last_reason, history=history,
    )


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--advisory-json", required=True)
    parser.add_argument("--target-json", required=True)
    parser.add_argument("--edk2-checkout", required=True)
    parser.add_argument("--fix-commit", required=True)
    parser.add_argument("--seed-dir", required=True)
    parser.add_argument("--out-dir-base", required=True)
    parser.add_argument("--hbfaplus-source",
                         default=os.path.abspath(os.path.join(
                             os.path.dirname(__file__), "..", "..")))
    parser.add_argument("--sibling-dir")
    parser.add_argument("--fuzz-duration", type=int, default=120)
    parser.add_argument("--max-attempts", type=int, default=MAX_ATTEMPTS)
    parser.add_argument("--codeql-db", help="Explicit CodeQL database path, to skip "
                                             "auto-build/caching and force a specific "
                                             "database (e.g. one you built by hand with "
                                             "codeql_taint.py create-db). Omit this to "
                                             "let the pipeline auto-build and cache one "
                                             "per package/module/revision.")
    parser.add_argument("--codeql-cache-root",
                         help="Where auto-built CodeQL databases are cached "
                              "(default: <hbfaplus-source>/output/codeql_dbs)")
    args = parser.parse_args()

    with open(args.advisory_json) as f:
        advisory = json.load(f)
    with open(args.target_json) as f:
        target = json.load(f)

    outcome = run_refinement_loop(
        advisory, target, args.edk2_checkout, args.fix_commit, args.seed_dir,
        args.out_dir_base, args.hbfaplus_source, args.sibling_dir,
        args.fuzz_duration, args.max_attempts, args.codeql_db,
        args.codeql_cache_root,
    )
    print(json.dumps(dataclasses.asdict(outcome), indent=2))


if __name__ == "__main__":
    main()
