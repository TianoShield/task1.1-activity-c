#!/usr/bin/env python3
# @file
#
# Best-effort mode: skip the entire build -> guess-and-execute -> AFL++ ->
# post-fix-rebuild -> sanity-check chain. Ask the LLM for a harness, ask it
# for one specific exploit input, package both into a standalone .c file
# immediately. No Docker, no compile, no worktrees, no wait beyond two LLM
# calls.
#
# This trades every guarantee validator.py provides (does it actually
# compile, does it actually crash, does the crash actually disappear
# post-fix) for speed. The result is explicitly and permanently labeled
# "unvalidated_best_effort" — never "confirmed" — precisely so it can
# never be mistaken for a real, tested result anywhere in a report.
#
# Copyright (c) 2025-2026 TianoShield Contributors.
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
import dataclasses
import os
import sys
from typing import Optional

sys.path.insert(0, os.path.dirname(__file__))
import github_advisories as gha  # noqa: E402
import target_mapper as tm  # noqa: E402
import harness_generator  # noqa: E402
import poc_guesser  # noqa: E402
import poc_packager  # noqa: E402

HBFAPLUS_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


@dataclasses.dataclass
class BestEffortResult:
    ghsa_id: str
    module: str
    verdict: str  # "unvalidated_best_effort" | "generation_failed" | "guess_failed" | error states
    reason: str
    harness_c: Optional[str] = None
    harness_inf: Optional[str] = None
    harness_reasoning: Optional[str] = None  # the model's own "why this works" from generation
    standalone_poc_c: Optional[str] = None
    standalone_poc_inf: Optional[str] = None
    guess_reasoning: Optional[str] = None


def run_best_effort(ghsa_id: str, edk2_checkout: str, out_dir_base: str,
                     token: Optional[str] = None,
                     codeql_db_path: Optional[str] = None) -> BestEffortResult:
    advisory = gha.fetch_advisory(ghsa_id, token)
    resolved = gha.resolve(advisory, token)
    if not resolved.fix_commit:
        return BestEffortResult(
            ghsa_id=ghsa_id, module="?", verdict="unresolvable",
            reason="No fix commit could be resolved from the advisory's references.",
        )

    targets = tm.map_files_to_targets(resolved.changed_files)
    if not targets:
        return BestEffortResult(
            ghsa_id=ghsa_id, module="?", verdict="no_edk2_files",
            reason="The fix commit touched no recognizable EDK2 package/module path.",
        )
    # Best-effort mode is explicitly about speed: one target, not every
    # target the advisory's fix commit touched.
    target = targets[0]

    pre_fix_commit = gha.get_pre_fix_commit(resolved.fix_commit, token)

    sibling = None
    if target.existing_harnesses:
        sibling = os.path.dirname(
            os.path.join(tm.FUZZ_HARNESS_ROOT, target.existing_harnesses[0]))
    else:
        candidates = tm.find_sibling_examples(target.package, target.module)
        sibling = candidates[0] if candidates else None

    out_dir = os.path.join(out_dir_base, ghsa_id,
                            f"{target.package}_{target.module}_best_effort")
    advisory_dict = dataclasses.asdict(advisory)
    target_dict = dataclasses.asdict(target)

    # --- One LLM call: the harness ------------------------------------
    try:
        gen_result = harness_generator.generate(
            advisory_dict, target_dict, out_dir,
            edk2_checkout=edk2_checkout, pre_fix_commit=pre_fix_commit,
            sibling_dir=sibling, codeql_db_path=codeql_db_path,
            fix_commit=resolved.fix_commit,
        )
    except Exception as e:
        return BestEffortResult(
            ghsa_id=ghsa_id, module=target.module, verdict="generation_failed",
            reason=f"Harness generation failed: {e}",
        )

    with open(gen_result["c_path"]) as f:
        harness_source = f.read()

    # Reuse the same (memoized) context computations the validated
    # pipeline uses, so a best-effort run and a validated run reason about
    # the same source/usage context — just skip everything downstream of
    # generation.
    usage_context = harness_generator._usage_context_cache.get(
        (edk2_checkout, pre_fix_commit, resolved.fix_commit,
         target_dict.get("changed_source_files", [""])[0]),
        None,
    )
    if usage_context is None:
        try:
            import usage_snippets
            first_file = target_dict.get("changed_source_files", [None])[0]
            diff_line = harness_generator._first_changed_line(
                edk2_checkout, pre_fix_commit, resolved.fix_commit, first_file)
            usage_context = (usage_snippets.build_usage_context(
                edk2_checkout, pre_fix_commit, first_file, diff_line)
                if diff_line else "(not available)") or "(not available)"
        except Exception:
            usage_context = "(not available)"

    source_snippets = harness_generator.get_source_snippets(
        advisory_dict, target_dict, edk2_checkout, pre_fix_commit, codeql_db_path)

    # --- One LLM call: the specific exploit input, no execution -------
    try:
        guessed_bytes, guess_reasoning = poc_guesser.propose_single_guess(
            advisory_dict, target_dict, harness_source, usage_context, source_snippets)
    except Exception as e:
        return BestEffortResult(
            ghsa_id=ghsa_id, module=target.module, verdict="guess_failed",
            reason=f"Could not get a specific exploit input from the LLM: {e}",
            harness_c=gen_result["c_path"], harness_inf=gen_result["inf_path"],
        )

    # --- Package immediately, no build attempt at all -----------------
    guess_path = os.path.join(out_dir, "guessed_input.bin")
    with open(guess_path, "wb") as f:
        f.write(guessed_bytes)

    standalone_info = {}
    try:
        standalone_info = poc_packager.package_standalone_poc(
            attempt_dir=out_dir,
            harness_inf_path=gen_result["inf_path"],
            harness_c_path=gen_result["c_path"],
            crash_input_path=guess_path,
            target=target_dict, advisory=advisory_dict,
            reasoning=guess_reasoning,
            try_build=False,  # the whole point of this mode: no compile
        )
    except Exception as e:
        return BestEffortResult(
            ghsa_id=ghsa_id, module=target.module, verdict="packaging_failed",
            reason=f"Standalone PoC packaging failed: {e}",
            harness_c=gen_result["c_path"], harness_inf=gen_result["inf_path"],
            guess_reasoning=guess_reasoning,
        )

    return BestEffortResult(
        ghsa_id=ghsa_id, module=target.module,
        verdict="unvalidated_best_effort",
        reason="Produced from a single harness-generation call and a single "
               "exploit-input guess, with NO build, NO execution, and NO "
               "crash confirmation of any kind. This may not compile, may "
               "not crash, and may not target the real bug even if it does "
               "crash. Use `pipeline.py run` for an actually-validated result.",
        harness_c=gen_result["c_path"], harness_inf=gen_result["inf_path"],
        standalone_poc_c=standalone_info.get("standalone_c_path"),
        standalone_poc_inf=standalone_info.get("standalone_inf_path"),
        guess_reasoning=guess_reasoning,
    )


def main():
    import argparse
    import json

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--advisory", required=True)
    parser.add_argument("--edk2-checkout", required=True)
    parser.add_argument("--out-dir-base", required=True)
    parser.add_argument("--codeql-db")
    args = parser.parse_args()

    token = os.environ.get("GITHUB_API_KEY") or os.environ.get("GITHUB_TOKEN")
    result = run_best_effort(args.advisory, args.edk2_checkout,
                              args.out_dir_base, token, args.codeql_db)
    print(json.dumps(dataclasses.asdict(result), indent=2))


if __name__ == "__main__":
    main()
