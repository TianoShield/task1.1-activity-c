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
    real_harness_for_comparison: Optional[str] = None
    # Only set when force_regenerate=True overrode an existing real
    # HBFAplus harness — the path to that real, hand-written harness, so
    # our LLM-generated one can be diffed directly against it.


def llm_explain_no_target(changed_files: list, advisory: dict) -> str:
    """Second opinion when target_mapper.py's deterministic path-parser
    finds nothing to target. That parser is pure regex against EDK2's
    typical module-naming suffixes (Dxe/Smm/Pei/Lib/Driver/Runtime) — it
    can miss a real target that just doesn't fit that pattern (an unusual
    filename, a header-only change, a module type the regex doesn't know
    about). Rather than trust the deterministic parser's silence as the
    final word, ask the LLM to actually look at the changed file list and
    give an independent judgment — and produce a real explanatory message
    either way, instead of a canned string.
    """
    import harness_generator  # reuse the one call_llm() implementation

    file_list = "\n".join(f"- {f}" for f in changed_files) or "(no files listed)"
    prompt = f"""\
A security fix commit touched these files:
{file_list}

## Advisory
{advisory.get('summary', '')}
{advisory.get('description', '')}

An automated path-based parser (looking for typical EDK2 driver/library
naming suffixes: Dxe, Smm, Pei, Lib, Driver, Runtime) found no recognizable
EDK2 module among these files.

Look at the actual file list yourself, independent of that parser. Answer
in 2-3 sentences:
- If you believe one of these files IS a real EDK2 driver, library, or
  module that a fuzz harness could target (even if its name doesn't match
  the typical suffixes), name the specific file and explain why.
- If not, briefly explain what these files actually appear to be (e.g.
  CI configuration, documentation, build scripts, test infrastructure)
  and why no fuzz harness target exists here.
"""
    try:
        return harness_generator.call_llm(
            prompt,
            system_prompt="You are a security engineer judging whether a "
                           "set of changed files includes any real EDK2 "
                           "firmware module a fuzz harness could target.",
        )
    except Exception as e:
        return f"(LLM review unavailable: {e})"


def run_best_effort(ghsa_id: str, edk2_checkout: str, out_dir_base: str,
                     token: Optional[str] = None,
                     codeql_db_path: Optional[str] = None,
                     force_regenerate: bool = False) -> BestEffortResult:
    advisory = gha.fetch_advisory(ghsa_id, token)
    resolved = gha.resolve(advisory, token)
    if not resolved.fix_commit:
        return BestEffortResult(
            ghsa_id=ghsa_id, module="?", verdict="unresolvable",
            reason="No fix commit could be resolved from the advisory's references.",
        )

    targets = tm.map_files_to_targets(resolved.changed_files)
    if not targets:
        llm_opinion = llm_explain_no_target(
            resolved.changed_files, dataclasses.asdict(advisory))
        return BestEffortResult(
            ghsa_id=ghsa_id, module="?", verdict="no_edk2_files",
            reason=f"Automated path parser found no recognizable EDK2 "
                   f"module. LLM second opinion: {llm_opinion}",
        )
    # Best-effort mode is explicitly about speed: one target, not every
    # target the advisory's fix commit touched.
    target = targets[0]

    real_harness_path = None
    if target.has_coverage and not force_regenerate:
        return BestEffortResult(
            ghsa_id=ghsa_id, module=target.module, verdict="already_covered",
            reason=f"HBFAplus already has a hand-written harness for "
                   f"{target.module} ({target.existing_harnesses[0] if target.existing_harnesses else '?'}); "
                   f"best-effort mode doesn't regenerate one when real "
                   f"coverage already exists. No LLM call made. Pass "
                   f"force_regenerate=True / --force to generate one "
                   f"anyway (e.g. to compare against the real one).",
        )
    if target.has_coverage and force_regenerate:
        # Preserve where the real one lives, so the eventual output can be
        # diffed against it directly — the whole point of forcing this.
        real_harness_path = (target.existing_harnesses[0]
                              if target.existing_harnesses else "(unknown)")

    pre_fix_commit = gha.get_pre_fix_commit(resolved.fix_commit, token)

    sibling = None
    if target.has_coverage and force_regenerate:
        # Leave-one-out: we're deliberately regenerating a harness for a
        # module that already has a real, hand-written one, specifically
        # to compare our LLM's independent attempt against it. Showing the
        # LLM that SAME real harness as its "sibling example" would leak
        # the expected answer directly — it wouldn't be generating
        # anything, just paraphrasing what it was just shown. Force
        # sibling selection through find_sibling_examples() instead, which
        # explicitly excludes the target module by name (see
        # target_mapper.py) and draws from genuinely different modules —
        # the same source of few-shot context the LLM would have if this
        # module had no coverage at all.
        candidates = tm.find_sibling_examples(target.package, target.module)
        sibling = candidates[0] if candidates else None
    elif target.existing_harnesses:
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
            # force_condensed intentionally left False (the default) here:
            # the user opted to keep the full prompt (full skill docs +
            # full sibling harness), accepting the associated timeout risk,
            # rather than trade context for speed. See harness_generator.py
            # build_prompt()'s force_condensed parameter if you want to
            # revisit this later.
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
        real_harness_for_comparison=(
            os.path.join(tm.FUZZ_HARNESS_ROOT, real_harness_path)
            if real_harness_path else None
        ),
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
