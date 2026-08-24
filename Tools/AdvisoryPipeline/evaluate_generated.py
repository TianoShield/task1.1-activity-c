#!/usr/bin/env python3
# @file
#
# Takes a harness/PoC that best_effort.py already generated (sitting under
# --out-dir-base, never touched by any LLM call in THIS module) and runs it
# through validator.py's real, deterministic pipeline: build against
# pre-fix, test the exact already-generated guess directly, fall back to
# AFL++ if that specific guess misses, then build post-fix and confirm.
#
# This is deliberately NOT the same as `pipeline.py run`: that regenerates
# a harness from scratch via harness_generator.py's retry loop, which may
# produce a DIFFERENT candidate than whatever's already sitting in
# best_effort's output (recall: we've seen real run-to-run variance from
# the same model on the same advisory this session). This module instead
# asks a narrower, more honest question: does THIS SPECIFIC artifact —
# the one already generated, already reviewed, already sitting on disk —
# actually compile and actually crash? No new LLM calls for the harness
# itself; the only LLM-produced thing reused here is the guess bytes
# best_effort.py already got.
#
# Copyright (c) 2025-2026 TianoShield Contributors.
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
import dataclasses
import os
import re
import shutil
import sys
from typing import Optional

sys.path.insert(0, os.path.dirname(__file__))
import github_advisories as gha  # noqa: E402
import target_mapper as tm  # noqa: E402
import validator  # noqa: E402

HBFAPLUS_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
EVAL_SUFFIX = "_LLMGenerated"  # never collides with a real existing harness dir


@dataclasses.dataclass
class EvaluationResult:
    ghsa_id: str
    module: str
    verdict: str  # "confirmed" | "not_regression_tested" | "no_repro" |
                  # "build_failed" | error states — same vocabulary as
                  # validator.py's real ValidationResult, since this module
                  # doesn't invent its own
    reason: str
    reused_guess_bytes_hex: Optional[str] = None
    build_or_execution_log: Optional[str] = None
    # The real compiler/build output (on build_failed) or the harness's own
    # stderr (on no_repro) — validator.py's ValidationResult only exposes a
    # generic reason string; the actual detail lives in
    # pre_fix.stderr_tail/post_fix.stderr_tail, which this module surfaces
    # explicitly rather than silently dropping. Capped to avoid bloating
    # every result with a full build log by default.


def _find_real_library_instance(edk2_checkout: str, library_class_name: str) -> Optional[str]:
    """Search edk2_checkout for a real .inf file whose [Defines] section
    declares LIBRARY_CLASS = <library_class_name> (with an optional
    |<consumer types> suffix, which we ignore). Returns the path relative
    to edk2_checkout, or None if no real implementation is found.
    """
    pattern = re.compile(
        rf"^\s*LIBRARY_CLASS\s*=\s*{re.escape(library_class_name)}\b",
        re.IGNORECASE | re.MULTILINE,
    )
    for dirpath, dirnames, filenames in os.walk(edk2_checkout):
        dirnames[:] = [d for d in dirnames if d not in (".git",)]
        for filename in filenames:
            if not filename.endswith(".inf"):
                continue
            full_path = os.path.join(dirpath, filename)
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except OSError:
                continue
            if pattern.search(text):
                return os.path.relpath(full_path, edk2_checkout)
    return None


def _ensure_library_class_registered(target_module: str, edk2_checkout: str) -> bool:
    """EDK2 requires every LibraryClass a module's .inf declares in its
    own [LibraryClasses] section to be resolved to a concrete instance,
    either via the platform DSC's global [LibraryClasses] section or a
    module-level override. Confirmed in production: error 4000, 'Instance
    of library class [X] is not found', when a generated harness declares
    a dependency on the very library class it's testing (a real, correct
    thing for it to do) but HBFAplus.dsc has never needed that class
    before, so no resolution exists anywhere.

    This finds the REAL upstream .inf that actually implements the class
    (rather than guessing/hardcoding a path) and adds the mapping to
    HBFAplus.dsc, idempotently.

    Returns True if the DSC was modified, False otherwise (already
    resolved, or no real implementation could be found — in which case
    the caller should expect the original error to resurface, now with a
    clear reason why).
    """
    dsc_path = os.path.join(HBFAPLUS_ROOT, "HBFAplus.dsc")
    with open(dsc_path, "r") as f:
        content = f.read()

    # Already resolved somewhere in the DSC (e.g. "DxeTpmMeasureBootLib|...")
    if re.search(rf"\b{re.escape(target_module)}\s*\|", content):
        return False

    real_inf_relpath = _find_real_library_instance(edk2_checkout, target_module)
    if not real_inf_relpath:
        return False  # nothing we can do; let the original error surface

    marker = "[LibraryClasses]"
    idx = content.find(marker)
    if idx == -1:
        raise RuntimeError(
            f"Could not find a [LibraryClasses] section in {dsc_path} to "
            f"register {target_module} — HBFAplus.dsc may have an "
            f"unexpected structure."
        )
    insert_at = idx + len(marker)
    new_content = (
        content[:insert_at]
        + f"\n  {target_module}|{real_inf_relpath}\n"
        + content[insert_at:]
    )
    with open(dsc_path, "w") as f:
        f.write(new_content)
    return True


def _ensure_component_registered(inf_relpath: str) -> bool:
    """EDK2's `build` command requires every module to be explicitly
    listed in the platform DSC's [Components] section — pointing `build
    -m` at a real, existing .inf file is not sufficient on its own
    (confirmed in production: error F002, 'Module ... is not a component
    of active platform'). Since we placed this harness ourselves under a
    brand-new directory, it was never added there.

    CRITICAL: HBFAplus.dsc describes a whole PLATFORM, and `build` parses
    and resolves every component listed in it, not just the one named by
    `-m`. So a previously-evaluated harness left registered here will
    fail the build of every LATER evaluation too, even ones testing a
    completely unrelated module. Confirmed in production: a batch run of
    7 advisories reported all 7 as build_failed with the identical error
    about one leftover harness from an earlier run — a totally invalid
    result caused purely by stale registration, not by the harnesses
    under test. So every previously-registered generated entry is purged
    before the current one is added, leaving exactly one at a time.

    Returns True if the DSC was modified.
    """
    dsc_path = os.path.join(HBFAPLUS_ROOT, "HBFAplus.dsc")
    with open(dsc_path, "r") as f:
        content = f.read()

    # Drop any component line we previously added. Ours are identifiable
    # by EVAL_SUFFIX, which _place_harness_for_build() puts in the path
    # and which no real hand-written HBFAplus harness ever contains.
    original = content
    kept_lines = [
        line for line in content.splitlines()
        if not (EVAL_SUFFIX in line and line.strip().endswith(".inf"))
    ]
    content = "\n".join(kept_lines)

    marker = "[Components]"
    idx = content.find(marker)
    if idx == -1:
        raise RuntimeError(
            f"Could not find a [Components] section in {dsc_path} to "
            f"register {inf_relpath} — HBFAplus.dsc may have an "
            f"unexpected structure."
        )
    insert_at = idx + len(marker)
    content = (
        content[:insert_at]
        + f"\n  {inf_relpath}\n"
        + content[insert_at:]
    )
    if content == original:
        return False
    with open(dsc_path, "w") as f:
        f.write(content)
    return True


_ERROR_LINE_RE = re.compile(
    r"error[:\s]|fatal error|FAILED|\berror\b.*not (?:defined|declared|found)",
    re.IGNORECASE)


def _extract_useful_log(full_log: str, context_lines: int = 3, max_chars: int = 6000) -> str:
    """A plain tail of the log isn't reliable here — confirmed in
    production that a single module's compile command line can include an
    enormous, mostly-irrelevant list of -I include paths (a global DSC
    setting applied to every module), which can push the real error well
    past any reasonable flat character cutoff. Search for lines that
    actually look like errors instead, with a bit of surrounding context,
    and only fall back to a plain tail if nothing matches at all.
    """
    lines = full_log.splitlines()
    error_line_indices = [i for i, line in enumerate(lines) if _ERROR_LINE_RE.search(line)]
    if not error_line_indices:
        return full_log[-max_chars:]

    collected = []
    last_included = -1
    for idx in error_line_indices:
        start = max(0, idx - context_lines)
        if start > last_included + 1:
            collected.append("...")
        collected.extend(lines[max(start, last_included + 1):idx + 1])
        last_included = idx
    result = "\n".join(collected)
    return result[-max_chars:] if len(result) > max_chars else result


def _place_harness_for_build(harness_c_path: str, harness_inf_path: str,
                              package: str, module: str) -> str:
    """Copy the already-generated harness into a real location under
    HBFAplus/FuzzHarness/, using EVAL_SUFFIX so it can never collide with
    or overwrite a real, existing hand-written harness for this module.
    Returns the inf path, relative to WORKSPACE, that build_harness() needs.
    """
    base_name = os.path.splitext(os.path.basename(harness_inf_path))[0]
    eval_dir = os.path.join(
        tm.FUZZ_HARNESS_ROOT, package, f"{module}{EVAL_SUFFIX}", base_name)
    os.makedirs(eval_dir, exist_ok=True)
    shutil.copy(harness_c_path, os.path.join(eval_dir, os.path.basename(harness_c_path)))
    shutil.copy(harness_inf_path, os.path.join(eval_dir, os.path.basename(harness_inf_path)))

    rel = os.path.relpath(eval_dir, HBFAPLUS_ROOT)  # e.g. FuzzHarness/Pkg/Mod_LLMGenerated/Base
    return os.path.join("HBFAplus", rel, os.path.basename(harness_inf_path))


def evaluate_generated_poc(ghsa_id: str, harness_c_path: str, harness_inf_path: str,
                            edk2_checkout: str, guessed_input_path: Optional[str] = None,
                            seed_dir: str = "HBFAplus/Seed/_default/Raw",
                            fuzz_duration: int = 120, use_afl_fallback: bool = True,
                            token: Optional[str] = None) -> EvaluationResult:
    advisory = gha.fetch_advisory(ghsa_id, token)
    resolved = gha.resolve(advisory, token)
    if not resolved.fix_commit:
        return EvaluationResult(
            ghsa_id=ghsa_id, module="?", verdict="unresolvable",
            reason="No fix commit could be resolved from the advisory's references.",
        )
    pre_fix_commit = gha.get_pre_fix_commit(resolved.fix_commit, token)

    targets = tm.map_files_to_targets(resolved.changed_files)
    if not targets:
        return EvaluationResult(
            ghsa_id=ghsa_id, module="?", verdict="no_edk2_files",
            reason="The fix commit touched no recognizable EDK2 package/module path.",
        )
    target = targets[0]

    inf_relpath = _place_harness_for_build(
        harness_c_path, harness_inf_path, target.package, target.module)
    _ensure_component_registered(inf_relpath)
    _ensure_library_class_registered(target.module, edk2_checkout)

    reused_guess_bytes = None
    direct_guess_fn = None
    if guessed_input_path and os.path.isfile(guessed_input_path):
        with open(guessed_input_path, "rb") as f:
            reused_guess_bytes = f.read()

        def direct_guess_fn(binary_path):
            # Re-use the EXACT bytes best_effort.py already got from the
            # LLM — no new guess, no new LLM call. Test that specific,
            # already-reviewed guess directly against the real binary.
            input_path = os.path.join(os.path.dirname(binary_path), "reused_guess.bin")
            with open(input_path, "wb") as f:
                f.write(reused_guess_bytes)
            result = validator.replay_input(binary_path, input_path)
            return type("ReusedGuessResult", (), {
                "success": result.crashed,
                "crash_input_path": input_path if result.crashed else None,
                "asan_summary": result.asan_summary,
            })()

    def sanity_check_fn(pre_fuzz, post_fuzz):
        import sanity_check
        advisory_dict = {
            "ghsa_id": ghsa_id,
            "cve_id": getattr(resolved, "cve_id", None),
            "summary": advisory.get("summary", "") if isinstance(advisory, dict) else "",
            "description": advisory.get("description", "") if isinstance(advisory, dict) else "",
        }
        target_dict = {
            "package": target.package,
            "module": target.module,
            "changed_source_files": list(resolved.changed_files),
        }
        with open(harness_c_path) as f:
            harness_source = f.read()
        sc_result = sanity_check.check(
            advisory_dict, target_dict, harness_source,
            pre_fuzz.asan_summary, pre_fuzz.stderr_tail,
        )
        return sc_result.passed, sc_result.reasoning

    result = validator.validate(
        edk2_checkout=edk2_checkout, pre_fix_commit=pre_fix_commit,
        fix_commit=resolved.fix_commit, inf_relpath=inf_relpath,
        seed_dir=seed_dir, hbfaplus_source=HBFAPLUS_ROOT,
        duration_s=fuzz_duration, direct_guess_fn=direct_guess_fn,
        use_afl_fallback=use_afl_fallback, sanity_check_fn=sanity_check_fn,
    )

    log_source = result.post_fix or result.pre_fix
    build_or_execution_log = (
        _extract_useful_log(log_source.stderr_tail) if log_source and log_source.stderr_tail else None
    )

    return EvaluationResult(
        ghsa_id=ghsa_id, module=target.module,
        verdict=result.verdict, reason=result.reason,
        reused_guess_bytes_hex=(reused_guess_bytes.hex() if reused_guess_bytes else None),
        build_or_execution_log=build_or_execution_log,
    )


def discover_generated_harnesses(out_dir_base: str):
    """Find every already-generated harness sitting under out_dir_base.

    best_effort.py writes each successful result into
    <out_dir_base>/<GHSA-ID>/<Package>_<Module>_best_effort/ containing a
    Test<Module>.c and a matching Test<Module>.inf (plus a
    *StandalonePoC.c we deliberately skip — that's the packaged
    standalone artifact, not the buildable harness). Returns a list of
    (ghsa_id, harness_c, harness_inf, guessed_input_or_None), sorted for
    stable, reproducible run order.
    """
    found = []
    if not os.path.isdir(out_dir_base):
        return found
    for ghsa_id in sorted(os.listdir(out_dir_base)):
        advisory_dir = os.path.join(out_dir_base, ghsa_id)
        if not os.path.isdir(advisory_dir) or not ghsa_id.startswith("GHSA-"):
            continue
        for sub in sorted(os.listdir(advisory_dir)):
            work_dir = os.path.join(advisory_dir, sub)
            if not os.path.isdir(work_dir):
                continue
            for filename in sorted(os.listdir(work_dir)):
                if not filename.endswith(".inf"):
                    continue
                if "StandalonePoC" in filename:
                    continue  # packaged artifact, not the buildable harness
                base = filename[:-len(".inf")]
                c_path = os.path.join(work_dir, base + ".c")
                inf_path = os.path.join(work_dir, filename)
                if not os.path.isfile(c_path):
                    continue
                guess_path = os.path.join(work_dir, "guessed_input.bin")
                found.append((
                    ghsa_id, c_path, inf_path,
                    guess_path if os.path.isfile(guess_path) else None,
                ))
    return found


def main():
    import argparse
    import json

    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--advisory",
                         help="Single GHSA id to evaluate. Omit and pass "
                              "--all to evaluate every generated harness.")
    parser.add_argument("--harness-c")
    parser.add_argument("--harness-inf")
    parser.add_argument("--edk2-checkout", required=True)
    parser.add_argument("--guessed-input")
    parser.add_argument("--all", action="store_true",
                         help="Evaluate EVERY already-generated harness found "
                              "under --out-dir-base, instead of one named "
                              "advisory. Each still goes through the full "
                              "real build/guess/AFL++ pipeline, so this takes "
                              "real time per advisory.")
    parser.add_argument("--out-dir-base",
                         default="/home/nsiavash/HBFAplusplus/output",
                         help="Where best_effort.py wrote its generated "
                              "harnesses (only used with --all).")
    parser.add_argument("--seed-dir", default="HBFAplus/Seed/_default/Raw")
    parser.add_argument("--fuzz-duration", type=int, default=120)
    parser.add_argument("--pocgen-mode", action="store_true",
                         help="Disable AFL++ fallback (match PoCGen exactly: "
                              "LLM-guess only)")
    args = parser.parse_args()

    token = os.environ.get("GITHUB_API_KEY") or os.environ.get("GITHUB_TOKEN")

    if not args.all:
        missing = [n for n, v in (("--advisory", args.advisory),
                                   ("--harness-c", args.harness_c),
                                   ("--harness-inf", args.harness_inf))
                   if not v]
        if missing:
            parser.error(f"{', '.join(missing)} required unless --all is used")
        result = evaluate_generated_poc(
            args.advisory, args.harness_c, args.harness_inf, args.edk2_checkout,
            args.guessed_input, args.seed_dir, args.fuzz_duration,
            use_afl_fallback=not args.pocgen_mode, token=token,
        )
        print(json.dumps(dataclasses.asdict(result), indent=2))
        return

    harnesses = discover_generated_harnesses(args.out_dir_base)
    if not harnesses:
        print(f"[!] No generated harnesses found under {args.out_dir_base}",
              file=sys.stderr)
        return
    print(f"[i] Evaluating {len(harnesses)} generated harness(es): "
          f"{[h[0] for h in harnesses]}", file=sys.stderr)

    report_path = os.path.join(args.out_dir_base, "evaluation_report.json")
    results = []
    for ghsa_id, c_path, inf_path, guess_path in harnesses:
        print(f"\n[i] === {ghsa_id} ({os.path.basename(inf_path)}) ===",
              file=sys.stderr)
        try:
            result = evaluate_generated_poc(
                ghsa_id, c_path, inf_path, args.edk2_checkout,
                guess_path, args.seed_dir, args.fuzz_duration,
                use_afl_fallback=not args.pocgen_mode, token=token,
            )
        except Exception as e:
            result = EvaluationResult(
                ghsa_id=ghsa_id, module="?", verdict="evaluation_error",
                reason=f"Evaluation raised an unexpected exception: {e}",
            )
        print(f"[i]   -> {result.verdict}", file=sys.stderr)
        results.append(result)
        # Write incrementally so a crash/disconnect partway through doesn't
        # lose everything already completed — these runs take real time.
        with open(report_path, "w") as f:
            json.dump([dataclasses.asdict(r) for r in results], f, indent=2)

    by_verdict = {}
    for r in results:
        by_verdict.setdefault(r.verdict, []).append(r.ghsa_id)
    print(f"\n[i] Done. {len(results)} evaluated. Full report: {report_path}",
          file=sys.stderr)
    for verdict, ids in sorted(by_verdict.items()):
        print(f"[i]   {verdict}: {len(ids)} {ids}", file=sys.stderr)


if __name__ == "__main__":
    main()
