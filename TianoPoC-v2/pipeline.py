#!/usr/bin/env python3
# @file
#
# AdvisoryPipeline orchestrator. Ties together:
#   (i)   github_advisories.py  — fetch + resolve EDK2 security advisories
#   (i.5) target_mapper.py      — map changed files -> package/module/depth
#   (ii)  harness_generator.py  — LLM candidate harness generation
#   (iii) validator.py          — build + fuzz pre/post-fix, compare
#   (iv)  refiner.py            — retry loop with build/fuzz feedback
#
# Copyright (c) 2025-2026 TianoShield Contributors.
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
"""
Usage:
    export GITHUB_API_KEY=...
    export OPENAI_API_KEY=...       # or "ollama" for a local model
    export OPENAI_BASE_URL=...      # e.g. http://localhost:11434/v1
    export HBFA_LLM_MODEL=...

    # Dry run: see what the pipeline WOULD do, without calling an LLM or
    # building anything. Always run this first over the whole security tab.
    python3 pipeline.py scan --edk2-checkout /path/to/edk2

    # Full run for every advisory the scan step flagged as actionable:
    python3 pipeline.py run --edk2-checkout /path/to/edk2 --seed-dir HBFAplus/Seed/_default/Raw

    # Full run for one advisory only:
    python3 pipeline.py run --edk2-checkout /path/to/edk2 --seed-dir ... --advisory GHSA-xxxx
"""
import argparse
import dataclasses
import json
import os
import sys
from typing import List, Optional

sys.path.insert(0, os.path.dirname(__file__))
import github_advisories as gha  # noqa: E402
import target_mapper as tm  # noqa: E402
import refiner  # noqa: E402

HBFAPLUS_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_OUTPUT_DIR = os.path.join(HBFAPLUS_ROOT, "output", "AdvisoryPipeline")


@dataclasses.dataclass
class ScanEntry:
    ghsa_id: str
    cve_id: Optional[str]
    fix_commit: Optional[str]
    targets: List[dict]
    action: str   # "generate" | "already_covered" | "unresolvable" | "no_edk2_files"


def scan(edk2_checkout_hint: Optional[str], token: Optional[str]) -> List[ScanEntry]:
    """Component (i) run over every advisory: fetch, resolve, map, and
    classify what action (if any) is needed. Pure read-only — safe to run
    repeatedly / on a schedule to see what's new on the security tab."""
    advisories = gha.list_advisories(token)
    entries: List[ScanEntry] = []
    for adv in advisories:
        resolved = gha.resolve(adv, token)
        if not resolved.fix_commit:
            entries.append(ScanEntry(adv.ghsa_id, adv.cve_id, None, [], "unresolvable"))
            continue
        targets = tm.map_files_to_targets(resolved.changed_files)
        if not targets:
            entries.append(ScanEntry(adv.ghsa_id, adv.cve_id, resolved.fix_commit,
                                      [], "no_edk2_files"))
            continue
        needs_generation = any(not t.has_coverage for t in targets)
        action = "generate" if needs_generation else "already_covered"
        entries.append(ScanEntry(
            adv.ghsa_id, adv.cve_id, resolved.fix_commit,
            [dataclasses.asdict(t) for t in targets], action,
        ))
    return entries


def run_for_advisory(ghsa_id: str, edk2_checkout: str, seed_dir: str,
                      token: Optional[str], out_dir_base: str,
                      fuzz_duration_s: int, codeql_db_path: Optional[str] = None,
                      codeql_cache_root: Optional[str] = None,
                      skip_codeql: bool = False,
                      max_attempts: Optional[int] = None,
                      use_afl_fallback: bool = True) -> dict:
    """Full component (i)->(iv) run for a single advisory."""
    advisory = gha.fetch_advisory(ghsa_id, token)
    resolved = gha.resolve(advisory, token)
    if not resolved.fix_commit:
        return {"ghsa_id": ghsa_id, "verdict": "unresolvable",
                "reason": "No fix commit could be resolved from the advisory's references."}

    targets = tm.map_files_to_targets(resolved.changed_files)
    if not targets:
        return {"ghsa_id": ghsa_id, "verdict": "no_edk2_files",
                "reason": "The fix commit touched no recognizable EDK2 package/module "
                          "path (e.g. only docs/CI files)."}

    outcomes = []
    for target in targets:
        sibling = None
        if not target.existing_harnesses:
            candidates = tm.find_sibling_examples(target.package, target.module)
            sibling = candidates[0] if candidates else None
        elif target.existing_harnesses:
            # Prefer the module's own existing harness as the structural
            # template — it's guaranteed to build and already matches the
            # right dependency stack.
            sibling = os.path.dirname(
                os.path.join(tm.FUZZ_HARNESS_ROOT, target.existing_harnesses[0])
            )

        advisory_dict = dataclasses.asdict(advisory)
        target_dict = dataclasses.asdict(target)
        module_out_dir = os.path.join(
            out_dir_base, ghsa_id, f"{target.package}_{target.module}"
        )
        outcome = refiner.run_refinement_loop(
            advisory_dict, target_dict, edk2_checkout, resolved.fix_commit,
            seed_dir, module_out_dir, HBFAPLUS_ROOT, sibling, fuzz_duration_s,
            max_attempts=(max_attempts if max_attempts is not None
                          else refiner.MAX_ATTEMPTS),
            codeql_db_path=codeql_db_path, codeql_cache_root=codeql_cache_root,
            skip_codeql=skip_codeql, use_afl_fallback=use_afl_fallback,
        )
        outcomes.append(dataclasses.asdict(outcome))

    return {"ghsa_id": ghsa_id, "cve_id": advisory.cve_id,
            "fix_commit": resolved.fix_commit, "targets": outcomes}


def _token() -> Optional[str]:
    return os.environ.get("GITHUB_API_KEY") or os.environ.get("GITHUB_TOKEN")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="Read-only scan of the whole security tab")
    p_scan.add_argument("--out", help="Write JSON report to this path instead of stdout")

    p_best = sub.add_parser("best-effort",
                             help="Fast, UNVALIDATED PoC: one harness-generation "
                                  "call + one exploit-input guess, no build, no "
                                  "execution, no crash confirmation of any kind. "
                                  "Verdict is always 'unvalidated_best_effort', "
                                  "never 'confirmed' — use `run` for an actually "
                                  "tested result.")
    p_best.add_argument("--advisory", required=True)
    p_best.add_argument("--edk2-checkout", required=True)
    p_best.add_argument("--out-dir-base", default=DEFAULT_OUTPUT_DIR)
    p_best.add_argument("--codeql-db")

    p_run = sub.add_parser("run", help="Generate+validate harnesses")
    p_run.add_argument("--edk2-checkout", required=True)
    p_run.add_argument("--seed-dir", required=True,
                        help="Fallback seed corpus dir if a target has no "
                             "existing Seed/ directory of its own")
    p_run.add_argument("--advisory", help="Restrict to a single GHSA id; "
                                           "omit to run over every advisory "
                                           "the scan step marks 'generate'")
    p_run.add_argument("--out-dir-base", default=DEFAULT_OUTPUT_DIR)
    p_run.add_argument("--fuzz-duration", type=int, default=120)
    p_run.add_argument("--max-attempts", type=int, default=None,
                        help="Cap the refinement loop's retry budget per "
                             "target (default: refiner.py's own default, "
                             "currently 10). Useful for a fast diagnostic "
                             "pass — e.g. --max-attempts 2 — to check "
                             "whether generation/build work at all before "
                             "committing to a long full-budget run.")
    p_run.add_argument("--limit", type=int,
                        help="Cap how many advisories to process this run "
                             "(recommended for the first full-scan pass — "
                             "each advisory can take many minutes)")
    p_run.add_argument("--codeql-db",
                        help="Explicit CodeQL database path, to force a "
                             "specific pre-built database instead of "
                             "letting the pipeline auto-build/cache one per "
                             "package/module/revision (the default — see "
                             "codeql_taint.py's get_or_create_database). "
                             "Only useful with a single --advisory, since "
                             "one DB covers one module/revision.")
    p_run.add_argument("--codeql-cache-root",
                        help="Where auto-built CodeQL databases are cached "
                             "across advisories/runs (default: "
                             "HBFAplus/output/codeql_dbs)")
    p_run.add_argument("--no-codeql", action="store_true",
                        help="Skip CodeQL entirely (built-in suite, "
                             "extended query, and auto-build) and go "
                             "straight to the LLM-guessed-sink fallback / "
                             "raw source. Useful if the CodeQL CLI isn't "
                             "installed, or to save the database-build time "
                             "on a quick trial run.")
    p_run.add_argument("--pocgen-mode", action="store_true",
                        help="Disable AFL++ as a fallback search step. "
                             "PoCGen has no blind-search/fuzzing component "
                             "anywhere in its architecture — it's 100%% "
                             "LLM-guess -> execute once -> refine with "
                             "feedback -> guess again. With this flag, if "
                             "poc_guesser.py's direct guesses all miss, the "
                             "attempt is simply no_repro — afl-fuzz never "
                             "runs at all. Without it (default), AFL++ "
                             "still runs as HBFAplus's own safety net "
                             "beyond what PoCGen itself does.")

    args = parser.parse_args()
    token = _token()
    if not token:
        print("[!] GITHUB_API_KEY/GITHUB_TOKEN not set — expect to hit "
              "unauthenticated rate limits fast.", file=sys.stderr)

    if args.cmd == "scan":
        entries = scan(args.edk2_checkout if hasattr(args, "edk2_checkout") else None, token)
        report = [dataclasses.asdict(e) for e in entries]
        text = json.dumps(report, indent=2)
        if args.out:
            with open(args.out, "w") as f:
                f.write(text)
            actionable = sum(1 for e in entries if e.action == "generate")
            print(f"[i] {len(entries)} advisories scanned, {actionable} need "
                  f"harness generation. Full report: {args.out}", file=sys.stderr)
        else:
            print(text)

    elif args.cmd == "best-effort":
        import best_effort
        os.makedirs(args.out_dir_base, exist_ok=True)
        result = best_effort.run_best_effort(
            args.advisory, args.edk2_checkout, args.out_dir_base,
            token, args.codeql_db,
        )
        report_path = os.path.join(args.out_dir_base, f"{args.advisory}_best_effort_report.json")
        with open(report_path, "w") as f:
            json.dump(dataclasses.asdict(result), f, indent=2)
        print(json.dumps(dataclasses.asdict(result), indent=2))
        print(f"\n[i] UNVALIDATED result — verdict is always "
              f"'unvalidated_best_effort' or an error state, never "
              f"'confirmed'. Report: {report_path}", file=sys.stderr)

    elif args.cmd == "run":
        os.makedirs(args.out_dir_base, exist_ok=True)
        if args.advisory:
            targets_to_run = [args.advisory]
        else:
            entries = scan(args.edk2_checkout, token)
            targets_to_run = [e.ghsa_id for e in entries if e.action == "generate"]
            if args.limit:
                targets_to_run = targets_to_run[: args.limit]
            print(f"[i] Running the full pipeline for {len(targets_to_run)} "
                  f"advisories: {targets_to_run}", file=sys.stderr)

        results = []
        for ghsa_id in targets_to_run:
            print(f"[i] === {ghsa_id} ===", file=sys.stderr)
            try:
                result = run_for_advisory(
                    ghsa_id, args.edk2_checkout, args.seed_dir, token,
                    args.out_dir_base, args.fuzz_duration, args.codeql_db,
                    args.codeql_cache_root, args.no_codeql, args.max_attempts,
                    use_afl_fallback=not args.pocgen_mode,
                )
            except Exception as e:
                result = {"ghsa_id": ghsa_id, "verdict": "error", "reason": str(e)}
            results.append(result)
            report_path = os.path.join(args.out_dir_base, "run_report.json")
            with open(report_path, "w") as f:
                json.dump(results, f, indent=2)
        print(f"[i] Done. Report: {os.path.join(args.out_dir_base, 'run_report.json')}",
              file=sys.stderr)


if __name__ == "__main__":
    main()
