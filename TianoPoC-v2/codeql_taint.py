#!/usr/bin/env python3
# @file
#
# Component (i)-part-3: static taint analysis for the target module, using
# CodeQL's C/C++ extractor and its built-in cpp-security-and-quality query
# suite. This is the direct analog of PoCGen's Section 2.2.3 (which used
# CodeQL's javascript/security library) — same tool, same idea (find a
# path from an attacker-reachable source to a sensitive sink), scoped here
# to the files the advisory's fix commit actually touched so the output
# maps onto real reachable dataflow near the fix, not a whole-package alert
# dump.
#
# Unlike PoCGen, we don't hand-roll vulnerability-type-specific sources/sinks
# (path traversal / command injection / etc. don't map cleanly onto C).
# Instead we lean on CodeQL's own `cpp-security-and-quality.qls` suite (CWE
# buffer overflow, integer overflow/wraparound, use-after-free, format
# string, out-of-bounds, etc.) and its `path-problem`-type queries, which
# already ship dataflow paths (SARIF `codeFlows`) from source to sink.
#
# Copyright (c) 2025-2026 TianoShield Contributors.
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
"""
Requires the CodeQL CLI on PATH (https://github.com/github/codeql-cli-binaries
releases) plus the standard CodeQL query packs (`codeql pack download
codeql/cpp-queries` or the bundle that ships them). Building a database
requires the *same* build environment HBFAplus already assumes (BaseTools,
gcc) since CodeQL traces a real compilation.

Usage:
    # One-time per edk2 revision you want to analyze:
    python3 codeql_taint.py create-db \\
        --edk2-checkout /path/to/edk2 \\
        --package NetworkPkg --module Dhcp6Dxe \\
        --db-path /tmp/codeql-dhcp6dxe

    # Then, scoped to an advisory's changed files:
    python3 codeql_taint.py taint-paths \\
        --db-path /tmp/codeql-dhcp6dxe \\
        --changed-files NetworkPkg/Dhcp6Dxe/Dhcp6Io.c
"""
import argparse
import dataclasses
import glob
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from typing import Dict, List, Optional

# Ships with every CodeQL CLI bundle; no separate download needed beyond the
# CLI itself and its bundled query packs.
DEFAULT_QUERY_SUITE = "cpp-security-and-quality.qls"


@dataclasses.dataclass
class TaintStep:
    file: str
    line: int
    message: str


@dataclasses.dataclass
class TaintFinding:
    rule_id: str
    rule_description: str
    severity: str
    steps: List[TaintStep]   # first = source, last = sink


def find_module_inf(edk2_checkout: str, package: str, module: str) -> Optional[str]:
    """Locate the real (upstream) INF for `module`, e.g.
    NetworkPkg/Dhcp6Dxe/Dhcp6Dxe.inf — this is what CodeQL actually traces
    the build of, as opposed to HBFAplus's mock-based harness INF."""
    pattern = os.path.join(edk2_checkout, package, "**", f"{module}.inf")
    matches = glob.glob(pattern, recursive=True)
    return matches[0] if matches else None


def create_database(edk2_checkout: str, package: str, module: str,
                     db_path: str, arch: str = "X64",
                     toolchain: str = "GCC5") -> None:
    """Build a CodeQL C/C++ database by tracing a real (non-fuzz) EDK2 build
    of the target module. Requires WORKSPACE/PACKAGES_PATH already set up
    the way HBFAEnvSetup.py expects (same as validator.build_harness)."""
    inf = find_module_inf(edk2_checkout, package, module)
    if not inf:
        raise FileNotFoundError(
            f"Could not find {module}.inf under {package}/ in {edk2_checkout}; "
            "pass an explicit build command instead if the module lives at a "
            "nonstandard path."
        )
    build_cmd = (f"build -p {package}/{package}.dsc -m {inf} "
                 f"-a {arch} -t {toolchain}")
    if os.path.isdir(db_path):
        raise FileExistsError(f"{db_path} already exists; remove it or pick "
                               f"a new --db-path")
    subprocess.run(
        ["codeql", "database", "create", db_path,
         "--language=cpp",
         f"--command={build_cmd}",
         f"--source-root={edk2_checkout}"],
        cwd=edk2_checkout, check=True, capture_output=True, text=True, timeout=1800,
    )


def get_or_create_database(edk2_checkout: str, package: str, module: str,
                            revision: str, cache_root: str,
                            arch: str = "X64", toolchain: str = "GCC5") -> Optional[str]:
    """Auto-caching wrapper around create_database: one database per
    (package, module, revision) under `cache_root`, reused across every
    refinement attempt for the same advisory instead of rebuilding per
    attempt. Returns None (rather than raising) on any failure — CodeQL
    involvement is meant to strengthen the prompt when available, never to
    block the pipeline when it isn't (no CLI installed, build fails, etc.),
    same convention as every other best-effort component here.
    """
    key = f"{package}_{module}_{revision[:12]}"
    db_path = os.path.join(cache_root, key)
    if os.path.isdir(db_path) and os.path.exists(os.path.join(db_path, "codeql-database.yml")):
        return db_path  # already built for this exact revision
    try:
        os.makedirs(cache_root, exist_ok=True)
        create_database(edk2_checkout, package, module, db_path, arch, toolchain)
        return db_path
    except Exception as e:
        print(f"[!] CodeQL database build failed for {package}/{module}@"
              f"{revision[:12]}, continuing without CodeQL context: {e}",
              file=sys.stderr)
        return None


# --- Tier 2: extended custom taint query -----------------------------------
#
# PoCGen's own fallback chain (paper §2.2.3): default CodeQL taint analysis
# first; if that finds nothing, retry with an *extended* set of taint
# propagation rules and sinks "our own", specifically because the built-in
# suite is tuned for high precision / low false positives and can miss
# real paths as a result. This is the C analog of that retry: a small,
# deliberately looser custom TaintTracking query covering common EDK2/UEFI
# memory-unsafety sinks (CopyMem, memcpy-family, AllocatePool sizing) that
# the general-purpose cpp-security-and-quality suite may not flag if, e.g.,
# the size argument's taint doesn't fit one of its specific CWE patterns.
_EXTENDED_SINK_FUNCTIONS = [
    "CopyMem", "SetMem", "memcpy", "memmove", "strcpy", "strcat", "sprintf",
    "AllocatePool", "AllocateZeroPool", "AllocateRuntimePool",
]

_EXTENDED_QUERY = """\
/**
 * @name Fuzz-reachable value flows to a known EDK2/UEFI memory-unsafety sink
 * @kind path-problem
 * @problem.severity warning
 * @id hbfa/extended-taint-to-sink
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph

class Edk2RiskySink extends Expr {
  Edk2RiskySink() {
    exists(FunctionCall fc |
      fc.getTarget().hasName([%(sink_names)s]) and
      this = fc.getAnArgument()
    )
  }
}

class ExtendedConfig extends TaintTracking::Configuration {
  ExtendedConfig() { this = "HbfaExtendedEdk2Config" }

  override predicate isSource(DataFlow::Node source) {
    exists(Parameter p | source.asParameter() = p)
  }

  override predicate isSink(DataFlow::Node sink) {
    sink.asExpr() instanceof Edk2RiskySink
  }
}

from ExtendedConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Value derived from parameter $@ reaches a memory-unsafety sink here.",
  source.getNode(), "this parameter"
"""

_QLPACK_YML = """\
name: hbfa/extended-taint
version: 0.0.1
dependencies:
  codeql/cpp-all: "*"
"""


def write_extended_query_pack(pack_dir: str) -> str:
    """Write the extended taint query + its qlpack.yml to `pack_dir`.
    Returns the path to the .ql file.

    NOTE: this query is written against the classic
    `TaintTracking::Configuration` class-based API, which has been stable
    across CodeQL CLI versions for a long time but may need adjusting for
    very new CodeQL releases that have moved to the module-based
    `TaintTracking::Global<...>` API. It has not been run against a real
    CodeQL installation in this environment (no CodeQL CLI available here)
    — same caveat as create_database()/analyze(), treat it as a reasonable
    starting point to validate against your actual CodeQL version, not a
    guaranteed-working query.
    """
    os.makedirs(pack_dir, exist_ok=True)
    sink_names = ", ".join(f'"{name}"' for name in _EXTENDED_SINK_FUNCTIONS)
    query_text = _EXTENDED_QUERY % {"sink_names": sink_names}
    query_path = os.path.join(pack_dir, "ExtendedEdk2Taint.ql")
    with open(query_path, "w") as f:
        f.write(query_text)
    with open(os.path.join(pack_dir, "qlpack.yml"), "w") as f:
        f.write(_QLPACK_YML)
    return query_path


def run_extended_query(db_path: str, pack_dir: Optional[str] = None) -> str:
    """Run the extended query and return the path to its SARIF output."""
    pack_dir = pack_dir or tempfile.mkdtemp(prefix="hbfa_extended_query_")
    write_extended_query_pack(pack_dir)
    sarif_path = os.path.join(tempfile.gettempdir(),
                               f"codeql_extended_{os.path.basename(db_path)}.sarif")
    subprocess.run(
        ["codeql", "database", "analyze", db_path, pack_dir,
         "--format=sarifv2.1.0", f"--output={sarif_path}", "--threads=0"],
        check=True, capture_output=True, text=True, timeout=1800,
    )
    return sarif_path


# --- Tier 3: LLM-guessed sinks ----------------------------------------------
#
# PoCGen's next fallback after its extended taint analysis also fails:
# "PoCGen prompts the LLM to guess the vulnerable sinks" (§2.2.3). Same
# idea here — show the LLM the changed source and ask it to name specific
# sink lines, rather than leaving harness_generator.py to fall back to
# unannotated raw source with no sink guidance at all.
_SINK_GUESS_PROMPT = """\
You are a C/UEFI security reviewer. Below is source code changed by a
security fix in an EDK2 driver.

## Advisory
{advisory_summary}

## Source (pre-fix revision)
{source_blocks}

## Task
CodeQL's static analysis did not find a clear taint path to a sink in this
code. Identify, as precisely as you can, the specific line(s) where
attacker-influenced data (e.g. a buffer/length pair, an untrusted option
value) reaches a memory-unsafety-relevant operation (a copy, an allocation
sized by untrusted input, an array index, a pointer dereference, etc.).

Respond with one line per guess, in exactly this format, and nothing else:
FILE:LINE - one-sentence reason
"""

_SINK_GUESS_LINE_RE = re.compile(r"^([^\s:]+):(\d+)\s*-\s*(.+)$")


def guess_sinks_with_llm(changed_files_content: Dict[str, str],
                          advisory_summary: str) -> List[TaintFinding]:
    """LLM fallback when both the built-in suite and the extended query
    come back empty. Returns pseudo-findings shaped like real ones (single-
    step "path": the guessed line only) so render_taint_snippets can render
    them the same way."""
    import harness_generator  # reuse the one call_llm() implementation

    source_blocks = "\n\n".join(
        f"### {path}\n```c\n{content}\n```"
        for path, content in changed_files_content.items()
    )
    prompt = _SINK_GUESS_PROMPT.format(advisory_summary=advisory_summary,
                                        source_blocks=source_blocks)
    response = harness_generator.call_llm(prompt)

    findings = []
    for line in response.splitlines():
        m = _SINK_GUESS_LINE_RE.match(line.strip())
        if not m:
            continue
        file_path, line_no, reason = m.group(1), int(m.group(2)), m.group(3)
        findings.append(TaintFinding(
            rule_id="llm-guessed-sink",
            rule_description="LLM-guessed sink (CodeQL found no static taint path)",
            severity="unknown",
            steps=[TaintStep(file=file_path, line=line_no, message=reason)],
        ))
    return findings


def analyze_with_fallbacks(db_path: Optional[str], changed_files: List[str],
                            edk2_checkout: str, pre_fix_commit: str,
                            advisory_summary: str = "") -> Dict[str, object]:
    """Run all three tiers in order, same escalation PoCGen uses: built-in
    suite -> extended custom query -> LLM-guessed sinks. Stops at the first
    tier that produces findings. Returns {"tier": ..., "findings": [...]}
    so callers can report which tier actually supplied the context.
    """
    if db_path:
        try:
            sarif_path = analyze(db_path)
            findings = filter_findings_to_files(sarif_path, changed_files)
            if findings:
                return {"tier": "builtin_suite", "findings": findings}
        except Exception as e:
            print(f"[!] Built-in CodeQL suite failed: {e}", file=sys.stderr)

        try:
            sarif_path = run_extended_query(db_path)
            findings = filter_findings_to_files(sarif_path, changed_files)
            if findings:
                return {"tier": "extended_query", "findings": findings}
        except Exception as e:
            print(f"[!] Extended CodeQL query failed: {e}", file=sys.stderr)

    # Tier 3 doesn't need a database at all — just the source.
    try:
        contents = {}
        for path in changed_files[:3]:
            result = subprocess.run(
                ["git", "-C", edk2_checkout, "show", f"{pre_fix_commit}:{path}"],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0:
                contents[path] = result.stdout
        if contents:
            findings = guess_sinks_with_llm(contents, advisory_summary)
            if findings:
                return {"tier": "llm_guess", "findings": findings}
    except Exception as e:
        print(f"[!] LLM sink-guessing failed: {e}", file=sys.stderr)

    return {"tier": "none", "findings": []}



    """Run the security query suite and return the path to the resulting
    SARIF file."""
    sarif_path = os.path.join(tempfile.gettempdir(),
                               f"codeql_{os.path.basename(db_path)}.sarif")
    subprocess.run(
        ["codeql", "database", "analyze", db_path, query_suite,
         "--format=sarifv2.1.0", f"--output={sarif_path}",
         "--threads=0"],
        check=True, capture_output=True, text=True, timeout=1800,
    )
    return sarif_path


def _location_file_line(loc: dict, db_source_root: str):
    phys = loc.get("physicalLocation", {})
    uri = phys.get("artifactLocation", {}).get("uri", "")
    line = phys.get("region", {}).get("startLine", 0)
    # SARIF URIs from CodeQL are relative to the database's source root.
    return uri, line


def filter_findings_to_files(sarif_path: str, changed_files: List[str],
                              db_source_root: str = "") -> List[TaintFinding]:
    """Parse the SARIF report and keep only findings whose sink (or any step
    in its dataflow path) touches one of the advisory's changed files —
    this is what scopes CodeQL's whole-package alert dump down to
    "does this relate to the fix commit" the same way PoCGen's taint
    extraction was scoped to the vulnerable function's candidates."""
    with open(sarif_path) as f:
        sarif = json.load(f)

    changed_set = set(changed_files)
    findings: List[TaintFinding] = []

    for run in sarif.get("runs", []):
        rules_by_id = {
            r["id"]: r.get("fullDescription", {}).get("text", r.get("id", ""))
            for r in run.get("tool", {}).get("driver", {}).get("rules", [])
        }
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            steps: List[TaintStep] = []

            # path-problem queries: dataflow path lives in codeFlows
            for code_flow in result.get("codeFlows", []):
                for thread_flow in code_flow.get("threadFlows", []):
                    for loc in thread_flow.get("locations", []):
                        physical = loc.get("location", {})
                        uri, line = _location_file_line(physical, db_source_root)
                        msg = physical.get("message", {}).get("text", "")
                        steps.append(TaintStep(file=uri, line=line, message=msg))

            # problem (non-path) queries: just the single alert location
            if not steps:
                for loc in result.get("locations", []):
                    uri, line = _location_file_line(loc, db_source_root)
                    steps.append(TaintStep(
                        file=uri, line=line,
                        message=result.get("message", {}).get("text", ""),
                    ))

            touches_change = any(step.file in changed_set for step in steps)
            if not touches_change:
                continue

            severity = result.get("properties", {}).get(
                "security-severity",
                run.get("tool", {}).get("driver", {}).get("rules", [{}])[0]
                    .get("defaultConfiguration", {}).get("level", "warning"),
            )
            findings.append(TaintFinding(
                rule_id=rule_id,
                rule_description=rules_by_id.get(rule_id, rule_id),
                severity=str(severity),
                steps=steps,
            ))

    return findings


def render_taint_snippets(findings: List[TaintFinding], source_root: str,
                           context_lines: int = 3) -> str:
    """Render findings as PoCGen-Fig.4-style annotated source blocks: for
    each step in the path, show `context_lines` before/after with a trailing
    comment describing that step, grouped by file."""
    if not findings:
        return "(no CodeQL findings touched the changed files)"

    blocks = []
    for finding in findings:
        blocks.append(f"### CodeQL finding: {finding.rule_id} "
                       f"({finding.severity})\n{finding.rule_description}\n")
        by_file: Dict[str, List[TaintStep]] = {}
        for step in finding.steps:
            by_file.setdefault(step.file, []).append(step)

        for file_path, steps in by_file.items():
            full_path = os.path.join(source_root, file_path)
            if not os.path.isfile(full_path):
                continue
            with open(full_path, "r", errors="replace") as f:
                lines = f.readlines()
            annotations = {s.line: s.message for s in steps}
            line_nums = sorted(annotations)
            windows = []
            for n in line_nums:
                windows.append(range(max(1, n - context_lines),
                                      min(len(lines), n + context_lines) + 1))
            merged: List[int] = sorted(set().union(*windows)) if windows else []

            snippet_lines = []
            for n in merged:
                text = lines[n - 1].rstrip("\n") if n - 1 < len(lines) else ""
                if n in annotations:
                    text += f"  // {annotations[n] or 'taint step'}"
                snippet_lines.append(text)
            blocks.append(f"`{file_path}`:\n```c\n" + "\n".join(snippet_lines) + "\n```")

    return "\n\n".join(blocks)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_create = sub.add_parser("create-db")
    p_create.add_argument("--edk2-checkout", required=True)
    p_create.add_argument("--package", required=True)
    p_create.add_argument("--module", required=True)
    p_create.add_argument("--db-path", required=True)

    p_taint = sub.add_parser("taint-paths")
    p_taint.add_argument("--db-path", required=True)
    p_taint.add_argument("--changed-files", nargs="+", required=True)
    p_taint.add_argument("--source-root", default="",
                          help="Defaults to the source root passed to create-db")
    p_taint.add_argument("--query-suite", default=DEFAULT_QUERY_SUITE)

    args = parser.parse_args()

    if args.cmd == "create-db":
        create_database(args.edk2_checkout, args.package, args.module, args.db_path)
        print(f"Database created at {args.db_path}")

    elif args.cmd == "taint-paths":
        sarif_path = analyze(args.db_path, args.query_suite)
        findings = filter_findings_to_files(sarif_path, args.changed_files)
        source_root = args.source_root or args.db_path
        print(render_taint_snippets(findings, source_root))


if __name__ == "__main__":
    main()
