#!/usr/bin/env python3
# @file
#
# Component (i)-part-4: usage snippet extraction + LLM summarization —
# direct analog of PoCGen Section 2.2.4. PoCGen pulls call sites from test
# files plus doc code blocks, then prompts an LLM to confirm/summarize them.
# There's no npm-style "documentation" tree for an arbitrary EDK2 module, so
# the two source of usage evidence here are:
#   1. the target function's own doxygen header comment (EDK2's coding
#      standard requires one — @param/@retval document exactly the
#      "input types and possible values" PoCGen's usage snippets exist to
#      surface), and
#   2. real call sites of that function elsewhere in the edk2 tree (the
#      direct analog of PoCGen's "usage snippets from test files").
# An LLM then summarizes both into a short, concrete usage description,
# same as PoCGen's doc-snippet summarization step.
#
# Copyright (c) 2025-2026 TianoShield Contributors.
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
import argparse
import dataclasses
import glob
import os
import re
import subprocess
import sys
from typing import List, Optional

sys.path.insert(0, os.path.dirname(__file__))

# EDK2's coding standard puts a function's opening/closing braces at column
# 0 (nested-block braces are always indented) — this makes column-0 braces
# a reliable proxy for "function body starts/ends here" without needing a
# real C parser.
_COL0_OPEN = re.compile(r"^\{\s*$")
_COL0_CLOSE = re.compile(r"^\}\s*$")
_FUNC_NAME_LINE = re.compile(r"^([A-Za-z_]\w*)\s*\(")
_DOXYGEN_END = re.compile(r"^\*\*/\s*$")


@dataclasses.dataclass
class FunctionInfo:
    name: str
    start_line: int   # 1-indexed, opening brace line
    end_line: int     # 1-indexed, closing brace line
    header_comment: Optional[str]
    body_preview: str


@dataclasses.dataclass
class CallSite:
    file: str
    line: int
    snippet: str


def find_enclosing_function(source_text: str, line_no: int) -> Optional[FunctionInfo]:
    """Locate the function whose body contains `line_no` (1-indexed), using
    EDK2's column-0-brace coding convention."""
    lines = source_text.split("\n")
    opens = [i for i, l in enumerate(lines) if _COL0_OPEN.match(l)]
    closes = [i for i, l in enumerate(lines) if _COL0_CLOSE.match(l)]
    if not opens or not closes:
        return None

    # Pair each open with the next close after it (EDK2 style never nests
    # column-0 braces, so this is a safe 1:1 pairing).
    pairs = []
    close_iter = iter(sorted(closes))
    next_close = next(close_iter, None)
    for o in sorted(opens):
        while next_close is not None and next_close < o:
            next_close = next(close_iter, None)
        if next_close is not None:
            pairs.append((o, next_close))

    target_idx = line_no - 1
    for open_i, close_i in pairs:
        if open_i <= target_idx <= close_i:
            name = _extract_function_name(lines, open_i)
            if not name:
                continue
            header = _extract_doxygen_header(lines, open_i, name)
            body_lines = lines[open_i:min(close_i + 1, open_i + 40)]
            return FunctionInfo(
                name=name, start_line=open_i + 1, end_line=close_i + 1,
                header_comment=header, body_preview="\n".join(body_lines),
            )
    return None


def _extract_function_name(lines: List[str], open_brace_idx: int) -> Optional[str]:
    # Walk upward from the opening brace to the nearest line of the form
    # `FunctionName (` at column 0 — EDK2 style always has the function
    # name (not the return type) as the first token of that line. Bounded
    # to 30 lines back, which comfortably covers EDK2's typical
    # return-type-line + multi-line-parameter-list signatures.
    for i in range(open_brace_idx - 1, max(-1, open_brace_idx - 30), -1):
        m = _FUNC_NAME_LINE.match(lines[i])
        if m:
            return m.group(1)
    return None


def _extract_doxygen_header(lines: List[str], open_brace_idx: int,
                             func_name: str) -> Optional[str]:
    # Find the signature start (the line with func_name), then walk further
    # up past any doxygen `/** ... **/` block immediately preceding it.
    sig_line_idx = None
    for i in range(open_brace_idx - 1, max(-1, open_brace_idx - 30), -1):
        if _FUNC_NAME_LINE.match(lines[i]):
            sig_line_idx = i
            break
    if sig_line_idx is None:
        return None
    # Skip the return-type line(s) directly above the signature.
    i = sig_line_idx - 1
    while i >= 0 and lines[i].strip() and not _DOXYGEN_END.match(lines[i]):
        i -= 1
    if i < 0 or not _DOXYGEN_END.match(lines[i]):
        return None
    end_of_comment = i
    start_of_comment = i
    while start_of_comment >= 0 and not lines[start_of_comment].strip().startswith("/**"):
        start_of_comment -= 1
    if start_of_comment < 0:
        return None
    return "\n".join(lines[start_of_comment:end_of_comment + 1])


def find_call_sites(edk2_checkout: str, function_name: str,
                     definition_file: str, limit: int = 4,
                     context_lines: int = 3) -> List[CallSite]:
    """grep the edk2 tree for real call sites of `function_name`, excluding
    its own definition file — the direct analog of PoCGen extracting usage
    snippets from test files by finding call sites of the vulnerable
    function."""
    try:
        proc = subprocess.run(
            ["grep", "-rn", "-P", "--include=*.c",
             rf"\b{re.escape(function_name)}\s*\(", edk2_checkout],
            capture_output=True, text=True, timeout=60,
        )
    except FileNotFoundError:
        return []
    if proc.returncode not in (0, 1):  # 1 = no matches, still fine
        return []

    sites: List[CallSite] = []
    seen_files = set()
    abs_def_file = os.path.abspath(os.path.join(edk2_checkout, definition_file))
    for line in proc.stdout.splitlines():
        try:
            path, line_no_str, _rest = line.split(":", 2)
        except ValueError:
            continue
        if os.path.abspath(path) == abs_def_file:
            continue  # skip the definition itself, we already have its body
        if path in seen_files:
            continue  # one example per file keeps the prompt varied, not repetitive
        line_no = int(line_no_str)
        with open(path, "r", errors="replace") as f:
            file_lines = f.readlines()
        start = max(0, line_no - context_lines - 1)
        end = min(len(file_lines), line_no + context_lines)
        snippet = "".join(file_lines[start:end])
        rel_path = os.path.relpath(path, edk2_checkout)
        sites.append(CallSite(file=rel_path, line=line_no, snippet=snippet))
        seen_files.add(path)
        if len(sites) >= limit:
            break
    return sites


def summarize_usage(function_info: FunctionInfo, call_sites: List[CallSite]) -> str:
    """LLM summarization step — PoCGen's analog: prompt an LLM to confirm/
    summarize extracted usage evidence rather than dumping raw snippets
    into the harness-generation prompt unfiltered."""
    import harness_generator  # local import: avoid a hard dependency for
                               # callers that only want the raw extraction

    parts = [f"Function: {function_info.name}"]
    if function_info.header_comment:
        parts.append(f"Header comment:\n{function_info.header_comment}")
    parts.append(f"Body (first lines):\n{function_info.body_preview}")
    for site in call_sites:
        parts.append(f"Call site in {site.file}:{site.line}:\n{site.snippet}")

    prompt = (
        "Below is a C function from EDK2 (UEFI firmware) plus real call "
        "sites of it elsewhere in the codebase.\n\n"
        + "\n\n".join(parts)
        + "\n\nSummarize, in under 150 words: (1) what each parameter "
          "actually represents and any constraints implied by real callers "
          "(buffer/length pairs, expected value ranges, null-checks callers "
          "perform before calling it, etc.), and (2) the minimal realistic "
          "way to invoke this function that a fuzz harness should replicate. "
          "Be concrete and specific to this function — no generic advice."
    )
    return harness_generator.call_llm(prompt)


def build_usage_context(edk2_checkout: str, revision: str, file_path: str,
                         changed_line: int) -> Optional[str]:
    """End-to-end: locate the function, extract header + call sites, and
    return an LLM summary — or None if nothing useful was found (in which
    case the caller should fall back gracefully, same convention as
    codeql_taint.py)."""
    result = subprocess.run(
        ["git", "-C", edk2_checkout, "show", f"{revision}:{file_path}"],
        capture_output=True, text=True, timeout=15,
    )
    if result.returncode != 0:
        return None
    func = find_enclosing_function(result.stdout, changed_line)
    if not func:
        return None
    call_sites = find_call_sites(edk2_checkout, func.name, file_path)
    try:
        return summarize_usage(func, call_sites)
    except Exception as e:
        print(f"[!] Usage summarization failed, continuing without it: {e}",
              file=sys.stderr)
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--edk2-checkout", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--file", required=True)
    parser.add_argument("--line", type=int, required=True)
    args = parser.parse_args()

    summary = build_usage_context(args.edk2_checkout, args.revision, args.file, args.line)
    print(summary or "(no usage context found)")


if __name__ == "__main__":
    main()
