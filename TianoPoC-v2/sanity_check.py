#!/usr/bin/env python3
# @file
#
# Component (iii)-part-2: LLM sanity check — direct analog of PoCGen
# Section 2.4.6. PoCGen's own words on why this exists: "Passing the
# vulnerability-specific validation checks is a necessary condition for an
# exploit to be considered valid, but it is not sufficient as it is
# possible to achieve the desired outcome with other means." Their example:
# a ReDoS validator just measures execution time, so an LLM might generate
# a slow regex unrelated to the actual vulnerable function.
#
# The mechanical analog for us is validator.py's `confirmed` verdict: it
# only checks "did ASan abort pre-fix, and not post-fix, for the same
# input, with the target module somewhere on the call stack" (see
# validator.py's docstring). That's a meaningfully looser bar than "this is
# actually the bug the advisory describes" — a harness could, for example,
# trip an unrelated pre-existing bug in a mock protocol that happens to get
# fixed as a side effect of the same commit, or crash in a way that's
# nowhere near the advisory's actual described impact.
#
# This check runs ONLY on the `confirmed` path (i.e. rarely — once per
# advisory in the success case, not once per refinement attempt), same as
# PoCGen: it's the last gate before accepting a result, not part of the
# generate/build/fuzz inner loop.
#
# Copyright (c) 2025-2026 TianoShield Contributors.
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
import dataclasses
import re
import sys
import os
from typing import Optional

sys.path.insert(0, os.path.dirname(__file__))

PROMPT_TEMPLATE = """\
You are reviewing a candidate regression-test harness for an EDK2 security
advisory, to catch false positives before it's accepted. A false positive
here means: the harness crashes, and the crash disappears after the fix —
but for a reason unrelated to the actual vulnerability described in the
advisory (e.g. it happens to trip a different, coincidentally-also-fixed
bug, or the "crash" is a memory-safety issue in the fuzz harness's own
mock/glue code rather than in the target module).

## Advisory
{advisory_id} ({cve_id})
{advisory_summary}
{advisory_description}

## Target
Package: {package}, Module: {module}
Files the fix commit changed:
{changed_files}

## The harness that reproduced a crash pre-fix and not post-fix
```c
{harness_source}
```

## What actually crashed (ASan)
Rule/summary: {asan_summary}
```
{asan_stderr_tail}
```

## Task
Does this crash genuinely demonstrate the vulnerability described above,
reached through the target module's real entry point (not a fabricated or
unrelated crash, and not a bug in the harness's own mock/glue code rather
than in {module} itself)?

Respond with exactly two lines:
VERDICT: YES
or
VERDICT: NO

followed by a one-paragraph justification referencing the specific ASan
summary and the advisory's described impact.
"""

_VERDICT_RE = re.compile(r"VERDICT:\s*(YES|NO)", re.IGNORECASE)


@dataclasses.dataclass
class SanityCheckResult:
    passed: bool
    reasoning: str


def build_prompt(advisory: dict, target: dict, harness_source: str,
                  asan_summary: Optional[str], asan_stderr_tail: str) -> str:
    return PROMPT_TEMPLATE.format(
        advisory_id=advisory.get("ghsa_id", "unknown"),
        cve_id=advisory.get("cve_id") or "no CVE assigned",
        advisory_summary=advisory.get("summary", ""),
        advisory_description=advisory.get("description", ""),
        package=target.get("package"),
        module=target.get("module"),
        changed_files="\n".join(f"- {p}" for p in target.get("changed_source_files", [])),
        harness_source=harness_source,
        asan_summary=asan_summary or "(no summary line captured)",
        asan_stderr_tail=asan_stderr_tail,
    )


def check(advisory: dict, target: dict, harness_source: str,
          asan_summary: Optional[str], asan_stderr_tail: str) -> SanityCheckResult:
    import harness_generator  # reuse the one call_llm() implementation

    prompt = build_prompt(advisory, target, harness_source, asan_summary,
                           asan_stderr_tail)
    response = harness_generator.call_llm(prompt)
    m = _VERDICT_RE.search(response)
    if not m:
        # Fail closed: an unparseable response is treated as "did not pass
        # sanity check" rather than silently accepted — same spirit as
        # PoCGen never letting the LLM's opinion override the mechanical
        # validators when the two disagree/are ambiguous.
        return SanityCheckResult(
            passed=False,
            reasoning=f"Sanity check response didn't contain a parseable "
                      f"VERDICT line; treating as failed. Raw response:\n{response}",
        )
    passed = m.group(1).upper() == "YES"
    return SanityCheckResult(passed=passed, reasoning=response)


def main():
    import argparse
    import json

    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--advisory-json", required=True)
    parser.add_argument("--target-json", required=True)
    parser.add_argument("--harness-c", required=True, help="Path to the harness .c file")
    parser.add_argument("--asan-summary")
    parser.add_argument("--asan-stderr-file",
                         help="Path to a file containing the ASan stderr tail")
    args = parser.parse_args()

    with open(args.advisory_json) as f:
        advisory = json.load(f)
    with open(args.target_json) as f:
        target = json.load(f)
    with open(args.harness_c) as f:
        harness_source = f.read()
    stderr_tail = ""
    if args.asan_stderr_file:
        with open(args.asan_stderr_file) as f:
            stderr_tail = f.read()

    result = check(advisory, target, harness_source, args.asan_summary, stderr_tail)
    print(json.dumps(dataclasses.asdict(result), indent=2))
    sys.exit(0 if result.passed else 1)


if __name__ == "__main__":
    main()
