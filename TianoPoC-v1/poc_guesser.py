#!/usr/bin/env python3
# @file
#
# Component (iii)-part-0: direct PoC-input guessing — this is the piece
# that makes the LLM's role match PoCGen's more closely than the plain
# harness-generation flow does on its own.
#
# harness_generator.py produces a *harness*: generic scaffolding that reads
# whatever bytes a fuzzer feeds it (MockFuzzContextGetU8, etc.) and routes
# them into the target. It never proposes a specific triggering input —
# that's structurally different from PoCGen, whose LLM directly proposes a
# concrete candidate exploit value each round (e.g. Fig. 2's
# `'a'.repeat(30000)`), tested immediately, refined guess-by-guess.
#
# This module adds that missing piece: once a harness builds successfully,
# before reaching for AFL++'s blind search, ask the LLM to propose a
# specific byte sequence it believes will reach the vulnerable line and
# trigger the crash — grounded in the harness's own byte-consumption logic
# (so the guess is a plausible input for *this* harness, not a guess in the
# abstract) — test that one input directly via a single execution, and if
# it doesn't crash, feed the LLM the actual outcome (no crash / wrong
# crash / harness error) and ask for a refined guess. This is cheap (no
# fuzzing campaign) and can succeed in one or two rounds for bugs with an
# obvious trigger shape (e.g. "just make Length huge"), falling back to
# AFL++'s blind search only once this direct-guessing budget is exhausted.
#
# Copyright (c) 2025-2026 TianoShield Contributors.
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
import dataclasses
import os
import re
import sys
import tempfile
from typing import List, Optional

sys.path.insert(0, os.path.dirname(__file__))

GUESS_PROMPT_TEMPLATE = """\
`{module}` is vulnerable.

## Vulnerability Description:

```
{advisory_description}
```

## Usage examples of the vulnerable function
{usage_context}

## Harness (this is what will actually run your exploit input — its
## byte-reading logic is the fixed "skeleton" your exploit must fit into)
```c
{harness_source}
```

## Task:

Create an exploit that uses the vulnerability in `{module}` to trigger a
crash (memory-safety fault: buffer overflow, out-of-bounds read/write, or
similar) when the harness above processes it.
Respond with the full exploit and explain why it works.
If the vulnerable function can throw or return an error, do not try to
handle it and pass it on — the exploit must not guard against or suppress
the crash.
Enclose the exploit as a hex-encoded byte string, under a heading
`GUESS (hex):`.

{previous_attempts}

## Source code:
{source_snippets}
"""

_HEX_BLOCK_RE = re.compile(r"GUESS \(hex\):\s*\n([0-9a-fA-F\s]+)")


@dataclasses.dataclass
class GuessAttempt:
    guess_hex: str
    reasoning: str
    crashed: bool
    asan_summary: Optional[str]
    outcome_note: str  # human-readable summary of what happened, fed back
                       # into the next guess's prompt


@dataclasses.dataclass
class GuessLoopResult:
    success: bool
    crash_input_path: Optional[str]  # only set if success
    asan_summary: Optional[str]
    attempts: List[GuessAttempt]


def build_guess_prompt(advisory: dict, target: dict, harness_source: str,
                        previous_attempts: List[GuessAttempt],
                        usage_context: str = "(not available)",
                        source_snippets: str = "(not available)") -> str:
    if previous_attempts:
        # Nearest real equivalent to PoCGen's `similarExploits` few-shot
        # slot: PoCGen retrieves similar *past* exploits via BM25 across
        # its whole corpus; there's no equivalent corpus of past guesses
        # across different advisories/runs here, so the closest honest
        # analog is the guesses already tried *this session* — still
        # "examples of what has/hasn't worked," just scoped to one run
        # rather than a cross-run corpus.
        parts = ["## Previous exploit attempts this session and what actually happened"]
        for i, att in enumerate(previous_attempts, 1):
            parts.append(
                f"Exploit attempt {i}: {att.guess_hex}\n"
                f"Your reasoning was: {att.reasoning}\n"
                f"Actual outcome: {att.outcome_note}"
            )
        previous_block = "\n\n".join(parts)
    else:
        previous_block = ""

    return GUESS_PROMPT_TEMPLATE.format(
        module=target.get("module", "the target module"),
        advisory_description=(advisory.get("description")
                               or advisory.get("summary", "")),
        usage_context=usage_context,
        harness_source=harness_source,
        previous_attempts=previous_block,
        source_snippets=source_snippets,
    )


def parse_guess(response: str) -> bytes:
    m = _HEX_BLOCK_RE.search(response)
    if not m:
        raise ValueError(
            "LLM guess response didn't contain a 'GUESS (hex):' block; "
            f"got:\n{response[:500]}"
        )
    hex_str = re.sub(r"\s+", "", m.group(1))
    try:
        return bytes.fromhex(hex_str)
    except ValueError as e:
        raise ValueError(f"LLM guess wasn't valid hex ({e}): {hex_str[:100]}") from e


def _describe_outcome(result) -> str:
    """`result` is a validator.FuzzResult from replay_input()."""
    if result.crashed:
        return f"CRASHED — ASan reported: {result.asan_summary or '(no summary captured)'}"
    tail = (result.stderr_tail or "").strip()
    if tail:
        return f"did NOT crash. Harness stderr: {tail[-300:]}"
    return "did NOT crash, and produced no stderr output — likely rejected early by a length/bounds check before reaching the vulnerable code."


def guess_and_test_loop(binary_path: str, advisory: dict, target: dict,
                         harness_source: str, max_guesses: int = 4,
                         work_dir: Optional[str] = None,
                         usage_context: str = "(not available)",
                         source_snippets: str = "(not available)") -> GuessLoopResult:
    """Direct port of PoCGen's guess -> test -> refine loop, scoped to a
    specific input rather than harness code. Returns as soon as one guess
    crashes; otherwise exhausts `max_guesses` and reports every attempt.

    `usage_context` and `source_snippets` mirror PoCGen's own
    `usageSnippets`/`taintPathSnippets` prompt slots (see build_guess_prompt)
    — pass through harness_generator.py's already-computed values for these
    so the guess is grounded in the actual vulnerable code, not just the
    harness's byte-reading shape and the advisory's prose description.
    """
    import harness_generator  # reuse the one call_llm() implementation
    import validator

    work_dir = work_dir or tempfile.mkdtemp(prefix="hbfa_poc_guess_")
    attempts: List[GuessAttempt] = []

    for i in range(max_guesses):
        prompt = build_guess_prompt(advisory, target, harness_source, attempts,
                                     usage_context, source_snippets)
        try:
            response = harness_generator.call_llm(
                prompt,
                system_prompt=f"You are proposing concrete exploits for "
                               f"a fuzz harness targeting "
                               f"{target.get('module', 'a UEFI driver')}. "
                               f"Respond only in the exact requested format.",
            )
            guess_bytes = parse_guess(response)
        except Exception as e:
            attempts.append(GuessAttempt(
                guess_hex="(parse failed)", reasoning="",
                crashed=False, asan_summary=None,
                outcome_note=f"Your response could not be parsed: {e}",
            ))
            continue

        input_path = os.path.join(work_dir, f"guess_{i}.bin")
        with open(input_path, "wb") as f:
            f.write(guess_bytes)

        result = validator.replay_input(binary_path, input_path)
        reasoning_m = re.search(r"REASONING:\s*\n?(.+)", response, re.DOTALL)
        reasoning = reasoning_m.group(1).strip()[:300] if reasoning_m else ""

        attempt = GuessAttempt(
            guess_hex=guess_bytes.hex(), reasoning=reasoning,
            crashed=result.crashed, asan_summary=result.asan_summary,
            outcome_note=_describe_outcome(result),
        )
        attempts.append(attempt)

        if result.crashed:
            return GuessLoopResult(
                success=True, crash_input_path=input_path,
                asan_summary=result.asan_summary, attempts=attempts,
            )

    return GuessLoopResult(success=False, crash_input_path=None,
                            asan_summary=None, attempts=attempts)


def main():
    import argparse
    import json

    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--advisory-json", required=True)
    parser.add_argument("--target-json", required=True)
    parser.add_argument("--harness-c", required=True)
    parser.add_argument("--max-guesses", type=int, default=4)
    args = parser.parse_args()

    with open(args.advisory_json) as f:
        advisory = json.load(f)
    with open(args.target_json) as f:
        target = json.load(f)
    with open(args.harness_c) as f:
        harness_source = f.read()

    result = guess_and_test_loop(args.binary, advisory, target,
                                  harness_source, args.max_guesses)
    print(json.dumps(dataclasses.asdict(result), indent=2))


if __name__ == "__main__":
    main()
