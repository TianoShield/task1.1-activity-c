"""
pocgen_validation.py

Adapts the validation methodology from PoCGen (Simsek, Eghbali, Pradel;
"PoCGen: Generating Proof-of-Concept Exploits for Vulnerabilities in Npm
Packages", FSE 2026) to HBFAplusplus's UEFI/C fuzzing pipeline.

PoCGen's validation has three layers (Section 2.4 of the paper):
  1. A vulnerability-type-specific validator (objective, mechanical check).
  2. A sanity check that the vulnerable function actually appears in the
     call stack when the bug fires (rules out "right crash, wrong cause").
  3. An LLM-based final check that the exploit genuinely matches the
     vulnerability described in the report (filters false positives that
     pass the mechanical checks for unrelated reasons).

This module reimplements that same three-layer structure for ASAN-style
crash output from a compiled AFL++ target, instead of V8 runtime hooks.

Integration point: call `validate_poc(...)` from validator.py right after
a crash is reproduced pre-fix and confirmed absent post-fix, BEFORE
returning verdict="confirmed". If validate_poc returns ok=False, downgrade
the verdict instead (e.g. to "false_positive" or "needs_review").
"""

from __future__ import annotations

import re
import subprocess
import json
from dataclasses import dataclass, field
from typing import Callable, Optional


# ============================================================
# Layer 1 — per-vulnerability-type validators
# ============================================================
#
# PoCGen's validators (Section 2.4.1-2.4.5) are each a short, objective,
# mechanical check tied to what "success" concretely looks like for that
# bug class. The UEFI/C equivalents below key off ASAN's crash summary
# line, which names the bug class explicitly
# (e.g. "heap-buffer-overflow", "SEGV on unknown address", "use-after-free").
#
# Add one entry per bug class you actually see across your advisories.
# Each validator receives the raw ASAN/UBSan output and returns True if
# the crash is of the expected class for that advisory.

def _asan_error_block(asan_output: str) -> str:
    """
    ASAN's crash class (heap-buffer-overflow, etc.) is on the ERROR: line,
    but the access kind (READ/WRITE of size N) is on the line right after
    it, and the bug-class name also repeats on the SUMMARY: line at the
    end. Rather than matching a single line, pull the whole block from
    the first "==NNNN==ERROR:" line through the "SUMMARY:" line (or end
    of output), so fragments can come from anywhere in that block.
    """
    lines = asan_output.splitlines()
    start = next((i for i, l in enumerate(lines) if re.search(r"==\d+==ERROR:", l)), None)
    if start is None:
        return asan_output  # fall back to searching everything
    end = next(
        (i for i in range(start, len(lines)) if "SUMMARY:" in lines[i]),
        len(lines) - 1,
    )
    return "\n".join(lines[start:end + 1])


def _asan_summary_contains(asan_output: str, *fragments: str) -> bool:
    """True if every fragment appears somewhere in the ASAN error block."""
    block = _asan_error_block(asan_output)
    return all(f in block for f in fragments)


VULN_TYPE_VALIDATORS: dict[str, Callable[[str], bool]] = {
    "heap-buffer-overflow-read": lambda out: _asan_summary_contains(
        out, "heap-buffer-overflow", "READ"
    ),
    "heap-buffer-overflow-write": lambda out: _asan_summary_contains(
        out, "heap-buffer-overflow", "WRITE"
    ),
    "stack-buffer-overflow": lambda out: _asan_summary_contains(
        out, "stack-buffer-overflow"
    ),
    "global-buffer-overflow": lambda out: _asan_summary_contains(
        out, "global-buffer-overflow"
    ),
    "use-after-free": lambda out: _asan_summary_contains(
        out, "heap-use-after-free"
    ),
    "null-deref": lambda out: (
        "SEGV on unknown address" in out and "0x000000000000" in out
    ),
    "oob-read-generic": lambda out: "READ" in out and (
        "heap-buffer-overflow" in out
        or "stack-buffer-overflow" in out
        or "global-buffer-overflow" in out
    ),
    "oob-write-generic": lambda out: "WRITE" in out and (
        "heap-buffer-overflow" in out
        or "stack-buffer-overflow" in out
        or "global-buffer-overflow" in out
    ),
    "integer-overflow": lambda out: _asan_summary_contains(
        out, "UndefinedBehaviorSanitizer", "overflow"
    ),
    "assertion-failure": lambda out: (
        "ASSERT" in out or "Assertion" in out
    ),
}


def validate_vuln_type(asan_output: str, vuln_type: str) -> bool:
    """
    Layer 1: mechanical, objective check that the crash matches the
    expected bug class for this advisory. Mirrors PoCGen 2.4.1-2.4.5:
    each vulnerability type has ONE concrete, checkable definition of
    "the exploit worked" rather than "something crashed".
    """
    validator = VULN_TYPE_VALIDATORS.get(vuln_type)
    if validator is None:
        raise KeyError(
            f"No validator registered for vuln_type={vuln_type!r}. "
            f"Add one to VULN_TYPE_VALIDATORS — do not silently pass "
            f"unclassified crashes, that defeats the point of this layer."
        )
    return validator(asan_output)


# ============================================================
# Layer 2 — sanity check: was the vulnerable function actually on the
# call stack when the crash happened?
# ============================================================
#
# PoCGen (2.4.6): "we search the call stack when the vulnerability is
# triggered for a call to the vulnerable function. If no such call is
# found, the exploit is considered invalid." This stops a PoC from being
# credited for crashing somewhere unrelated to the harness's actual
# target function.

def sanity_check_call_stack(asan_output: str, vulnerable_function: str) -> bool:
    """
    Layer 2: confirm `vulnerable_function` (a C symbol name, e.g.
    "PeCoffLoaderGetImageInfo") appears somewhere in the ASAN backtrace.

    ASAN backtraces look like:
        #0 0x... in PeCoffLoaderGetImageInfo /path/to/file.c:123
        #1 0x... in TestPeCoffLoader /path/to/harness.c:45
        ...
    We match on the mangled-or-demangled symbol name appearing after
    "in " on any "#N " frame line. Loose substring match on purpose —
    inlined/static functions sometimes get a suffix like
    ".part.0" or ".constprop.0" from the compiler.
    """
    frame_lines = [
        line for line in asan_output.splitlines()
        if re.match(r"\s*#\d+\s", line)
    ]
    return any(vulnerable_function in line for line in frame_lines)


# ============================================================
# Layer 3 — LLM-based false-positive filter
# ============================================================
#
# PoCGen (end of 2.4.6): "we prompt the LLM to check whether the exploit
# actually triggers the vulnerability described in the report. This is
# done to filter out any invalid exploits that passed the previous
# validation checks." This is the layer that catches: right function,
# right bug class, but not actually what the advisory describes (e.g. a
# denial-of-service crash reported as a memory-corruption advisory).
#
# `call_llm` is intentionally left as a thin seam — wire it to whatever
# API you already call elsewhere in the pipeline (OpenAI, Anthropic,
# etc.) rather than hardcoding a provider here.

LLM_FALSE_POSITIVE_PROMPT_TEMPLATE = """\
You are reviewing a proof-of-concept crash to confirm it demonstrates a \
specific reported vulnerability, not an unrelated bug that happens to \
crash the same binary.

## Vulnerability report
{advisory_text}

## Vulnerable function (per the harness)
{vulnerable_function}

## ASAN/crash output produced by the PoC input
```
{asan_output}
```

## Task
Answer with a single JSON object, nothing else:
{{"matches_advisory": true|false, "reason": "<one or two sentences>"}}

Consider it a match only if the crash's root cause plausibly matches the \
mechanism described in the advisory (e.g. a heap overflow while parsing \
the malformed field the advisory names) — not merely "some crash \
happened in the right function."
"""


def build_false_positive_prompt(
    advisory_text: str, vulnerable_function: str, asan_output: str
) -> str:
    return LLM_FALSE_POSITIVE_PROMPT_TEMPLATE.format(
        advisory_text=advisory_text.strip(),
        vulnerable_function=vulnerable_function,
        asan_output=asan_output.strip()[-4000:],  # keep prompt bounded
    )


def llm_confirm_exploit(
    call_llm: Callable[[str], str],
    advisory_text: str,
    vulnerable_function: str,
    asan_output: str,
) -> tuple[bool, str]:
    """
    Layer 3. `call_llm` is a function you supply: str prompt -> str
    response. Keeping it injected (rather than importing an SDK here)
    means this module has zero hard dependency on which LLM provider
    HBFAplus's pipeline already uses.
    """
    prompt = build_false_positive_prompt(
        advisory_text, vulnerable_function, asan_output
    )
    raw = call_llm(prompt)
    try:
        parsed = json.loads(raw)
        return bool(parsed["matches_advisory"]), str(parsed.get("reason", ""))
    except (json.JSONDecodeError, KeyError):
        # Fail closed: if the LLM didn't return parseable JSON, don't
        # silently accept the exploit as validated.
        return False, f"Unparseable LLM response: {raw[:300]!r}"


# ============================================================
# Combined entry point
# ============================================================

@dataclass
class PoCValidationResult:
    ok: bool
    layer_failed: Optional[str] = None   # "vuln_type" | "call_stack" | "llm" | None
    reason: str = ""


def validate_poc(
    *,
    asan_output: str,
    vuln_type: str,
    vulnerable_function: str,
    advisory_text: str,
    call_llm: Optional[Callable[[str], str]] = None,
) -> PoCValidationResult:
    """
    Runs all three PoCGen-style layers in order, short-circuiting on the
    first failure (cheapest/most-mechanical checks first, LLM last —
    same ordering PoCGen uses, since the LLM call is the expensive one).
    """
    if not validate_vuln_type(asan_output, vuln_type):
        return PoCValidationResult(
            ok=False, layer_failed="vuln_type",
            reason=f"ASAN output does not match expected class for vuln_type={vuln_type!r}",
        )

    if not sanity_check_call_stack(asan_output, vulnerable_function):
        return PoCValidationResult(
            ok=False, layer_failed="call_stack",
            reason=f"{vulnerable_function!r} not found in crash backtrace",
        )

    if call_llm is not None:
        matches, reason = llm_confirm_exploit(
            call_llm, advisory_text, vulnerable_function, asan_output
        )
        if not matches:
            return PoCValidationResult(ok=False, layer_failed="llm", reason=reason)

    return PoCValidationResult(ok=True)


# ============================================================
# Refinement loop (PoCGen Fig. 7, adapted)
# ============================================================
#
# PoCGen's loop refines the EXPLOIT-GENERATION prompt when a candidate
# fails. In your pipeline, the closer analogue is refining HARNESS
# GENERATION when a candidate harness fails to build, or builds but
# never reaches the vulnerable function during fuzzing. The scoring
# idea (Fig. 7, lines 14-17: score by new errors surfaced + taint/coverage
# progress) carries over directly.
#
# This is a skeleton, not a drop-in — `generate_harness` and
# `build_and_short_fuzz` are stubs you wire to your existing
# harness-generation and validator.build_harness()/run_short_fuzz()
# functions.

import heapq
import itertools


@dataclass(order=True)
class _QueueItem:
    score: int
    seq: int = field(compare=True)
    prompt: str = field(compare=False)


class RefinementLoop:
    """
    Priority-queue refinement loop, mirroring PoCGen's algorithm
    (Fig. 7): try a prompt, and if it fails, push a refined prompt back
    onto the queue with a score reflecting how much new information the
    attempt surfaced. Higher score = tried sooner. Stops at max_attempts
    (PoCGen uses 30) or on first success.
    """

    def __init__(
        self,
        seed_prompt: str,
        generate_harness: Callable[[str], str],
        build_and_short_fuzz: Callable[[str], dict],
        max_attempts: int = 30,
    ):
        self.generate_harness = generate_harness
        self.build_and_short_fuzz = build_and_short_fuzz
        self.max_attempts = max_attempts
        self._counter = itertools.count()
        self._heap: list[_QueueItem] = []
        self._seen_harnesses: set[str] = set()
        self._push(seed_prompt, score=0)

    def _push(self, prompt: str, score: int) -> None:
        # heapq is a min-heap; negate score so higher score pops first.
        heapq.heappush(self._heap, _QueueItem(-score, next(self._counter), prompt))

    def run(self) -> Optional[str]:
        attempts = 0
        while self._heap and attempts < self.max_attempts:
            item = heapq.heappop(self._heap)
            attempts += 1

            harness_code = self.generate_harness(item.prompt)
            if harness_code in self._seen_harnesses:
                continue  # PoCGen: don't re-query the LLM for a repeat
            self._seen_harnesses.add(harness_code)

            result = self.build_and_short_fuzz(harness_code)
            if result.get("success"):
                return harness_code

            # Build the refined prompt + score exactly as PoCGen does:
            # append new error text / coverage info, score by how much
            # new signal this attempt produced.
            new_info = result.get("build_error") or result.get("coverage_gap") or ""
            score = len(new_info.splitlines())  # crude proxy for "new signal"
            refined_prompt = item.prompt + f"\n\n## Feedback from previous attempt:\n{new_info}"
            self._push(refined_prompt, score)

        return None
