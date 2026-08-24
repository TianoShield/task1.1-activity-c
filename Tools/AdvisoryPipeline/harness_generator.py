#!/usr/bin/env python3
# @file
#
# Component (ii): generates a candidate fuzz harness (INF + C) for a Target
# resolved by target_mapper.py, given a security advisory. This is the LLM
# step of the pipeline — structurally the same role PoCGen's
# "Exploit Generation" component plays, except the artifact produced is a
# defensive fuzz harness (INF/C) rather than an exploit script, and the
# few-shot "similar exploits" are replaced by sibling HBFAplus harnesses.
#
# Copyright (c) 2025-2026 TianoShield Contributors.
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
"""
Requires the same .env-style config as the rest of this repo's tooling:
    OPENAI_API_KEY=...            # or "ollama" for a local Ollama model
    OPENAI_BASE_URL=...           # e.g. http://localhost:11434/v1 for Ollama
    HBFA_LLM_MODEL=...            # model name known to that endpoint

Usage:
    python3 harness_generator.py \\
        --advisory-json resolved_advisory.json \\
        --target-json target.json \\
        --edk2-checkout /path/to/edk2 \\
        --pre-fix-commit <sha> \\
        --out-dir HBFAplus/FuzzHarness/NetworkPkg/Dhcp6Dxe/TestDhcp6DriverAdv \\
        --extra-context "error: previous attempt failed to link, X undefined"
"""
import argparse
import dataclasses
import json
import os
import re
import subprocess
import sys
import textwrap
import urllib.error
import urllib.request
from typing import Dict, List, Optional

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
HBFAPLUS_ROOT = os.path.join(REPO_ROOT, "HBFAplus")
SKILLS_ROOT = os.path.join(REPO_ROOT, ".claude", "skills")

# Skills relevant to harness generation, read as prompt context — this plays
# the same role PoCGen's static-analysis-derived taint path / usage snippets
# play: giving the LLM concrete, project-specific ground truth instead of
# relying on general C/UEFI knowledge alone.
_RELEVANT_SKILLS = ["fuzz-harness", "mock-creation", "deep-stack-harness"]

# Memoizes usage_snippets.build_usage_context() results across attempts
# within the same process — see build_prompt()'s usage_context block for
# why: it's a full extra LLM round-trip that never actually changes
# between retries of the same target, so recomputing it every attempt was
# pure wasted wall-clock time on real hardware.
_usage_context_cache: Dict[tuple, str] = {}

PROMPT_TEMPLATE = """\
You are a security engineer extending HBFAplus, a UEFI firmware fuzzing
framework built on EDK2 and AFL++. Your job is to write a fuzz harness that
exercises the code changed by a security fix, so the harness can be run
against the pre-fix source (to confirm it reproduces the bug) and the
post-fix source (to confirm the fix resolves it) as a regression test.

## Advisory
{advisory_id} ({cve_id}) — severity: {severity}
{advisory_summary}

{advisory_description}

## Target
Package: {package}
Module: {module}
Changed files (from the fix commit): 
{changed_files}

Suggested harness depth: {suggested_depth}
(See the depth taxonomy below — L1 mocks only the target's immediate
dependency; deeper levels run real drivers underneath it, down to the
network/SNP boundary for "Deep".)

## Vulnerable/changed source (pre-fix revision)
{source_snippets}

## Usage examples of the vulnerable function (extracted from the codebase, LLM-summarized)
{usage_context}

## Reference: HBFAplus harness-authoring rules
{skill_docs}

## Reference: a real, working sibling harness in this codebase
Use this as your structural template — same INF layout, same
ToolChainHarnessLib entry-point pattern, same style of fuzz-buffer-to-input
plumbing. Adapt it to the target module rather than inventing new patterns.

{sibling_example}

{extra_context}

## Task
Produce a harness for **{module}** specifically — not any other module.
1. `<BaseName>.inf` — the EDK2 module INF, following the sibling example's
   [Defines]/[Sources]/[Packages]/[LibraryClasses] structure. Use a fresh
   FILE_GUID (any valid GUID-formatted string).
2. `<BaseName>.c` — the harness source. It must call {module}'s real
   entry point / real API (never call the vulnerable function's internals
   directly), feed it fuzzer-controlled bytes that reach the changed
   lines, and must NOT hand-construct the crash condition — the crash
   must occur *through* {module}'s own logic.

Reaching {module} correctly — read this carefully:
- Check the "Usage examples" and "Source code" sections above FIRST to see
  how {module}'s function is actually invoked in real code. Not every
  module is reached through a UEFI protocol — many EDK2 modules are plain
  libraries, reached by calling the function directly (a normal C function
  call), with no protocol involved at all. If the usage examples show a
  direct function call, call it the same way — a direct function call,
  not through any protocol.
- Only go through a UEFI protocol if the usage examples or source code
  above actually show one being used for this specific module.
- Do NOT invent a protocol name, GUID, or interface that does not appear
  verbatim in the Usage examples or Source code sections above. A
  plausible-sounding name you construct yourself (e.g. by guessing at
  EDK2's `gEfiXxxProtocolGuid` naming convention) is not the same as a
  real one, and referencing a protocol that doesn't actually exist will
  cause the harness to fail to build entirely.

Do not add defensive checks (bounds checks, null checks, length
validation) that would prevent the crash from occurring — the harness's
job is to reach the existing bug as-is, not to fix or guard around it. If
the target function can throw/return an error status, let it propagate;
do not catch or suppress it.

After the code, briefly explain why the harness reaches {module}'s
vulnerable code path and why the crash should occur.

Respond with exactly two fenced code blocks, in this order:

```inf
<contents of the .inf file>
```

```c
<contents of the .c file>
```
"""


def _load_skill_docs(condensed: bool = False) -> str:
    if condensed:
        # Retry prompts: a short reminder instead of the full multi-KB
        # skill docs, for the same reason the sibling example gets trimmed
        # above — the model has already seen the full rules once.
        return ("(Full harness-authoring rules omitted on retry — you saw "
                "them in your previous attempt. Key reminders: use "
                "ToolChainHarnessLib's entry-point pattern, choose harness "
                "depth per the L1/L1L2/L3/Deep taxonomy, and never "
                "hand-construct the crash — it must occur through the "
                "target module's own real logic.)")
    parts = []
    for name in _RELEVANT_SKILLS:
        path = os.path.join(SKILLS_ROOT, name, "SKILL.md")
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                parts.append(f"### skill: {name}\n\n{f.read()}")
    return "\n\n".join(parts) if parts else "(no skill docs found)"


def _read_sibling_example(example_dir: str) -> str:
    """Render one sibling harness's INF+C as a single text block."""
    out = []
    for root, _dirs, files in os.walk(example_dir):
        for f in sorted(files):
            if f.endswith((".inf", ".c")):
                full = os.path.join(root, f)
                with open(full, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
                rel = os.path.relpath(full, HBFAPLUS_ROOT)
                lang = "inf" if f.endswith(".inf") else "c"
                out.append(f"`{rel}`:\n```{lang}\n{content}\n```")
    return "\n\n".join(out) if out else "(no example found)"


def _read_source_at_commit(edk2_checkout: str, commit: str, path: str,
                            max_chars: int = 4000) -> str:
    """git show <commit>:<path> against the local edk2 checkout, so the LLM
    sees the actual pre-fix source rather than guessing. Falls back to a
    placeholder if the checkout/commit isn't available locally (e.g. running
    target-mapping only, without a full edk2 clone)."""
    try:
        result = subprocess.run(
            ["git", "-C", edk2_checkout, "show", f"{commit}:{path}"],
            capture_output=True, text=True, timeout=15, check=True,
        )
        content = result.stdout
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
        return f"(source unavailable: {e})"
    if len(content) > max_chars:
        content = content[:max_chars] + "\n... (truncated)"
    return content


def _first_changed_line(edk2_checkout: str, pre_fix_commit: str, fix_commit: str,
                         file_path: str) -> Optional[int]:
    """Return the first line number (in the pre-fix revision) touched by the
    fix commit's diff for `file_path`, via `git diff` hunk headers."""
    try:
        result = subprocess.run(
            ["git", "-C", edk2_checkout, "diff", "--unified=0",
             pre_fix_commit, fix_commit, "--", file_path],
            capture_output=True, text=True, timeout=15, check=True,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return None
    for line in result.stdout.splitlines():
        m = re.match(r"^@@ -(\d+)", line)
        if m:
            return int(m.group(1))
    return None


# Memoizes get_source_snippets() the same way _usage_context_cache does for
# usage context — the CodeQL/raw-source computation is identical across
# every attempt for a given target, and poc_guesser.py needs the exact same
# value build_prompt() computed, without a second CodeQL run or duplicated
# logic.
_source_snippets_cache: Dict[tuple, str] = {}


def get_source_snippets(advisory: dict, target: dict,
                         edk2_checkout: Optional[str],
                         pre_fix_commit: Optional[str],
                         codeql_db_path: Optional[str] = None) -> str:
    """CodeQL taint path (tiers 1-3) if available, else raw pre-fix source
    for the changed files. This is PoCGen's `taintPathSnippets` slot —
    factored out as its own function so both harness_generator.py's main
    prompt and poc_guesser.py's guess prompt use the exact same computed
    value instead of each recomputing (or worse, poc_guesser.py never
    having it at all, which was the actual gap this closes)."""
    changed_files = target.get("changed_source_files", [])
    cache_key = (edk2_checkout, pre_fix_commit, codeql_db_path,
                 tuple(changed_files))
    if cache_key in _source_snippets_cache:
        return _source_snippets_cache[cache_key]

    source_snippets = None
    codeql_tier_used = None
    if codeql_db_path or edk2_checkout:
        try:
            import codeql_taint
            result = codeql_taint.analyze_with_fallbacks(
                db_path=codeql_db_path, changed_files=changed_files,
                edk2_checkout=edk2_checkout or "", pre_fix_commit=pre_fix_commit or "",
                advisory_summary=advisory.get("summary", ""),
            )
            codeql_tier_used = result["tier"]
            if result["findings"]:
                source_snippets = codeql_taint.render_taint_snippets(
                    result["findings"], edk2_checkout or codeql_db_path)
        except Exception as e:  # CodeQL is best-effort context, never fatal
            print(f"[!] CodeQL taint analysis unavailable, falling back to "
                  f"raw source: {e}", file=sys.stderr)

    if source_snippets is not None and codeql_tier_used:
        tier_label = {
            "builtin_suite": "CodeQL cpp-security-and-quality suite",
            "extended_query": "CodeQL extended custom taint query (built-in suite found nothing)",
            "llm_guess": "LLM-guessed sink (CodeQL found no static taint path)",
        }.get(codeql_tier_used, codeql_tier_used)
        source_snippets = f"[Source: {tier_label}]\n\n{source_snippets}"

    if source_snippets is None:
        if edk2_checkout and pre_fix_commit:
            snippets = []
            for path in changed_files[:5]:  # cap to keep the prompt bounded
                src = _read_source_at_commit(edk2_checkout, pre_fix_commit, path)
                snippets.append(f"### {path}\n```c\n{src}\n```")
            source_snippets = "\n\n".join(snippets)
        else:
            source_snippets = ("(no local edk2 checkout provided — pass "
                                "--edk2-checkout and --pre-fix-commit to include "
                                "real source)")

    _source_snippets_cache[cache_key] = source_snippets
    return source_snippets


def build_prompt(advisory: dict, target: dict, edk2_checkout: Optional[str],
                  pre_fix_commit: Optional[str], sibling_dir: Optional[str],
                  extra_context: str = "", codeql_db_path: Optional[str] = None,
                  fix_commit: Optional[str] = None,
                  force_condensed: bool = False) -> str:
    changed_files = target.get("changed_source_files", [])

    source_snippets = get_source_snippets(advisory, target, edk2_checkout,
                                           pre_fix_commit, codeql_db_path)

    # is_retry drives the same "drop the heavy reference material" behavior
    # either way it gets triggered: genuine retry feedback (the refinement
    # loop's normal case), or an explicit force_condensed request — for
    # best_effort.py specifically, which never retries at all (one-shot by
    # design) and so would otherwise always send the full, untrimmed
    # ~140k-character prompt every single time, defeating the entire point
    # of a "fast" mode. force_condensed lets it opt into the smaller prompt
    # without needing to fabricate fake "previous attempt" feedback text.
    is_retry = bool(extra_context.strip()) or force_condensed
    if is_retry:
        # PoCGen's own documented mitigation for prompt bloat across
        # refinements (§2.5.3): "PoCGen removes parts of the prompt that
        # the LLM has correctly used in the previous attempts... removes
        # the usage snippets from the prompt." The direct analog here: the
        # model has already seen the full sibling-harness template once: on
        # a retry, it needs the specific correction, not the whole
        # reference material again. Concretely, this matters more than it
        # might sound like — a large local model's prompt-processing time
        # scales with prompt size, so a prompt that keeps *growing* every
        # retry directly increases the odds the *next* retry times out
        # before it can even respond, turning failures into a
        # self-reinforcing spiral rather than genuinely more focused
        # follow-up attempts.
        sibling_example = ("(sibling harness example omitted on retry — "
                            "you already saw its full structure in your "
                            "previous attempt; focus on the feedback below "
                            "instead of re-deriving the template from scratch)")
    else:
        sibling_example = _read_sibling_example(sibling_dir) if sibling_dir else "(none)"

    usage_context = "(no local edk2 checkout provided)"
    if edk2_checkout and pre_fix_commit and fix_commit and changed_files:
        # Memoized: this depends only on the fixed edk2 checkout/commits/
        # changed-files — never on the retry feedback — so recomputing it
        # (a full separate LLM round-trip) on every single attempt,
        # including retries, was pure wasted wall-clock time. Compute once
        # per (checkout, pre-fix commit, fix commit, first changed file)
        # and reuse for the rest of this process's attempts.
        cache_key = (edk2_checkout, pre_fix_commit, fix_commit, changed_files[0])
        if cache_key in _usage_context_cache:
            usage_context = _usage_context_cache[cache_key]
        else:
            try:
                import usage_snippets
                # Anchor on the first changed file/line — best-effort; a fix
                # commit can touch several functions, but the first changed
                # file is usually where the primary vulnerable function lives.
                first_file = changed_files[0]
                diff_line = _first_changed_line(edk2_checkout, pre_fix_commit,
                                                 fix_commit, first_file)
                if diff_line:
                    summary = usage_snippets.build_usage_context(
                        edk2_checkout, pre_fix_commit, first_file, diff_line)
                    usage_context = summary or "(no usage evidence found for this function)"
                else:
                    usage_context = "(could not determine a changed line to anchor on)"
            except Exception as e:
                print(f"[!] Usage snippet extraction unavailable: {e}", file=sys.stderr)
                usage_context = "(usage snippet extraction failed, continuing without it)"
            _usage_context_cache[cache_key] = usage_context
    elif not fix_commit:
        usage_context = "(no fix_commit provided — can't diff to find the changed line)"

    return PROMPT_TEMPLATE.format(
        advisory_id=advisory.get("ghsa_id", "unknown"),
        cve_id=advisory.get("cve_id") or "no CVE assigned",
        severity=advisory.get("severity", "unknown"),
        advisory_summary=advisory.get("summary", ""),
        advisory_description=advisory.get("description", ""),
        package=target.get("package"),
        module=target.get("module"),
        changed_files="\n".join(f"- {p}" for p in changed_files),
        suggested_depth=target.get("suggested_depth"),
        source_snippets=source_snippets,
        usage_context=usage_context,
        skill_docs=_load_skill_docs(condensed=is_retry),
        sibling_example=sibling_example,
        extra_context=(f"## Feedback from previous attempt\n{extra_context}"
                        if extra_context else ""),
    )


def call_llm(prompt: str, system_prompt: Optional[str] = None) -> str:
    base_url = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
    api_key = os.environ.get("OPENAI_API_KEY", "")
    model = os.environ.get("HBFA_LLM_MODEL", "gpt-4o-mini")
    # Default of 180s was sized for a hosted API on fast hardware. Direct
    # measurement on real hardware (see AdvisoryPipeline debugging session)
    # showed the full first-attempt prompt (~38k tokens with skill docs +
    # sibling harness) was still only 80% through prompt processing at
    # 596s and climbing — even 600s was too short. 1500s (25 min) is a
    # safer default for a large local-model first attempt; override via
    # HBFA_LLM_TIMEOUT_S if your setup needs more (or much less, e.g. for
    # a fast hosted API — retries are far smaller and finish in seconds).
    timeout_s = int(os.environ.get("HBFA_LLM_TIMEOUT_S", "1500"))
    # How many tokens of context to request from a local Ollama model.
    # Confirmed by direct testing (see AdvisoryPipeline debugging session)
    # that Ollama's *default* context window can silently be as small as
    # 4096 tokens regardless of the model's real trained context length —
    # far smaller than this pipeline's typical ~30-40k token first-attempt
    # prompt, causing the model to lose earlier prompt content (including
    # the target module name) via context eviction well before it responds.
    # 65536 is a safe default given the prompt sizes we've measured;
    # override via HBFA_LLM_NUM_CTX if your hardware needs a smaller value
    # or your prompts are consistently larger.
    num_ctx = int(os.environ.get("HBFA_LLM_NUM_CTX", "65536"))

    # Direct port of PoCGen's real system.hbs: a persona tied to the actual
    # target ("security researcher specialized in exploiting
    # {{vulnerabilityType.label}} vulnerabilities"), not a generic role —
    # this also means the target module name now appears in *two* places
    # in the request (system message + Task section) instead of only once
    # near the top of a single long user message.
    if system_prompt is None:
        system_prompt = ("You are a precise systems/security engineer. "
                          "Follow the requested output format exactly.")

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": prompt},
    ]

    # Ollama's OpenAI-compatible /v1/chat/completions shim does not
    # reliably expose context-length control (no num_ctx equivalent in the
    # OpenAI request schema) — confirmed context-window behavior only
    # responds to Ollama's *native* API, which accepts an explicit
    # "options": {"num_ctx": N} field. Detect Ollama via the .env
    # convention this pipeline's own docs establish (OPENAI_API_KEY=ollama)
    # and switch to the native endpoint in that case; real OpenAI-compatible
    # providers (a hosted API, api_key set to something else) keep using
    # the standard /v1/chat/completions path unchanged.
    is_ollama = api_key.strip().lower() == "ollama"

    if is_ollama:
        # base_url is typically ".../v1" (OpenAI-compat convention); the
        # native API lives one level up, at the host root.
        native_root = base_url.rstrip("/")
        if native_root.endswith("/v1"):
            native_root = native_root[: -len("/v1")]
        body = json.dumps({
            "model": model,
            "messages": messages,
            "options": {"num_ctx": num_ctx},
            "stream": False,
        }).encode("utf-8")
        url = f"{native_root}/api/chat"
    else:
        body = json.dumps({
            "model": model,
            "messages": messages,
            "temperature": 0.2,
        }).encode("utf-8")
        url = f"{base_url.rstrip('/')}/chat/completions"

    req = urllib.request.Request(url, data=body)
    req.add_header("Content-Type", "application/json")
    if api_key and not is_ollama:
        req.add_header("Authorization", f"Bearer {api_key}")
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"LLM call failed: {e.code} {e.read().decode(errors='replace')}") from e
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise RuntimeError(
            f"LLM call timed out or failed to connect after {timeout_s}s "
            f"(prompt was {len(prompt)} chars). If you're running a local "
            f"model on limited hardware, this prompt size may genuinely "
            f"need more time — try increasing HBFA_LLM_TIMEOUT_S, or use a "
            f"smaller/faster model. Underlying error: {e}"
        ) from e

    if is_ollama:
        # Native /api/chat response shape: {"message": {"content": ...}, ...}
        return data["message"]["content"]
    return data["choices"][0]["message"]["content"]


_INF_BLOCK_RE = re.compile(r"```inf\s*\n(.*?)```", re.DOTALL)
_C_BLOCK_RE = re.compile(r"```c\s*\n(.*?)```", re.DOTALL)


def parse_response(text: str) -> Dict[str, str]:
    inf_m = _INF_BLOCK_RE.search(text)
    c_m = _C_BLOCK_RE.search(text)
    if not inf_m or not c_m:
        raise ValueError("LLM response did not contain both an ```inf and a "
                          "```c fenced block; got:\n" + text[:2000])
    return {"inf": inf_m.group(1).strip(), "c": c_m.group(1).strip()}


def _infer_base_name(inf_text: str) -> str:
    m = re.search(r"^\s*BASE_NAME\s*=\s*(\S+)", inf_text, re.MULTILINE)
    return m.group(1) if m else "TestGeneratedDriver"


def write_candidate(files: Dict[str, str], out_dir: str) -> Dict[str, str]:
    base_name = _infer_base_name(files["inf"])
    os.makedirs(out_dir, exist_ok=True)
    inf_path = os.path.join(out_dir, f"{base_name}.inf")
    c_path = os.path.join(out_dir, f"{base_name}.c")
    # Make sure the [Sources] section actually references the .c file we're
    # about to write, regardless of what the LLM guessed for the filename.
    inf_text = files["inf"]
    if f"{base_name}.c" not in inf_text:
        inf_text = re.sub(r"(\[Sources\]\s*\n)", rf"\1  {base_name}.c\n", inf_text, count=1)
    with open(inf_path, "w") as f:
        f.write(inf_text)
    with open(c_path, "w") as f:
        f.write(files["c"])
    return {"inf_path": inf_path, "c_path": c_path, "base_name": base_name}


_GUID_SYMBOL_RE = re.compile(r"\bg[A-Z][A-Za-z0-9]*Guid\b")
_ENTRY_POINT_SYMBOL_RE = re.compile(r"\b(\w+EntryPoint)\b")


def _symbol_exists_in_tree(symbol: str, *roots: str) -> bool:
    """Search for `symbol` as a whole word anywhere under any of `roots`.
    Cheap, no-compile way to answer "is this a real symbol or did the LLM
    invent it" — a real GUID/function is declared or defined SOMEWHERE in
    the codebase; a fabricated one won't appear anywhere at all.

    Pure Python, deliberately NOT shelling out to `grep`: macOS ships BSD
    grep by default, which doesn't support `-P` (Perl-compatible regex,
    used for the \\b word-boundary match) at all — `grep -P` fails
    immediately with "invalid option -- P" on BSD grep, which silently made
    every single call to this function report "not found" on macOS,
    including for genuinely real symbols (confirmed in production: this
    exact bug flagged the real `gEfiTcg2ProtocolGuid` as fabricated). Same
    category of GNU-vs-BSD tool incompatibility as the bash 3.2/`tr`/
    `realpath` issues found earlier — fixed the same way: stop depending on
    a system tool's specific flavor and do it in pure Python instead,
    which behaves identically on every platform.

    Excludes this tool's own directory from the search — otherwise a
    fabricated symbol named as an *example* in a docstring/comment here
    (as literally happened during development of this exact check: the
    docstring names both real fabricated symbols found in production
    testing) would be found and treated as "proof" it's real.
    """
    self_dir = os.path.dirname(os.path.abspath(__file__))
    symbol_re = re.compile(rf"\b{re.escape(symbol)}\b")
    text_extensions = (".c", ".h", ".inf", ".dec", ".dsc", ".py", ".md", ".txt")

    for root in roots:
        if not root or not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            # Skip this tool's own directory (see docstring above) and
            # version-control internals, which can be huge and irrelevant.
            dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__")]
            if os.path.abspath(dirpath).startswith(self_dir):
                dirnames[:] = []  # don't descend further into it either
                continue
            for filename in filenames:
                if not filename.endswith(text_extensions):
                    continue
                full_path = os.path.join(dirpath, filename)
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        if symbol_re.search(f.read()):
                            return True
                except (OSError, UnicodeDecodeError):
                    continue
    return False


_REQUIRED_HARNESS_FUNCTIONS = (
    "InitializeHarness", "RunTestHarness", "CleanupHarness", "GetMaxBufferSize",
)


def check_harness_implements_contract(files: Dict[str, str]) -> None:
    """Raise ValueError if the generated .c file doesn't actually define
    the four functions ToolChainHarnessLib's real main() calls
    (InitializeHarness, RunTestHarness, CleanupHarness, GetMaxBufferSize).

    This exists because of a real failure mode found in production
    testing: a candidate defined only a plausible-sounding
    `DxeTpmMeasureBootLibEntryPoint` function (echoing the exact
    fabricated-entry-point pattern from an earlier bug, just this time
    defined *locally* in the same file) and never implemented any of the
    four required contract functions at all. check_symbols_exist() didn't
    catch this, because its local-definition exemption correctly assumes
    "if it's defined right here, it's not a fabricated external symbol" —
    but that assumption says nothing about whether the file defines the
    *right* functions. A harness with zero fabricated/undefined symbols can
    still fail to actually be a harness at all; this check verifies the
    one thing that actually matters structurally: the required entry
    points ToolChainHarnessLib's main() will call into are genuinely
    present, not just "no obviously wrong symbols."
    """
    c_text = files.get("c", "")
    missing = []
    for func_name in _REQUIRED_HARNESS_FUNCTIONS:
        # Same definition-detection pattern used elsewhere: identifier,
        # parens, then an opening brace — matches both EDK2's strict
        # multi-line style and a single-line definition.
        def_re = re.compile(rf"\b{re.escape(func_name)}\s*\([^;{{}}]*\)\s*\{{",
                             re.DOTALL)
        if not def_re.search(c_text):
            missing.append(func_name)
    if missing:
        raise ValueError(
            "Generated harness does not define the required "
            f"ToolChainHarnessLib contract function(s): {', '.join(missing)}. "
            "Every harness must implement all four of "
            f"{', '.join(_REQUIRED_HARNESS_FUNCTIONS)} — these are what "
            "ToolChainHarnessLib's own main() calls into. Defining an "
            "unrelated entry-point function instead (even a real-looking, "
            "locally-defined one) is not sufficient; these exact four "
            "function names/signatures are required."
        )


def check_symbols_exist(files: Dict[str, str], edk2_checkout: Optional[str],
                         hbfaplus_root: Optional[str] = None) -> None:
    """Raise ValueError if the generated harness references a GUID or
    EntryPoint-style symbol that doesn't exist anywhere in real source.

    This exists because of a real failure mode found in production testing
    (best-effort mode, CVE-2022-36763): the LLM referenced a plausible-
    sounding but entirely fabricated protocol
    (`gEfiTcg2MeasureProtocolGuid`, not the real `gEfiTcg2ProtocolGuid`)
    and a fabricated driver entry point
    (`DxeTpmMeasureBootLibEntryPoint`, invented for a module that's
    actually a library, not a driver). `check_targets_correct_module()`
    only verifies the *module name* appears in the text — it has no way to
    catch a fabricated *symbol* dressed up around a correct module name.
    This check closes that gap without needing a compile: it's a text
    search against real source, so it works even in best_effort mode,
    which never builds anything at all.
    """
    if not edk2_checkout and not hbfaplus_root:
        return  # nothing to check against — best-effort with no checkout
    combined = files.get("inf", "") + "\n" + files.get("c", "")

    fabricated = []

    for guid in sorted(set(_GUID_SYMBOL_RE.findall(combined))):
        if not _symbol_exists_in_tree(guid, edk2_checkout, hbfaplus_root):
            fabricated.append(f"GUID/protocol symbol '{guid}'")

    for entry_point in sorted(set(_ENTRY_POINT_SYMBOL_RE.findall(combined))):
        # Skip ones the harness defines itself in this same file — only
        # flag references to something claimed to exist elsewhere. Matches
        # both EDK2's strict multi-line style (name alone on its own line)
        # and a single-line definition, as long as there's a function body
        # (identifier, parens, then an opening brace) rather than just a
        # bare reference to the name as a value.
        local_def_re = re.compile(
            rf"\b{re.escape(entry_point)}\s*\([^;{{}}]*\)\s*\{{", re.DOTALL)
        if local_def_re.search(files.get("c", "")):
            continue
        if not _symbol_exists_in_tree(entry_point, edk2_checkout, hbfaplus_root):
            fabricated.append(f"entry-point symbol '{entry_point}'")

    if fabricated:
        raise ValueError(
            "Generated harness references symbol(s) that don't exist "
            "anywhere in the real edk2/HBFAplus source, and are not "
            f"defined locally in the harness itself: {'; '.join(fabricated)}. "
            "These look like plausible-sounding but fabricated protocol/"
            "entry-point names rather than real API. Use the actual real "
            "protocol/function this module exposes — check the module's "
            "own header/source for the correct symbol name, or call the "
            "vulnerable function directly rather than inventing an "
            "intermediary protocol."
        )


def check_targets_correct_module(files: Dict[str, str], target: dict) -> None:
    """Raise ValueError if the generated harness doesn't appear to actually
    be about the target module at all.

    This exists because smaller/local LLMs are more prone than GPT-4/5-class
    models to a specific failure mode: given a detailed real sibling harness
    as a structural few-shot example, they sometimes reproduce that sibling
    almost verbatim for its *own* module instead of adapting it to the
    actual target. That produces a harness that may well build and even
    "work" — it's just testing the wrong thing entirely, and every one of
    those wastes a full build+fuzz cycle before the mismatch becomes
    apparent. This check is a cheap, immediate way to catch it: the target
    module's name should appear *somewhere* in the candidate (module
    library class, a comment, the changed file path, etc.) — if it doesn't
    appear anywhere at all, the harness is almost certainly for the wrong
    module.
    """
    module = target.get("module", "")
    if not module:
        return  # nothing to check against
    combined = files.get("inf", "") + "\n" + files.get("c", "")
    if module not in combined:
        raise ValueError(
            f"Generated harness never mentions the target module "
            f"'{module}' anywhere in its INF or C source — it looks like "
            f"it was copied from an unrelated sibling example instead of "
            f"being adapted for the actual target. The harness must "
            f"directly exercise '{module}', not a different module."
        )


def build_system_prompt(target: dict) -> str:
    """Direct port of PoCGen's system.hbs: 'You are a security researcher
    specialized in exploiting {{vulnerabilityType.label}} vulnerabilities
    in npm packages.' We don't have their vulnerability-type classification
    step, so the closest faithful substitute is the target module/package
    itself — still a persona tied to the actual target, not a generic role."""
    module = target.get("module", "the target module")
    package = target.get("package", "")
    where = f"{module} ({package})" if package else module
    return (f"You are a security researcher specialized in building fuzz "
            f"harnesses for {where}, part of the EDK2 UEFI firmware "
            f"codebase.")


def generate(advisory: dict, target: dict, out_dir: str,
             edk2_checkout: Optional[str] = None,
             pre_fix_commit: Optional[str] = None,
             sibling_dir: Optional[str] = None,
             extra_context: str = "",
             codeql_db_path: Optional[str] = None,
             fix_commit: Optional[str] = None,
             force_condensed: bool = False) -> Dict[str, str]:
    prompt = build_prompt(advisory, target, edk2_checkout, pre_fix_commit,
                           sibling_dir, extra_context, codeql_db_path, fix_commit,
                           force_condensed)
    response = call_llm(prompt, system_prompt=build_system_prompt(target))
    files = parse_response(response)
    check_targets_correct_module(files, target)
    check_harness_implements_contract(files)
    check_symbols_exist(files, edk2_checkout, HBFAPLUS_ROOT)
    return write_candidate(files, out_dir)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--advisory-json", required=True)
    parser.add_argument("--target-json", required=True)
    parser.add_argument("--edk2-checkout")
    parser.add_argument("--pre-fix-commit")
    parser.add_argument("--sibling-dir")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--extra-context", default="")
    parser.add_argument("--codeql-db", help="Path to a CodeQL database created by "
                                             "codeql_taint.py create-db, for "
                                             "taint-path-informed prompts")
    parser.add_argument("--fix-commit", help="SHA of the commit that fixed the "
                                              "advisory; enables usage-snippet "
                                              "extraction (diffs against "
                                              "--pre-fix-commit to find the "
                                              "changed line)")
    args = parser.parse_args()

    with open(args.advisory_json) as f:
        advisory = json.load(f)
    with open(args.target_json) as f:
        target = json.load(f)

    result = generate(advisory, target, args.out_dir, args.edk2_checkout,
                       args.pre_fix_commit, args.sibling_dir, args.extra_context,
                       args.codeql_db, args.fix_commit)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
