# TianoPoC

An automated pipeline that turns a GitHub Security Advisory into a build-tested, crash-verified proof-of-concept fuzz harness for TianoCore EDK II, combining an LLM, EDK2's real build system, and AFL++.

## Credit

TianoPoC is built as an add-on to [HBFAplus](https://github.com/TianoShield/HBFAplusplus), a modernized fork of Intel's Host-based Firmware Analysis (HBFA) framework, originally released in the white-paper ["Using Host-based Firmware Analysis to Improve Platform Resiliency"](https://www.intel.com/content/dam/develop/external/us/en/documents/intel-usinghbfatoimproveplatformresiliency-820238.pdf). All credit for the underlying fuzzing framework, host libraries, and mock protocol infrastructure belongs to the HBFAplus project and its contributors.

This repository contains only TianoPoC's own contribution: the `Tools/AdvisoryPipeline` component and a small set of infrastructure fixes it needed. It's meant to be placed inside a working HBFAplus checkout, not used standalone.

## PoC Generation Pipeline (`Tools/AdvisoryPipeline`)

The pipeline turns a GitHub Security Advisory into a build-tested, crash-verified regression harness. The methodology is inspired by [PoCGen](https://doi.org/10.1145/3808178) (Simsek, Eghbali, Pradel; FSE 2026), adapted from npm/JavaScript vulnerabilities to UEFI/C firmware code.

### How it works

1. **Scan**: queries GitHub's Security Advisories API for the target repo (e.g. `tianocore/edk2`), resolves each advisory's official fix (with a multi-tier fallback: structured references, PR links, in-text commit/PR mentions, commit-message search, and the project's own `SecurityFixes.yaml`/CVE wiki), maps the changed files to EDK2 packages/modules, and checks whether an existing harness already covers each one.
2. **Generate**: for advisories without existing coverage, prompts an LLM with the advisory description, the vulnerable source at the pre-fix commit, and (when available) a real sibling harness as a structural template, producing a candidate `.c`/`.inf` harness pair.
3. **Structural gates**: before ever touching a compiler, the generated harness is checked for two things, that it actually defines the four required entry points (`InitializeHarness`, `RunTestHarness`, `CleanupHarness`, `GetMaxBufferSize`), and that it genuinely references the target module rather than something unrelated.
4. **Build**: places the harness in the real package tree, registers it in the platform DSC, and compiles it with EDK2's build system using the `AFL` (afl-clang-fast) toolchain profile.
5. **Refine on failure**: if a structural gate or the build itself fails, that exact error is fed back to the LLM for another attempt, matching PoCGen's own refinement-loop design.
6. **Find a crash**: once a harness builds, the LLM proposes one specific candidate input first (PoCGen-style direct guessing). If that misses, AFL++ fuzzes as a fallback safety net (disable with `--pocgen-mode` to test the LLM-only approach in isolation).
7. **Verify the regression**: the same harness is rebuilt against the advisory's official fix commit, and the exact crashing input is replayed. A genuine fix must make the crash disappear.
8. **Sanity check**: a final LLM pass compares the crash output against the advisory's description to filter out crashes that pass the mechanical checks for the wrong reason.

Any failure in steps 3 through 7 loops back to step 2 with that specific failure fed back as feedback, up to `--max-attempts` tries.

### Requirements

TianoPoC assumes a working HBFAplus checkout is already set up and buildable (Docker or local, per [HBFAplus's own setup instructions](https://github.com/TianoShield/HBFAplusplus)). To use TianoPoC:

```bash
# Inside a working HBFAplus checkout:
cp -r Tools/AdvisoryPipeline /path/to/HBFAplus/Tools/
```

Required environment:

```bash
export GITHUB_API_KEY=...
export OPENAI_API_KEY=...       # or "ollama" for a local model
export OPENAI_BASE_URL=...      # e.g. http://localhost:11434/v1
export HBFA_LLM_MODEL=...
```

### Usage

```bash
# Read-only scan of the whole security tab, no LLM calls, no builds
python3 HBFAplus/Tools/AdvisoryPipeline/pipeline.py scan

# Full run for one advisory
python3 HBFAplus/Tools/AdvisoryPipeline/pipeline.py run \
    --edk2-checkout /path/to/edk2 \
    --seed-dir HBFAplus/Seed/_default/Raw \
    --advisory GHSA-xxxx-xxxx-xxxx

# Full run for every advisory the scan step marks actionable
python3 HBFAplus/Tools/AdvisoryPipeline/pipeline.py run \
    --edk2-checkout /path/to/edk2 \
    --seed-dir HBFAplus/Seed/_default/Raw
```

Key flags:

| Flag | Effect |
|---|---|
| `--max-attempts N` | Cap the refinement loop's retry budget per target (default 10) |
| `--pocgen-mode` | Disable the AFL++ fallback, pure LLM-guess-and-refine, no blind fuzzing |
| `--no-codeql` | Skip CodeQL taint-path analysis (faster, less prompt context) |
| `--limit N` | Cap how many advisories to process in one run |

### Pipeline components

| File | Role |
|---|---|
| `pipeline.py` | Top-level CLI orchestrating everything below (`scan` / `run` / `best-effort`) |
| `github_advisories.py` | Fetches and resolves advisories from the GitHub Security Advisories API, with a multi-tier fix-commit resolver |
| `target_mapper.py` | Maps changed files to EDK2 packages/modules, finds sibling examples |
| `harness_generator.py` | Builds the LLM prompt, parses the response, and runs the structural gates |
| `refiner.py` | Runs the generate, build, and feedback refinement loop |
| `validator.py` | Deterministic build/fuzz/replay verification, no LLM calls of its own |
| `sanity_check.py` | Final LLM pass confirming a crash genuinely matches the advisory |
| `poc_guesser.py` | LLM-proposed direct input guessing (PoCGen-style, tried before AFL++) |
| `usage_snippets.py` | Extracts real call-site examples of the vulnerable function for the LLM prompt |
| `codeql_taint.py` | Optional CodeQL taint-path analysis for extra prompt context |
| `best_effort.py` | Fast, unvalidated single-shot generation and guess, no build, no execution |
| `poc_packager.py` | Packages a confirmed PoC and its inputs for handoff |


### Current status

An earlier evaluation pass used `llama3.1:8b`, which failed even more consistently. Most attempts were rejected at the structural gates before ever reaching a build. Switching to `qwen2.5-coder:7b` (a model specifically tuned for code generation) got noticeably further: it more reliably passes the structural gates and reaches real compiler errors more often than gate rejections, though it has not yet produced a confirmed PoC either. Model specialization for code generation appears to matter more than raw parameter count for this task.

The pipeline's full infrastructure, advisory resolution, target mapping, harness placement, DSC registration, build, fuzz, post-fix replay, and sanity checking, works correctly end-to-end, validated against the complete real `tianocore/edk2` security advisory set (13 advisories). Using `qwen2.5-coder:7b`, the pipeline has not yet produced a confirmed PoC. The two most common failure modes:

- **Structural gate rejection** (about 45% of attempts): most often the generated harness omits one or more of the four required entry-point functions, typically right after correcting an unrelated build error, suggesting the model loses track of one requirement while fixing another.
- **Genuine build errors** (about 20% of attempts): most commonly missing `#include` directives for standard EDK2/UEFI headers, even when a correct, complete sibling harness with proper includes is shown directly in the prompt.

Results are expected to improve with a stronger model. `HBFA_LLM_MODEL` is a plain environment variable, so swapping models requires no code changes.


## License

This project is licensed under the terms of the LICENSE file included in this repository.

## Acknowledgments

This material is based upon work supported by the U.S. National Science Foundation (NSF) under Grant No. 2534021. In preparing this work, generative AI models and tools, including GPT and Claude models, were used to assist with generating and revising content, including code and text.
