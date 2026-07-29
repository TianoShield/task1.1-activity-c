# AdvisoryPipeline

Automatically generates HBFAplus fuzz harnesses for **published, already-fixed**
EDK2 security advisories (https://github.com/tianocore/edk2/security), so
each disclosed vulnerability gets a regression-test harness that:

1. reproduces the crash against the **pre-fix** revision, and
2. confirms the crash is **gone** against the **post-fix** revision.

The design directly mirrors the four-component architecture of
[PoCGen](https://doi.org/10.1145/3808178) (generating PoC exploits for npm
vulnerabilities from informal reports), with EDK2/C/AFL++ primitives
standing in for npm/JS/CodeQL ones:

| PoCGen component | This pipeline | File |
|---|---|---|
| Vulnerability report ingestion | Fetch + resolve GHSA advisory → fix commit → changed files | `github_advisories.py` |
| Taint path / vulnerable function | Map changed files → EDK2 package/module, pick harness depth (`fuzz-harness` skill's L1/L1L2/L3/Deep taxonomy), check existing coverage | `target_mapper.py` |
| Taint path extraction (CodeQL) | Same tool PoCGen used, ported to C: CodeQL C/C++ database + built-in security suite, filtered to the advisory's changed files | `codeql_taint.py` |
| **Usage snippet extraction + LLM summarization (§2.2.4)** | **Locate the function enclosing the fix commit's diff (EDK2's column-0-brace convention), pull its doxygen header, grep the edk2 tree for real call sites, LLM-summarize into concrete parameter/invocation guidance** | **`usage_snippets.py`** |
| Candidate exploit generation (LLM) | Candidate harness generation (LLM), prompted with the advisory, CodeQL taint path or raw source, the usage-snippet summary, project skill docs, and a sibling harness template | `harness_generator.py` |
| Exploit validation | Build against pre-fix/post-fix EDK2 checkouts; short AFL++/ASan run; crash pre-fix + no crash post-fix = mechanically valid | `validator.py` |
| **LLM sanity check (§2.4.6)** | **Gates the `confirmed` verdict: an LLM reviews the harness source + ASan output against the advisory text, to catch mechanically-valid-but-wrong-bug false positives before accepting a result. Runs once per advisory (on the success path), not per attempt — same as PoCGen** | **`sanity_check.py`** |
| Prompt refiners / refinement loop | Priority-queue retry loop (PoCGen Fig. 7); a failed sanity check is fed back in as a refinement signal like any other, not a silent discard | `refiner.py` |
| — | Orchestrates all of the above; `scan` (read-only survey) and `run` (full pipeline) | `pipeline.py` |

### Honest gaps vs. PoCGen's full LLM usage

PoCGen actually uses an LLM in six places (paper §2.2–§2.4.6): vulnerability-type
classification, vulnerable-function ranking, a CodeQL-taint-fallback ("guess
the sinks"), usage-snippet summarization, exploit generation, and the
final sanity check. This pipeline now covers five of those six — usage
snippets, the sanity check, and the CodeQL-fallback sink-guessing close the
three gaps flagged earlier. Still missing:

- **Vulnerable-function ranking (§2.2.2)**: `target_mapper.py`'s
  suffix-based module detection is a deterministic heuristic, not an LLM
  judgment call the way PoCGen ranks candidate functions. When a fix
  commit touches multiple functions, there's no ranking of which one is
  "the" vulnerable one — `usage_snippets.py` and `codeql_taint.py`'s tier 3
  both just anchor on the first changed file's first diff hunk.

### On the CodeQL component specifically

PoCGen's own ablation study (Table 1 in the paper) found taint-path context
was the single biggest contributor to success rate — removing it dropped
71%→21%. `codeql_taint.py` is the C port of that idea, and it now mirrors
PoCGen's own **three-tier fallback chain** (paper §2.2.3), not just the
first tier:

| Tier | What it does | When it's used |
|---|---|---|
| 1. Built-in suite | CodeQL's `cpp-security-and-quality.qls` (buffer overflow, UAF, integer overflow, etc.), filtered to the advisory's changed files | Always tried first, if a database is available |
| 2. Extended custom query | A looser, hand-written `TaintTracking` query (parameters → `CopyMem`/`memcpy`-family/`AllocatePool` sizing) — the direct analog of PoCGen's own "extended taint analysis" retry when the high-precision built-in suite finds nothing | If tier 1 finds nothing for the changed files |
| 3. LLM-guessed sinks | Show the LLM the changed source, ask it to name specific risky lines | If tiers 1 and 2 both find nothing, or no database exists at all (e.g. CodeQL isn't installed) |

**This is now automatic** — you no longer need to run `codeql_taint.py
create-db` yourself before a `pipeline.py run`. `refiner.py` auto-builds
(and caches) one CodeQL database per `(package, module, revision)` under
`HBFAplus/output/codeql_dbs/` the first time it's needed, and reuses it
across every refinement attempt for that advisory and across future
advisories that touch the same module/revision. If the build fails (no
CodeQL CLI, BaseTools issue, etc.) it logs a warning and falls straight to
tier 3 — CodeQL involvement strengthens the prompt when available, it
never blocks the pipeline when it isn't.

```sh
# Default: auto-builds/caches a database as needed, tries all 3 tiers
python3 pipeline.py run --edk2-checkout /workspace/edk2-upstream \
    --seed-dir HBFAplus/Seed/_default/Raw --advisory GHSA-xxxx-xxxx-xxxx

# Force a specific pre-built database instead
python3 pipeline.py run --edk2-checkout /workspace/edk2-upstream \
    --seed-dir HBFAplus/Seed/_default/Raw --advisory GHSA-xxxx-xxxx-xxxx \
    --codeql-db /tmp/codeql-dhcp6dxe

# Skip CodeQL entirely (tiers 1+2), go straight to LLM-guessed sinks —
# useful with no CodeQL CLI installed, or for a fast trial run
python3 pipeline.py run --edk2-checkout /workspace/edk2-upstream \
    --seed-dir HBFAplus/Seed/_default/Raw --advisory GHSA-xxxx-xxxx-xxxx \
    --no-codeql
```

One honest difference from PoCGen worth calling out: PoCGen's CodeQL usage
(tier 1) targeted JS-specific vulnerability classes (path traversal,
command/code injection, prototype pollution, ReDoS) with hand-picked
sources/sinks matched to each class. There's no equally clean C analog for
most of those classes, so tier 1 here leans on CodeQL's **general-purpose**
`cpp-security-and-quality` suite instead — the same suite CodeQL's own
GitHub code scanning uses, but less precisely targeted than PoCGen's
per-vulnerability-type queries were. Tier 2's custom query is a reasonable
attempt at narrowing that gap for common EDK2 memory-unsafety patterns
specifically, but — same caveat as before — it hasn't been run against a
real CodeQL installation in this environment (no CodeQL CLI here); treat it
as a starting point to validate against your actual CodeQL version.

## Why this is a regression-testing tool, not an exploit generator

Every advisory this pipeline touches is **already public and already
patched** by the time it appears in `tianocore/edk2`'s security tab. The
harness's entire value is in proving the *old* code was reachable and the
*new* code isn't — the same purpose HBFAplus's existing hand-written
harnesses serve, and the same purpose PoCGen's authors describe in their
paper's Ethical Considerations section: PoC generation for disclosed,
already-patched issues speeds up regression testing and helps downstream
consumers verify they're no longer exposed. This pipeline does not target
unpatched/undisclosed advisories, and `github_advisories.py` only lists
`state=published` advisories for that reason.

## Docker

There are **two** ways to run this from the host, and they matter for
different reasons — this mirrors PoCGen's own setup (`run-mnt.sh` +
`.env`), not just superficially:

### `run-mnt.sh` — disposable, unprivileged (use this for anything that builds/fuzzes)

This is the direct equivalent of PoCGen's `run-mnt.sh`: a fresh `--rm`
container per invocation, secrets via `.env`, and — the part that actually
matters — **no `--privileged`, no `NET_ADMIN`/`SYS_ADMIN`, no host
networking**. PoCGen's dynamic analysis runs untrusted, LLM-generated code
(the candidate exploit) inside exactly this kind of narrowly-scoped,
throwaway container; `harness_generator.py`/`validator.py`/`refiner.py`
compile and actively fuzz untrusted, LLM-generated **C** code, which is the
same category of thing and deserves the same treatment. The long-lived
`hbfa-dev` service (used by `run.sh`/`build.sh`/`docker_run.sh`) is
`--privileged` with `NET_ADMIN`/`SYS_ADMIN` and `network_mode: host`,
because HBFAplus also supports QEMU/TAP-based tests elsewhere — none of
which the AdvisoryPipeline needs. Handing that same privilege level to a
loop that compiles and fuzzes LLM-written code is a larger blast radius
than the task requires, so `run-mnt.sh` deliberately doesn't ask for it.

```sh
# from the repo root
echo "GITHUB_API_KEY=ghp_xxx"      >> .env
echo "OPENAI_API_KEY=ollama"       >> .env
echo "OPENAI_BASE_URL=http://host.docker.internal:11434/v1" >> .env
echo "HBFA_LLM_MODEL=llama3.1"     >> .env

./HBFAplus/Tools/AdvisoryPipeline/run-mnt.sh output \
    pipeline.py run --edk2-checkout /home/builder/hbfa_workspace/edk2-upstream \
                     --seed-dir HBFAplus/Seed/_default/Raw \
                     --advisory GHSA-xxxx-xxxx-xxxx \
                     --out-dir-base /output
```

Note `--edk2-checkout` here is already a **container-side** path (unlike
`docker_run.sh`, `run-mnt.sh` doesn't rewrite it for you — it's a thinner
script, closer to PoCGen's original). Since the whole repo root is mounted
at `/home/builder/hbfa_workspace`, an `edk2-upstream/` clone placed there
shows up at that same path inside the container.

One honest divergence from PoCGen worth knowing about: PoCGen mounts its
source **read-only** (`-v .:/app:ro`) because its dynamic analysis only
ever needs to write to `/output`. HBFAplus's build system doesn't have that
luxury — `AFLplusplus/afl-fuzz`, `edk2/BaseTools/Source/C/bin/*`, and
`Build/` all get written back into the workspace tree itself, and that's
*intentional* (it's how `init_hbfa_env.sh` avoids rebuilding AFL++/BaseTools
on every single container start). So `run-mnt.sh` mounts the repo
read-write. If that read-write blast radius bothers you more than the
privilege/networking one, the fix is the same shape `validator.py` already
uses for the `edk2` checkout itself: point the whole run at a disposable
`git worktree` / copy instead of your primary checkout, rather than trying
to make the mount read-only.

### `docker_run.sh` — the long-lived dev container (use this for everything else)

Read-only operations that don't compile or execute anything untrusted —
`scan` (pure GitHub API calls), or just poking around — are fine through
the existing `hbfa-dev` service, the same way you'd use `./run.sh`
interactively:

```sh
./HBFAplus/Tools/AdvisoryPipeline/docker_run.sh scan --out scan_report.json
```

It brings up `hbfa-dev` via `docker compose up -d` if it isn't already
running, forwards whichever of `GITHUB_API_KEY` / `OPENAI_API_KEY` /
`OPENAI_BASE_URL` / `HBFA_LLM_MODEL` are set on your host into the
container, and rewrites `--edk2-checkout` from a host path to its
container-side equivalent automatically (both `--edk2-checkout <path>` and
`--edk2-checkout=<path>` forms) — it hard-fails with a clear message if the
path resolves outside the repo root rather than silently pointing at
nothing.

**Recommendation:** `scan` via `docker_run.sh` (or even just locally if you
have `GITHUB_API_KEY` set — it makes zero build/fuzz calls), `run` via
`run-mnt.sh`.

If you're already inside a container shell (via `./run.sh` or the VS Code
Dev Container), skip both wrappers and just call `python3 pipeline.py ...`
directly — same as any other script in `HBFAplus/Tools/`.

## Setup

Same `.env`-style variables as the rest of this repo's tooling, plus a
model name:

```sh
export GITHUB_API_KEY=ghp_xxx      # classic PAT, public_repo scope is enough
export OPENAI_API_KEY=ollama       # or a real OpenAI key
export OPENAI_BASE_URL=http://localhost:11434/v1   # omit for api.openai.com
export HBFA_LLM_MODEL=llama3.1     # must match a model your endpoint serves
```

You'll also need a local `edk2` clone with enough history to reach both a
fix commit and its parent for whichever advisories you're targeting. The
`edk2/` submodule pinned in this repo tracks a fork/branch
(`TianoShield/edk2@hbfaplusplus`); for advisory resolution you generally
want a clone of **upstream** `tianocore/edk2` instead, since that's where
the fix commits referenced by GHSA advisories actually live:

```sh
git clone https://github.com/tianocore/edk2.git /workspace/edk2-upstream
```

Pass that path as `--edk2-checkout`.

## Usage

**Step 1 — dry-run scan (always do this first).** Read-only; only hits the
GitHub API, no LLM calls, no builds:

```sh
python3 pipeline.py scan --out scan_report.json
```

This tells you, per advisory: whether a fix commit could be resolved, which
package/module it maps to, what harness depth is suggested, and whether
HBFAplus already has a harness there (`action: "already_covered"`) or needs
one generated (`action: "generate"`). Inspect this before spending LLM/build
budget — it's normal for a chunk of advisories to land in
`no_edk2_files` (e.g. advisories that only touched CI config or docs) or
`unresolvable` (no commit/PR linked in the advisory yet).

**Step 2 — run the pipeline**, starting with a `--limit` while you dial in
seed corpora and fuzz duration for your environment (a from-scratch EDK2
build is not fast; budget accordingly):

```sh
python3 pipeline.py run \
    --edk2-checkout /workspace/edk2-upstream \
    --seed-dir HBFAplus/Seed/_default/Raw \
    --limit 3 \
    --fuzz-duration 180
```

Once you're happy with the results, drop `--limit` to process every
`generate`-flagged advisory from the scan.

**Single advisory** (e.g. to retry one, or to work an advisory the scan
step didn't cover automatically):

```sh
python3 pipeline.py run \
    --edk2-checkout /workspace/edk2-upstream \
    --seed-dir HBFAplus/Seed/_default/Raw \
    --advisory GHSA-xxxx-xxxx-xxxx
```

Output lands under `output/AdvisoryPipeline/<GHSA-id>/<Package>_<Module>/`,
with one `attempt_N/` per refinement attempt and a top-level
`run_report.json` summarizing verdicts across the whole run.

## Verdicts

| Verdict | Meaning |
|---|---|
| `confirmed` | Harness reproduces pre-fix, doesn't post-fix. Ready to commit as a regression test / seed for `HBFAplus/POC/`. |
| `no_repro` | Built fine, never crashed in the time budget — likely not reaching the changed lines. Refiner will retry with reachability feedback; if still `exhausted`, consider a deeper harness level manually (see the `fuzz-harness` / `deep-stack-harness` skills). |
| `build_failed` | Candidate harness doesn't compile against this EDK2 revision. |
| `not_regression_tested` | Reproduced pre-fix, but either the post-fix build failed, or the same input still crashes post-fix (harness may be hitting an unrelated bug — worth a manual look; could also be a genuinely unfixed variant, which is itself a useful finding). |
| `unresolvable` / `no_edk2_files` | Nothing for the generator to act on (no linked fix commit, or the fix touched no recognizable package/module path). |

## Known limitations / next steps

- `target_mapper.py`'s package→module heuristic assumes standard EDK2
  driver-naming suffixes (`Dxe`, `Smm`, `Pei`, `Lib`, `Driver`, `Runtime`);
  unusual module names may need a manual override.
- The refinement loop budget (`MAX_ATTEMPTS = 10`) is much smaller than
  PoCGen's 30, because a UEFI build+fuzz cycle costs minutes, not seconds —
  tune `--fuzz-duration` and the attempt cap to your available compute.
- `validator.py` uses `git worktree` against a single local `edk2` clone;
  running multiple advisories concurrently against the same checkout will
  race on worktree names — parallelize by giving each advisory its own
  `--edk2-checkout` clone (or a `git clone --shared` per worker) if you want
  concurrency.
