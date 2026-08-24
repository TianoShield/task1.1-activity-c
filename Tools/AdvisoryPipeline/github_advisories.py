#!/usr/bin/env python3
# @file
#
# Fetches EDK2 security advisories from the GitHub "Security" tab
# (https://github.com/tianocore/edk2/security) and resolves each one to the
# commit(s)/files that fixed it. This is component (i)-report-ingestion of
# the AdvisoryPipeline: it turns an informal advisory into a structured
# "what changed" record that target_mapper.py can map onto an EDK2
# package/module and that harness_generator.py can use as prompt context.
#
# Copyright (c) 2025-2026 TianoShield Contributors.
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
"""
Usage:
    export GITHUB_API_KEY=ghp_xxx   # classic PAT with public_repo scope is enough

    # List all published advisories for tianocore/edk2:
    python3 github_advisories.py list

    # Resolve one advisory to its changed files:
    python3 github_advisories.py resolve GHSA-xxxx-xxxx-xxxx
"""

import argparse
import dataclasses
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, List, Optional

REPO_OWNER = "tianocore"
REPO_NAME = "edk2"
API_ROOT = "https://api.github.com"

_COMMIT_URL_RE = re.compile(
    r"github\.com/tianocore/edk2/commit/([0-9a-fA-F]{7,40})"
)
_PR_URL_RE = re.compile(
    r"github\.com/tianocore/edk2/pull/(\d+)"
)

# For rebase-merged PRs, GitHub's merge_commit_sha points at just the last
# individually-rebased commit -- NOT a synthetic diff of the whole PR.
# Confirmed in production: PR #10628 (11 commits) resolved to a
# merge_commit_sha whose own diff was one docs file, while the real fix
# was nine commits earlier in that same PR. Track which fix_commit came
# from which PR number so resolve() can use /pulls/{n}/files (which
# GitHub aggregates correctly across every commit) instead of trusting
# the single merge-commit's own diff.
_PR_NUMBER_FOR_COMMIT: Dict[str, int] = {}


def resolve_changed_files_for_pr(pr_number: int, token: Optional[str] = None) -> List[str]:
    """Full file list across every commit in a PR, via GitHub's dedicated
    PR-files endpoint -- correct regardless of merge strategy (merge
    commit, squash, or rebase), unlike diffing a single commit SHA."""
    files = _gh_request(f"/repos/{REPO_OWNER}/{REPO_NAME}/pulls/{pr_number}/files", token)
    return [f["filename"] for f in files]



@dataclasses.dataclass
class Advisory:
    ghsa_id: str
    cve_id: Optional[str]
    summary: str
    description: str
    severity: str
    references: List[str]
    affected_packages: List[str]  # package/ecosystem names as reported by GHSA, if any


@dataclasses.dataclass
class ResolvedAdvisory:
    advisory: Advisory
    fix_commit: Optional[str]          # SHA of the commit that fixed it
    pre_fix_commit: Optional[str]      # first parent of fix_commit (vulnerable state)
    changed_files: List[str]           # repo-relative paths touched by the fix


def _gh_request(path: str, token: Optional[str]) -> dict:
    url = path if path.startswith("http") else f"{API_ROOT}{path}"
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            remaining = resp.headers.get("X-RateLimit-Remaining")
            if remaining is not None and int(remaining) < 2:
                reset = int(resp.headers.get("X-RateLimit-Reset", "0"))
                sleep_for = max(0, reset - int(time.time())) + 1
                print(f"[!] Rate limit nearly exhausted, sleeping {sleep_for}s",
                      file=sys.stderr)
                time.sleep(sleep_for)
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"GitHub API error {e.code} for {url}: {body}") from e


def list_advisories(token: Optional[str] = None, state: str = "published") -> List[Advisory]:
    """List all security advisories published for tianocore/edk2.

    Uses GET /repos/{owner}/{repo}/security-advisories, paginating until
    exhausted. Requires `token` for anything beyond a handful of unauthenticated
    requests (GitHub's anonymous rate limit is very low).
    """
    advisories: List[Advisory] = []
    page = 1
    while True:
        path = (f"/repos/{REPO_OWNER}/{REPO_NAME}/security-advisories"
                f"?state={state}&per_page=100&page={page}")
        batch = _gh_request(path, token)
        if not batch:
            break
        for raw in batch:
            advisories.append(_parse_advisory(raw))
        if len(batch) < 100:
            break
        page += 1
    return advisories


def _parse_advisory(raw: dict) -> Advisory:
    cve_id = raw.get("cve_id")
    references = [r for r in raw.get("references", []) if isinstance(r, str)]
    # GHSA "references" sometimes lives at top level, sometimes nested under
    # vulnerabilities[].package or identifiers[]. Be defensive.
    for ident in raw.get("identifiers", []) or []:
        if ident.get("type") == "CVE" and not cve_id:
            cve_id = ident.get("value")
    affected_packages = []
    for vuln in raw.get("vulnerabilities", []) or []:
        pkg = (vuln.get("package") or {}).get("name")
        if pkg:
            affected_packages.append(pkg)
    return Advisory(
        ghsa_id=raw.get("ghsa_id", raw.get("id", "")),
        cve_id=cve_id,
        summary=raw.get("summary", ""),
        description=raw.get("description", "") or "",
        severity=raw.get("severity", "unknown"),
        references=references,
        affected_packages=affected_packages,
    )


def fetch_advisory(ghsa_id: str, token: Optional[str] = None) -> Advisory:
    raw = _gh_request(f"/repos/{REPO_OWNER}/{REPO_NAME}/security-advisories/{ghsa_id}", token)
    return _parse_advisory(raw)



_NON_SOURCE_FILE_RE = re.compile(
    r"(?:^|/)(SecurityFixes\.ya?ml|.*\.md|.*\.txt|.*\.rst)$", re.IGNORECASE
)


def _is_non_source_only(files):
    """True if every file in `files` is docs/metadata, not real source
    (.c/.h/.nasm/.inf/etc.) -- used both to reject a Tier 4 search match
    that only coincidentally mentions the CVE, and to detect a resolved
    commit that's actually just a SecurityFixes.yaml tracking update
    rather than the real code fix."""
    if not files:
        return True
    return all(_NON_SOURCE_FILE_RE.search(f) for f in files)


def _fetch_file_at_commit(path_in_repo, commit, token):
    """Fetch a repo file's raw text content at a specific commit, via the
    GitHub contents API (base64-encoded in the JSON response)."""
    import base64
    raw = _gh_request(
        f"/repos/{REPO_OWNER}/{REPO_NAME}/contents/{path_in_repo}?ref={commit}",
        token,
    )
    content_b64 = raw.get("content", "")
    return base64.b64decode(content_b64).decode("utf-8", errors="replace")


def _parse_security_fixes_yaml(text):
    """Minimal hand-rolled parser for edk2's SecurityFixes.yaml format --
    intentionally not a general YAML parser, just enough structure to pull
    out `files_impacted` and `commit_titles` per CVE entry. Avoids adding
    a PyYAML dependency for a narrow, well-known file shape:

        CVE_2023_45229:
          commit_titles:
            - "..."
            - "..."
          cve: CVE-2023-45229
          files_impacted:
            - NetworkPkg\Dhcp6Dxe\Dhcp6Io.c
    """
    entries = {}
    current_key = None
    current_field = None
    for line in text.splitlines():
        top_level = re.match(r"^([A-Za-z0-9_]+):\s*$", line)
        if top_level:
            current_key = top_level.group(1)
            entries[current_key] = {"commit_titles": [], "files_impacted": [], "cve": None}
            current_field = None
            continue
        if current_key is None:
            continue
        field = re.match(r"^\s{2}([a-z_]+):\s*(.*)$", line)
        if field:
            current_field = field.group(1)
            value = field.group(2).strip()
            if current_field == "cve" and value:
                entries[current_key]["cve"] = value
            continue
        item = re.match(r'^\s{4,}-\s*"?([^"]*)"?\s*$', line)
        if item and current_field in ("commit_titles", "files_impacted"):
            entries[current_key][current_field].append(item.group(1).strip())
    return entries


def _search_commit_by_title(title, token):
    """Like _search_commit, but query on an exact commit-message title
    rather than a bare CVE/GHSA id -- SecurityFixes.yaml's commit_titles
    are distinctive enough (e.g. "SECURITY PATCH CVE-2023-45229 Patch")
    that an exact-phrase search reliably finds the one real fix commit."""
    return _search_commit(title, token)


def _resolve_via_security_fixes_yaml(advisory, yaml_path, tracking_commit, token):
    """Tier 6: the advisory's officially-linked commit turned out to be a
    SecurityFixes.yaml tracking update, not the code fix itself. Parse
    that file for the matching CVE entry and recover the real fix commit
    (via its distinctive commit title) plus the exact files it touches.

    Returns (fix_commit_or_None, files_impacted_list).
    """
    try:
        text = _fetch_file_at_commit(yaml_path, tracking_commit, token)
    except Exception:
        return None, []
    entries = _parse_security_fixes_yaml(text)

    cve_key = (advisory.cve_id or "").replace("-", "_")
    entry = entries.get(cve_key)
    if entry is None:
        # cve field inside each entry is the canonical "CVE-YYYY-NNNNN"
        # form -- fall back to matching on that if the dict key itself
        # doesn't line up (observed key typos/variants in this file).
        for e in entries.values():
            if e.get("cve") == advisory.cve_id:
                entry = e
                break
    if entry is None:
        return None, []

    files_impacted = [f.replace("\\", "/") for f in entry.get("files_impacted", [])]

    for title in entry.get("commit_titles", []):
        sha = _search_commit_by_title(title, token)
        if sha:
            return sha, files_impacted

    # Found the real target files, but couldn't pin down the exact fix
    # commit SHA -- still far more useful than nothing; callers can
    # decide what to do with files-without-a-commit.
    return None, files_impacted


def resolve_fix_commit(advisory: Advisory, token: Optional[str] = None) -> Optional[str]:
    """Find the commit SHA that fixed `advisory`.

    Tries, in order:
      1. A commit URL directly in the structured `references` list.
      2. A merged-PR URL in `references` -> that PR's merge commit.
      3. A commit/PR URL embedded inline in the advisory's free-text
         `description` (common in practice — many GHSA advisories link the
         fix in prose rather than the structured references array, which
         `references` alone misses entirely).
      4. GitHub's Search API, for merged PRs or commits mentioning the CVE
         or GHSA id — for advisories where the fix isn't linked from the
         advisory at all (e.g. filed well after the actual fix landed).

    Returns None if none of these find anything — which, for genuinely
    unfixed/embargoed advisories, is the correct answer, not a failure.
    """
    for ref in advisory.references:
        m = _COMMIT_URL_RE.search(ref)
        if m:
            return m.group(1)
    for ref in advisory.references:
        m = _PR_URL_RE.search(ref)
        if m:
            pr_number = m.group(1)
            pr = _gh_request(f"/repos/{REPO_OWNER}/{REPO_NAME}/pulls/{pr_number}", token)
            if pr.get("merged") and pr.get("merge_commit_sha"):
                _PR_NUMBER_FOR_COMMIT[pr["merge_commit_sha"]] = pr_number
                return pr["merge_commit_sha"]

    # Tier 3: the description body itself, not just the structured
    # references list.
    m = _COMMIT_URL_RE.search(advisory.description)
    if m:
        return m.group(1)
    m = _PR_URL_RE.search(advisory.description)
    if m:
        pr_number = m.group(1)
        pr = _gh_request(f"/repos/{REPO_OWNER}/{REPO_NAME}/pulls/{pr_number}", token)
        if pr.get("merged") and pr.get("merge_commit_sha"):
            _PR_NUMBER_FOR_COMMIT[pr["merge_commit_sha"]] = pr_number
            return pr["merge_commit_sha"]

    # Tier 4: search for merged PRs/commits mentioning the CVE or GHSA id,
    # for advisories that don't link their own fix at all.
    for query_term in filter(None, [advisory.cve_id, advisory.ghsa_id]):
        pr_sha = _search_merged_pr(query_term, token)
        if pr_sha and not _is_non_source_only(resolve_changed_files(pr_sha, token)):
            return pr_sha
        commit_sha = _search_commit(query_term, token)
        if commit_sha and not _is_non_source_only(resolve_changed_files(commit_sha, token)):
            return commit_sha

    # Tier 5: EDK2's own hand-maintained CVE-to-fix wiki page
    # (tianocore/tianocore.github.io wiki, "EDK II CVE information").
    # This is the authoritative project-specific source for exactly this
    # question, and covers advisories the previous four tiers miss
    # entirely — including cases where the fix predates GHSA adoption, or
    # where the CVE was filed well after the actual fix landed.
    if advisory.cve_id:
        wiki_urls = get_wiki_fix_urls(advisory.cve_id, token=token)
        for url in wiki_urls:
            m = _COMMIT_URL_RE.search(url)
            if m:
                return m.group(1)
        for url in wiki_urls:
            m = _PR_URL_RE.search(url)
            if m:
                pr_number = m.group(1)
                pr = _gh_request(f"/repos/{REPO_OWNER}/{REPO_NAME}/pulls/{pr_number}", token)
                if pr.get("merged") and pr.get("merge_commit_sha"):
                    return pr["merge_commit_sha"]

    return None


def _search_merged_pr(query_term: str, token: Optional[str]) -> Optional[str]:
    query = f'repo:{REPO_OWNER}/{REPO_NAME} type:pr is:merged "{query_term}"'
    try:
        result = _gh_request(f"/search/issues?q={urllib.parse.quote(query)}", token)
    except RuntimeError:
        return None
    for item in result.get("items", []):
        pr_number = item.get("number")
        if not pr_number:
            continue
        pr = _gh_request(f"/repos/{REPO_OWNER}/{REPO_NAME}/pulls/{pr_number}", token)
        if pr.get("merged") and pr.get("merge_commit_sha"):
            _PR_NUMBER_FOR_COMMIT[pr["merge_commit_sha"]] = pr_number
            return pr["merge_commit_sha"]
    return None


def _search_commit(query_term: str, token: Optional[str]) -> Optional[str]:
    query = f'repo:{REPO_OWNER}/{REPO_NAME} "{query_term}"'
    try:
        result = _gh_request(f"/search/commits?q={urllib.parse.quote(query)}", token)
    except RuntimeError:
        return None
    items = result.get("items", [])
    return items[0]["sha"] if items else None


def resolve_changed_files(fix_commit: str, token: Optional[str] = None) -> List[str]:
    """List repo-relative file paths touched by `fix_commit`, plus its first
    parent (the "pre-fix" / vulnerable commit)."""
    commit = _gh_request(f"/repos/{REPO_OWNER}/{REPO_NAME}/commits/{fix_commit}", token)
    files = [f["filename"] for f in commit.get("files", [])]
    return files


def get_pre_fix_commit(fix_commit: str, token: Optional[str] = None) -> Optional[str]:
    commit = _gh_request(f"/repos/{REPO_OWNER}/{REPO_NAME}/commits/{fix_commit}", token)
    parents = commit.get("parents", [])
    return parents[0]["sha"] if parents else None


def resolve(advisory: Advisory, token: Optional[str] = None) -> ResolvedAdvisory:
    fix_commit = resolve_fix_commit(advisory, token)
    changed_files: List[str] = []
    pre_fix_commit = None
    if fix_commit:
        if fix_commit in _PR_NUMBER_FOR_COMMIT:
            changed_files = resolve_changed_files_for_pr(_PR_NUMBER_FOR_COMMIT[fix_commit], token)
        else:
            changed_files = resolve_changed_files(fix_commit, token)
        pre_fix_commit = get_pre_fix_commit(fix_commit, token)

        # Tier 6: the resolved commit only touched a SecurityFixes.yaml
        # tracking file, not real source -- that file itself records the
        # actual fix commit's title(s) and the exact files it touches.
        # Recover the real fix commit via commit-title search rather than
        # silently reporting this advisory as having no EDK2 target.
        yaml_files = [f for f in changed_files if f.endswith("SecurityFixes.yaml")]
        if yaml_files and _is_non_source_only(changed_files):
            real_sha, files_impacted = _resolve_via_security_fixes_yaml(
                advisory, yaml_files[0], fix_commit, token
            )
            if real_sha:
                fix_commit = real_sha
                changed_files = resolve_changed_files(fix_commit, token)
                pre_fix_commit = get_pre_fix_commit(fix_commit, token)
            elif files_impacted:
                # No exact commit found, but SecurityFixes.yaml still told
                # us the real vulnerable files -- surface them so this
                # advisory shows up as a real (if build-unverifiable)
                # target instead of no_edk2_files.
                changed_files = files_impacted

    return ResolvedAdvisory(
        advisory=advisory,
        fix_commit=fix_commit,
        pre_fix_commit=pre_fix_commit,
        changed_files=changed_files,
    )


def _token_from_env() -> Optional[str]:
    return os.environ.get("GITHUB_API_KEY") or os.environ.get("GITHUB_TOKEN")


# --- Tier 5: EDK2's own CVE-information wiki page --------------------------
#
# https://github.com/tianocore/tianocore.github.io/wiki/EDK-II-CVE-information
# is a hand-maintained page, one section per CVE, each listing (among other
# things) a "Commit(s) where fixed:" line with links to the actual GitHub
# PR(s)/commit(s). GitHub wikis are themselves git repos, so the most
# robust way to read this is to clone it (once, cached) rather than scrape
# the rendered HTML, which is more likely to shift with GitHub UI changes.
_WIKI_REPO_URL = "https://github.com/tianocore/tianocore.github.io.wiki.git"
_WIKI_CVE_PAGE = "EDK-II-CVE-information.md"
_CVE_HEADER_RE = re.compile(r"^\[?(CVE-\d{4}-\d+)\]?", re.MULTILINE)
_MD_LINK_URL_RE = re.compile(r"\((https?://[^\s)]+)\)")

_wiki_cache: Dict[str, List[str]] = {}
_wiki_cache_loaded = False


def _clone_or_update_wiki_repo(cache_dir: str) -> Optional[str]:
    repo_dir = os.path.join(cache_dir, "tianocore.github.io.wiki")
    try:
        if os.path.isdir(os.path.join(repo_dir, ".git")):
            subprocess.run(["git", "-C", repo_dir, "pull", "--ff-only"],
                            capture_output=True, text=True, timeout=60, check=True)
        else:
            os.makedirs(cache_dir, exist_ok=True)
            subprocess.run(["git", "clone", "--depth", "1", _WIKI_REPO_URL, repo_dir],
                            capture_output=True, text=True, timeout=60, check=True)
        return repo_dir
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"[!] Could not fetch the EDK2 CVE-information wiki (tier 5 fix-commit "
              f"resolution unavailable): {e}", file=sys.stderr)
        return None


def _parse_cve_wiki_markdown(md_text: str) -> Dict[str, List[str]]:
    """Parse the wiki page into {cve_id: [github.com/.../commit/... or
    .../pull/... urls found in that CVE's section]}.

    Sections are separated by a horizontal rule on its own line — the
    actual wiki source uses `***` (not `---`, which is what the web-
    rendered HTML normalizes it to) and CRLF line endings, both of which
    matter for the split regex below.
    """
    normalized = md_text.replace("\r\n", "\n")
    sections = re.split(r"\n(?:-{3,}|\*{3,})\n", normalized)
    result: Dict[str, List[str]] = {}
    for section in sections:
        cve_ids = _CVE_HEADER_RE.findall(section)
        if not cve_ids:
            continue
        # All URLs in the section that point at an edk2 commit or PR —
        # deliberately not restricted to just the "Commit(s) where fixed:"
        # line, since some entries wrap onto multiple lines or list several
        # PRs across a short paragraph.
        urls = [u for u in _MD_LINK_URL_RE.findall(section)
                if "tianocore/edk2/commit/" in u or "tianocore/edk2/pull/" in u]
        for cve_id in cve_ids:
            result.setdefault(cve_id, []).extend(urls)
    return result


def get_wiki_fix_urls(cve_id: str, cache_dir: Optional[str] = None,
                       token: Optional[str] = None) -> List[str]:
    """Return whatever commit/PR URLs the CVE-information wiki lists for
    `cve_id`, or an empty list if the page isn't reachable or has no entry
    for it. Cached in-process (the whole page is parsed once, not once per
    CVE) and on-disk (the wiki clone is reused across pipeline runs)."""
    global _wiki_cache_loaded
    if not _wiki_cache_loaded:
        cache_dir = cache_dir or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), ".wiki_cache")
        repo_dir = _clone_or_update_wiki_repo(cache_dir)
        if repo_dir:
            page_path = os.path.join(repo_dir, _WIKI_CVE_PAGE)
            if os.path.isfile(page_path):
                with open(page_path, "r", encoding="utf-8", errors="replace") as f:
                    _wiki_cache.update(_parse_cve_wiki_markdown(f.read()))
        _wiki_cache_loaded = True
    return _wiki_cache.get(cve_id, [])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="List all published EDK2 security advisories")

    p_resolve = sub.add_parser("resolve", help="Resolve one advisory to changed files")
    p_resolve.add_argument("ghsa_id")

    args = parser.parse_args()
    token = _token_from_env()
    if not token:
        print("[!] No GITHUB_API_KEY/GITHUB_TOKEN set; unauthenticated rate "
              "limits are very low (60 req/hr).", file=sys.stderr)

    if args.cmd == "list":
        advisories = list_advisories(token)
        for adv in advisories:
            print(f"{adv.ghsa_id}\t{adv.cve_id or '-'}\t{adv.severity}\t{adv.summary}")
        print(f"\n[i] {len(advisories)} advisories total", file=sys.stderr)

    elif args.cmd == "resolve":
        advisory = fetch_advisory(args.ghsa_id, token)
        resolved = resolve(advisory, token)
        print(json.dumps(dataclasses.asdict(resolved), indent=2))


if __name__ == "__main__":
    main()
