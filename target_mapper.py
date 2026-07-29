#!/usr/bin/env python3
# @file
#
# Maps a resolved advisory's changed files onto an EDK2 Package/Module,
# decides which HBFAplus harness depth (L1 / L1L2 / L3 / Full, see the
# fuzz-harness skill) is appropriate, and reports whether HBFAplus already
# has coverage for that module. This is component (i)-part-2: turning
# "these files changed" into "this is the vulnerable function / module,
# and here is how deep a harness needs to go".
#
# Copyright (c) 2025-2026 TianoShield Contributors.
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
import dataclasses
import os
import re
import sys
from typing import Dict, List, Optional, Set

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "Scripts"))
try:
    from gen_driver_registry import KNOWN_DEPENDENCIES  # type: ignore
except ImportError:
    # Fallback copy kept in sync with gen_driver_registry.py's table; used only
    # if the Scripts/ import path changes.
    KNOWN_DEPENDENCIES: Dict[str, List[str]] = {
        "Ip4Dxe": ["MnpDxe", "ArpDxe"],
        "Udp4Dxe": ["Ip4Dxe"],
        "Dhcp4Dxe": ["Udp4Dxe"],
        "Dns4Dxe": ["Udp4Dxe"],
        "Mtftp4Dxe": ["Udp4Dxe"],
        "Ip6Dxe": ["MnpDxe"],
        "Udp6Dxe": ["Ip6Dxe"],
        "Dhcp6Dxe": ["Udp6Dxe"],
        "Dns6Dxe": ["Udp6Dxe"],
        "Mtftp6Dxe": ["Udp6Dxe"],
        "TcpDxe": ["Ip4Dxe", "Ip6Dxe"],
        "HttpDxe": ["TcpDxe"],
        "TlsDxe": ["TcpDxe"],
    }

HBFAPLUS_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
FUZZ_HARNESS_ROOT = os.path.join(HBFAPLUS_ROOT, "FuzzHarness")
MOCK_PROTOCOLS_ROOT = os.path.join(HBFAPLUS_ROOT, "MockProtocols")

# EDK2 top-level packages we know how to reason about. Advisories touching
# packages outside this list still get mapped, just with `known_stack=False`
# so the harness generator knows it can't reuse KNOWN_DEPENDENCIES.
_PACKAGE_RE = re.compile(r"^(?P<package>[A-Za-z0-9]+Pkg)/")
# UEFI module/driver naming conventions: DXE drivers, SMM drivers, PEI
# modules, and libraries almost always end in one of these suffixes,
# regardless of how many grouping subdirectories (Universal/, Disk/, Bus/...)
# sit above them in the package tree.
_MODULE_SUFFIX_RE = re.compile(r".*(Dxe|Smm|Pei|Lib|Driver|Runtime)$")


@dataclasses.dataclass
class Target:
    package: str                  # e.g. "NetworkPkg"
    module: str                   # e.g. "Dhcp6Dxe"
    changed_source_files: List[str]
    known_stack: bool             # True if `module` is in KNOWN_DEPENDENCIES
    dependency_chain: List[str]   # real drivers below `module`, bottom-most first
    suggested_depth: str          # "L1" | "L1L2Deep" | "L3Deep" | "Deep"
    existing_harnesses: List[str]  # relative paths under FuzzHarness/ that already exist
    has_coverage: bool


def _extract_package_and_module(path: str):
    pkg_m = _PACKAGE_RE.match(path)
    if not pkg_m:
        return None
    package = pkg_m.group("package")
    parts = path.split("/")[1:-1]  # directory components between package and filename
    if not parts:
        return None
    # Prefer the deepest component that looks like a driver/module name;
    # this correctly resolves nested paths like
    # MdeModulePkg/Universal/Disk/DiskIoDxe/DiskIo.c -> module "DiskIoDxe",
    # not the grouping directory "Universal".
    for part in reversed(parts):
        if _MODULE_SUFFIX_RE.match(part):
            return (package, part)
    # No conventional suffix matched (e.g. an Include/ or Library/ header-only
    # change) — fall back to the directory immediately under the package,
    # which is the best available guess.
    return (package, parts[0])


def map_files_to_targets(changed_files: List[str]) -> List[Target]:
    """Group changed files by (Package, Module) and build a Target per group."""
    by_module: Dict[tuple, List[str]] = {}
    for path in changed_files:
        key = _extract_package_and_module(path)
        if not key:
            continue  # e.g. changes to .github/, docs/, BaseTools/ — not a driver
        by_module.setdefault(key, []).append(path)

    targets = []
    for (package, module), files in by_module.items():
        targets.append(_build_target(package, module, files))
    return targets


def _build_target(package: str, module: str, files: List[str]) -> Target:
    known_stack = module in KNOWN_DEPENDENCIES
    dependency_chain = _expand_chain(module) if known_stack else []
    depth = _suggest_depth(module, dependency_chain)
    existing = _find_existing_harnesses(package, module)
    return Target(
        package=package,
        module=module,
        changed_source_files=files,
        known_stack=known_stack,
        dependency_chain=dependency_chain,
        suggested_depth=depth,
        existing_harnesses=existing,
        has_coverage=len(existing) > 0,
    )


def _expand_chain(module: str, _seen: Optional[Set[str]] = None) -> List[str]:
    """Return the full list of real drivers below `module`, bottom-most first,
    e.g. Dhcp6Dxe -> [MnpDxe, Ip6Dxe, Udp6Dxe]."""
    _seen = _seen or set()
    if module in _seen:
        return []
    _seen.add(module)
    chain: List[str] = []
    for dep in KNOWN_DEPENDENCIES.get(module, []):
        chain.extend(d for d in _expand_chain(dep, _seen) if d not in chain)
        if dep not in chain:
            chain.append(dep)
    return chain


def _suggest_depth(module: str, dependency_chain: List[str]) -> str:
    """Mirror the fuzz-harness skill's depth taxonomy.

    Security advisories are exactly the case the skill calls out for "Full
    Deep": we don't know a priori whether the bug is a single-driver logic
    bug or a cross-layer interaction bug, and the whole point is finding out.
    Default to the module's existing L1 if one is already present (fast,
    cheap regression check); otherwise default one level short of full depth
    so the first attempt is still reasonably fast, and let the refinement
    loop escalate to Deep if L1 fails to reach the changed lines.
    """
    if not dependency_chain:
        return "L1"
    if len(dependency_chain) <= 2:
        return "L1L2Deep"
    return "L3Deep"


def _find_existing_harnesses(package: str, module: str) -> List[str]:
    """FuzzHarness/ mirrors EDK2's own (possibly deeply nested) package
    layout, so `module` may live several directories below `package`
    (e.g. MdeModulePkg/Universal/Disk/DiskIoDxe). Search recursively for a
    directory named exactly `module` rather than assuming it's a direct
    child."""
    package_dir = os.path.join(FUZZ_HARNESS_ROOT, package)
    if not os.path.isdir(package_dir):
        return []
    found = []
    for root, dirs, files in os.walk(package_dir):
        if os.path.basename(root) == module:
            # `root` is the module dir itself; the actual harness INF/C files
            # live one level deeper, in TestXxxDriver{,L1L2Deep,Deep,...}/.
            for sub_root, _sub_dirs, sub_files in os.walk(root):
                for f in sub_files:
                    if f.endswith(".inf"):
                        found.append(
                            os.path.relpath(os.path.join(sub_root, f), FUZZ_HARNESS_ROOT)
                        )
    return sorted(found)


def find_sibling_examples(package: str, module: str, limit: int = 2) -> List[str]:
    """Find harness INF/C files for *other* modules in the same package, to
    use as few-shot examples when the target module has zero existing
    coverage (analogous to PoCGen's BM25-retrieved `similarExploits`)."""
    package_dir = os.path.join(FUZZ_HARNESS_ROOT, package)
    if not os.path.isdir(package_dir):
        # Fall back to any package — better a mismatched real example than none.
        package_dir = FUZZ_HARNESS_ROOT
    examples = []
    for entry in sorted(os.listdir(package_dir)):
        if entry == module:
            continue
        full = os.path.join(package_dir, entry)
        if os.path.isdir(full):
            examples.append(full)
        if len(examples) >= limit:
            break
    return examples


def main():
    import argparse
    import json

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("changed_files", nargs="+",
                         help="Repo-relative changed file paths (e.g. from "
                              "github_advisories.py resolve)")
    args = parser.parse_args()
    targets = map_files_to_targets(args.changed_files)
    print(json.dumps([dataclasses.asdict(t) for t in targets], indent=2))


if __name__ == "__main__":
    main()
