# Contributing

Thanks for your interest in TianoPoC (an add-on to HBFAplus that turns
GitHub Security Advisories into build-tested, crash-verified PoC harnesses
for TianoCore EDK II).

## Before you start

This repo only contains `Tools/AdvisoryPipeline` and a small set of
infrastructure fixes — it's meant to sit inside a working HBFAplus
checkout, not run standalone. Set that up first per
[HBFAplus's instructions](https://github.com/TianoShield/HBFAplusplus).

## How to contribute

1. Open an issue first for anything beyond a trivial fix, describing the
   problem or enhancement, and which pipeline stage it affects (scan /
   generate / build / fuzz / verify / sanity-check).
2. Fork the repo and create a branch off `main`.
3. Make your changes.
4. Open a pull request against `main` describing what changed and why,
   and which advisory/advisories you validated against, if applicable.

## Coding standards

- No hard-coded secrets, tokens, or API keys anywhere in committed files —
  use environment variables (`GITHUB_API_KEY`, `OPENAI_API_KEY`, etc.) as
  the existing code does.
- New CLI flags should be documented in the README's "Key flags" table.
- New dependencies should be added to any relevant `requirements.txt` (or
  noted in the README) alongside the code that needs them.

## Handling generated PoCs / crash artifacts

Do not commit generated harnesses, crashing inputs, or packaged PoCs from
your own local runs to this repository.

## Reporting bugs / requesting features

Use GitHub Issues. Include: which pipeline stage, the advisory ID you were
targeting (if any), the LLM/model used (`HBFA_LLM_MODEL`), and whether
`--pocgen-mode` / `--no-codeql` were set.

## Reporting security issues

Do **not** open a public issue for security vulnerabilities — see
[SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under
the project's [MIT License](LICENSE).
