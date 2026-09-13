# Contributing

The public contribution workflow will be finalized before launch. For now:

1. Create a focused branch and keep changes small.
2. Add tests for behavioral or security changes.
3. Run `ruff check .`, `mypy`, and `pytest`.
4. Explain security assumptions and possible bypasses in the pull request.
5. Never add real secrets, personal data, or confidential prompts to fixtures.
6. Use `execuseal demo` as a smoke test for the public synthetic experience.

Product feedback and non-security bugs may use the checked-in issue forms after
the repository launches. Use only synthetic or fully redacted reproductions.
Suspected vulnerabilities and working bypasses must follow `SECURITY.md` and
must never be posted publicly.

By contributing, you agree that your contribution is licensed under Apache-2.0.
