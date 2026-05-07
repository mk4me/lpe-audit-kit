# Contributing to lpe-audit-kit

Thanks for your interest in contributing. This document covers what kinds of
contributions are welcome and how to submit them.

## Types of contributions

### Welcome

- **Distro support fixes** — if the script gets a wrong reading on your
  distro, please report with `./lpe-audit.sh --json` output and `cat /etc/os-release`
- **Detection improvements** — better heuristics for module presence,
  patch detection, container runtime detection
- **New audit checks** — additional related vulnerabilities in the same bug
  class (page-cache write primitives, confused deputy patterns)
- **Portability fixes** — making the script work on shells/distros it
  currently fails on
- **Documentation** — clearer explanations, translations, mitigation context
- **Test coverage** — see `tests/` for the existing test harness

### Out of scope

- Exploit code or PoCs — this is an auditor, not an exploit kit
- Auto-mitigation features that modify system state without explicit consent
- Anything that would make the script require non-standard dependencies
  (Python, jq mandatory, etc.) — POSIX sh portability is core

## Submitting changes

1. Fork the repo on GitHub
2. Create a feature branch: `git checkout -b feature/my-improvement`
3. Make your changes
4. Run tests: `make test` or `./tests/run-tests.sh`
5. Run linter: `make lint` (requires `shellcheck`)
6. Commit with a clear message
7. Push and open a PR against `main`

## Code style

- POSIX sh compatible (no bashisms in `lpe-audit.sh` core paths)
- Indent with 4 spaces, no tabs
- Variable names: `UPPERCASE_GLOBAL`, `lowercase_local`
- Run `shellcheck` clean (warnings about style are OK, errors are not)
- Comments in English

## Testing locally

The repo includes a test harness in `tests/` that validates output
parsing and the verdict logic on synthetic fixtures:

```bash
./tests/run-tests.sh
```

For testing on your actual distro:

```bash
./lpe-audit.sh                 # human output
./lpe-audit.sh --json | jq .   # validate JSON parses
echo "Exit code: $?"
```

## Reporting bugs

Please include:
- Distro and version (`cat /etc/os-release`)
- Kernel version (`uname -a`)
- `./lpe-audit.sh --json` output
- What you expected vs what happened

Open an issue at: https://github.com/mk4me/lpe-audit-kit/issues

## Security issues with the auditor

If you find a security issue *in the auditor itself* (e.g., the script does
something dangerous on a particular input), please follow [SECURITY.md](SECURITY.md)
for responsible disclosure rather than opening a public issue.

For Linux kernel vulnerabilities themselves, please report to
`security@kernel.org` and `linux-distros@vs.openwall.org` per upstream
guidelines, not here.

## License

By contributing, you agree that your contributions will be licensed under
the [Apache License 2.0](LICENSE).
