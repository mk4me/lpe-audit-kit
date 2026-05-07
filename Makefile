.PHONY: help test lint check release clean install-deps

VERSION := $(shell grep '^VERSION=' lpe-audit.sh | head -1 | cut -d'"' -f2)
KIT_NAME := lpe-audit-kit-$(VERSION)

help:
	@echo "lpe-audit-kit $(VERSION)"
	@echo ""
	@echo "Available targets:"
	@echo "  make test        Run test suite"
	@echo "  make lint        Run shellcheck on all scripts"
	@echo "  make check       Run lint + test"
	@echo "  make release     Build release tarball"
	@echo "  make clean       Remove build artifacts"
	@echo "  make install-deps  Install development dependencies"

test:
	@./tests/run-tests.sh

lint:
	@command -v shellcheck >/dev/null 2>&1 || { echo "shellcheck not installed"; exit 1; }
	@echo "Linting lpe-audit.sh..."
	@shellcheck -S warning lpe-audit.sh
	@echo "Linting fleet-audit.sh..."
	@shellcheck -S warning fleet-audit.sh
	@echo "Linting verify.sh..."
	@shellcheck -S warning verify.sh
	@echo "Linting tests/run-tests.sh..."
	@shellcheck -S warning tests/run-tests.sh
	@echo "All scripts pass shellcheck (warning level)."

check: lint test

release: clean
	@mkdir -p dist/$(KIT_NAME)
	@cp lpe-audit.sh fleet-audit.sh verify.sh hosts.txt.example \
	    README.md LICENSE NOTICE CHANGELOG.md SECURITY.md \
	    dist/$(KIT_NAME)/
	@cd dist/$(KIT_NAME) && \
	    sha256sum lpe-audit.sh fleet-audit.sh verify.sh README.md hosts.txt.example > SHA256SUMS
	@cd dist && tar czf $(KIT_NAME).tar.gz $(KIT_NAME)/
	@cd dist && sha256sum $(KIT_NAME).tar.gz > $(KIT_NAME).tar.gz.sha256
	@echo "Release tarball: dist/$(KIT_NAME).tar.gz"
	@ls -la dist/

clean:
	@rm -rf dist/ fleet-results-*/
	@find . -name "*.broken" -delete

install-deps:
	@echo "On Debian/Ubuntu: sudo apt install shellcheck dash"
	@echo "On RHEL/Fedora:   sudo dnf install ShellCheck dash"
	@echo "On macOS:         brew install shellcheck dash"
