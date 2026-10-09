# Developer tasks. `make help` lists them.
#
# ruff runs from $(RUFF). markdownlint-cli2 and editorconfig-checker run from PATH when installed,
# and otherwise from their container image, pinned by digest, with the repository mounted
# read-only and run as the calling user. Only tracked files are linted.

SHELL := bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help
MAKEFLAGS += --no-builtin-rules

PYTHON ?= python3
# From an activated virtualenv, or e.g. `make lint RUFF=../.venv/bin/ruff`
RUFF ?= ruff

MARKDOWNLINT_CLI2_IMAGE ?= docker.io/davidanson/markdownlint-cli2:v0.23.3@$\
	sha256:d5f3f3f04b2e285dcbcdcd13b4454d119e273e3c393a9dabd163dba4abad526d
EDITORCONFIG_CHECKER_IMAGE ?= ghcr.io/editorconfig-checker/editorconfig-checker:4.0.1@$\
	sha256:c843ca21130986fb1c8c5e09bb38075bd51432ad40cc6db118a6f8cde897db0e

PY_FILES = $(shell git ls-files '*.py')
MD_FILES = $(shell git ls-files '*.md')
SH_FILES = $(shell git ls-files '*.sh')
JSON_FILES = $(shell git ls-files '*.json')
ALL_FILES = $(shell git ls-files)

# $(call container,<binary>,<image>,<workdir>): <binary> from <image>, with the repository
# mounted at <workdir>. The entrypoint is named, since not every image sets one.
container = docker run --rm --user "$$(id -u):$$(id -g)" \
	--volume "$(CURDIR):$(3):ro" --workdir "$(3)" --entrypoint "$(1)" $(2)

.PHONY: help
help: ## List the targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN { FS = ":.*## " } { printf "  %-18s %s\n", $$1, $$2 }'

.PHONY: check
check: lint test ## Lint and test, as CI does except for `validate`

.PHONY: lint
lint: lint-py lint-md lint-editorconfig lint-sh lint-json ## Run every linter

.PHONY: fmt
fmt: ## Format Python with ruff, configured by ruff.toml
	$(RUFF) format $(PY_FILES)

.PHONY: lint-py
lint-py: ## Check that Python is formatted, showing the diff if not
	$(RUFF) format --check --diff $(PY_FILES)

.PHONY: lint-md
lint-md: ## Lint Markdown with markdownlint-cli2, configured by .markdownlint.yaml
	@if command -v markdownlint-cli2 >/dev/null; then \
		markdownlint-cli2 $(MD_FILES); \
	else \
		$(call container,markdownlint-cli2,$(MARKDOWNLINT_CLI2_IMAGE),/workdir) $(MD_FILES); \
	fi

# Indent size is left to ruff and markdownlint: editorconfig-checker reads every file as plain
# lines, so it counts the hanging indent of a docstring or a list item as a wrong indent.
EDITORCONFIG_CHECKER_FLAGS = -disable-indent-size

.PHONY: lint-editorconfig
lint-editorconfig: ## Check every tracked file against .editorconfig
	@if command -v editorconfig-checker >/dev/null; then \
		editorconfig-checker $(EDITORCONFIG_CHECKER_FLAGS) $(ALL_FILES); \
	else \
		$(call container,editorconfig-checker,$(EDITORCONFIG_CHECKER_IMAGE),/check) \
			$(EDITORCONFIG_CHECKER_FLAGS) $(ALL_FILES); \
	fi

.PHONY: lint-sh
lint-sh: ## Lint shell scripts with shellcheck
	shellcheck $(SH_FILES)

.PHONY: lint-json
lint-json: ## Check that every JSON file parses
	@for file in $(JSON_FILES); do \
		$(PYTHON) -m json.tool "$${file}" >/dev/null || { echo "invalid JSON: $${file}" >&2; exit 1; }; \
	done

.PHONY: test
test: ## Run the tests
	$(PYTHON) -m unittest discover -s tests

.PHONY: validate
validate: ## Run `claude plugin validate` (needs `claude` on PATH)
	bash ci/validate-plugin.sh plugin
