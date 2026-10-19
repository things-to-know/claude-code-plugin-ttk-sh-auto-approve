# Developer tasks. `make help` lists them.
#
# Notes:
# - This Makefile is designed for GNU Make; it may not work properly with other `make`
#   implementations
# - Recipes run in bash with `-e -u -o pipefail`, set in `SHELL` rather than `.SHELLFLAGS`, which
#   the GNU Make 3.81 that macOS ships ignores
#   - Caveat: `-u` only catches undefined **shell** variables; `--warn-undefined-variables` reports
#     the undefined Make ones
# - Make variables are written `${VAR}` rather than `$(VAR)`, to ease moving a line between this
#   file and a bash script
#   - Parentheses stay for Make functions, such as `$(shell ...)`, and for the arguments of a
#     `$(call ...)`, which would mean something else in bash
# - About linting/formatting tools:
#   - `ruff` runs through `uv`, from `.venv`, at the version `uv.lock` pins
#   - `markdownlint-cli2`, `editorconfig-checker`, `shellcheck` and `actionlint` run from `PATH`
#     when installed, and otherwise from their container image, pinned by digest, with the
#     repository mounted read-only and run as the calling user
#     - Except for `lint-md-fix`, which mounts it writable to write its fixes
#     - `LINTERS_FROM_IMAGES=1` runs them from their images even when installed, as CI does
#   - Only tracked files are linted

SHELL = /usr/bin/env bash -e -u -o pipefail
MAKEFLAGS += --no-builtin-rules
# Helps to detect errors in the Makefile itself, such as a misspelt variable
MAKEFLAGS += --warn-undefined-variables
.DEFAULT_GOAL := help

# Every path here is relative to the repository root: run from anywhere else, as with
# `make -f <repo>/Makefile`, `lint-py` checks the wrong files and passes
# - `lastword`, read before any `include`, names this file even when `MAKEFILES` or an earlier
#   `-f` puts another one first
# - Warning: do not use `=` instead of `:=` (we don't want late-binding)
ROOT_DIR := $(shell dirname $(realpath $(lastword ${MAKEFILE_LIST})))
ifneq (${CURDIR},${ROOT_DIR})
$(error Run make from the repository root: `make -C ${ROOT_DIR} <target>`)
endif

# --------------------------------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------------------------------

PYTHON ?= python3
UV ?= uv

# `uv run` installs it into .venv first when needed, and fails when uv.lock is out of date
RUFF ?= ${UV} run --locked ruff

# Recipes run without `VIRTUAL_ENV`, the variable that activating a virtualenv sets:
# - `uv run` always uses the project's own .venv, and while another virtualenv is active it warns
#   on every run that it ignores that one; no option silences just this warning
# - The other recipes' commands don't read it, and `PATH` still finds an activated virtualenv's
#   `python3` first
unexport VIRTUAL_ENV

# Extra arguments for `unittest`, e.g. `make test TEST_ARGS='-k Widening'`
TEST_ARGS ?=

# The Python versions `test-all-python-matrix` runs the tests on: those in CI's test matrix
# Warning: keep in sync with `.github/workflows/ci.yml` (`jobs.test.strategy.matrix.python`)
TEST_PYTHON_VERSIONS ?= 3.12 3.13 3.14

# The session to explain a verdict for, and the copy of the hook to ask, e.g.
# `make explain PROJECT=~/ws/app CWD=~/ws/app/sub < commands.txt`
PROJECT ?= ${CURDIR}
CWD ?= ${PROJECT}
HOOK ?= plugin/scripts/sh_auto_approve.py

PY_FILES = $(shell git ls-files '*.py')
MD_FILES = $(shell git ls-files '*.md')
SH_FILES = $(shell git ls-files '*.sh')
JSON_FILES = $(shell git ls-files '*.json')
WORKFLOW_FILES = $(shell git ls-files '.github/workflows/*.yml' '.github/workflows/*.yaml')
ALL_FILES = $(shell git ls-files)

# Set to run every linter that has an image from it, even when installed
# - e.g. `make lint LINTERS_FROM_IMAGES=1`
# - CI sets it, so that it runs the versions pinned here rather than the ones the runner ships
LINTERS_FROM_IMAGES ?=

# Container images, pinned by digest
# - A digest can't be wrapped, so `editorconfig-checker` skips these lines
# editorconfig-checker-disable
MARKDOWNLINT_CLI2_IMAGE ?= docker.io/davidanson/markdownlint-cli2:v0.23.3@sha256:d5f3f3f04b2e285dcbcdcd13b4454d119e273e3c393a9dabd163dba4abad526d
EDITORCONFIG_CHECKER_IMAGE ?= ghcr.io/editorconfig-checker/editorconfig-checker:4.0.1@sha256:c843ca21130986fb1c8c5e09bb38075bd51432ad40cc6db118a6f8cde897db0e
SHELLCHECK_IMAGE ?= docker.io/koalaman/shellcheck:v0.11.0@sha256:61862eba1fcf09a484ebcc6feea46f1782532571a34ed51fedf90dd25f925a8d
ACTIONLINT_IMAGE ?= docker.io/rhysd/actionlint:1.7.12@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667
# editorconfig-checker-enable

# $(call container,<binary>,<image>,<workdir>,<mode>):
# - <binary> from <image>, with the repository mounted at <workdir>, read-only or writable as
#   <mode> says: `ro` or `rw`
#   - Every call names it: under `--warn-undefined-variables`, an argument left out warns
# - The entrypoint is named, since not every image sets one
container = docker run --rm --user "$$(id -u):$$(id -g)" \
	--volume "${CURDIR}:$(3):$(4)" --workdir "$(3)" --entrypoint "$(1)" $(2)

# $(call path-or-container,<binary>,<image>,<workdir>,<mode>,<arguments>):
# - <binary> with <arguments>, from PATH when installed and `LINTERS_FROM_IMAGES` is empty, and
#   otherwise from <image>
path-or-container = if [[ -z "${LINTERS_FROM_IMAGES}" ]] && command -v $(1) >/dev/null; then \
		$(1) $(5); \
	else \
		$(call container,$(1),$(2),$(3),$(4)) $(5); \
	fi

# --------------------------------------------------------------------------------------------------
# Targets / Generic
# --------------------------------------------------------------------------------------------------

.PHONY: help
help: ## List the targets
	@echo 'See the "Develop" section of AGENTS.md.'
	@echo
	@grep -E '^[a-z-]+:.*## ' ${MAKEFILE_LIST} \
		| awk 'BEGIN { FS = ":.*## " } \
			{ name[NR] = $$1; text[NR] = $$2; if (length($$1) > width) width = length($$1) } \
			END { for (i = 1; i <= NR; i++) printf "  %-" width "s  %s\n", name[i], text[i] }'

.PHONY: check
check: lint
check: test
check: ## Lint and test as CI does, but with your installed linters and `python3`

.PHONY: compile-deps
compile-deps: ## Update uv.lock from pyproject.toml
	${UV} lock

.PHONY: install-dev
install-dev: ## Install the dev tools (ruff) into .venv, as uv.lock pins them
	${UV} sync --locked

.PHONY: lint
lint: lint-py
lint: lint-md
lint: lint-editorconfig
lint: lint-sh
lint: lint-json
lint: lint-gh-workflows
lint: ## Run every linter, fixing nothing

# Review its diff like any other change: see "Linting" in `AGENTS.md`
.PHONY: lint-fix
lint-fix: lint-py-fix
lint-fix: lint-md-fix
lint-fix: ## Apply the fixes the linters can make on their own

# `-B` ("write no `.pyc` files"): it keeps the tests' imports of the hooks from writing bytecode
# into `plugin/`, which a local marketplace install copies along with the scripts
.PHONY: test
test: ## Run the tests, e.g. `make test TEST_ARGS='-k Widening'`
	${PYTHON} -B -m unittest discover -s tests ${TEST_ARGS}

# `test` once per version, on the interpreter uv finds for it, which uv installs first if missing
.PHONY: test-all-python-matrix
test-all-python-matrix: ## Run the tests on each Python version in CI's matrix, from uv
	@for version in ${TEST_PYTHON_VERSIONS}; do \
		${UV} python install --quiet "$${version}"; \
		${MAKE} --no-print-directory test PYTHON="$$(${UV} python find "$${version}")"; \
	done

# .venv is left to `delete-venv`
.PHONY: clean
clean: ## Delete Python bytecode and ruff's cache
	find . -path ./.venv -prune -o -name __pycache__ -type d -prune -exec rm -rf -- {} +
	rm -rf .ruff_cache

# --------------------------------------------------------------------------------------------------
# Targets / Specific
# --------------------------------------------------------------------------------------------------

.PHONY: lint-py
lint-py: ## Check that Python is formatted, showing the diff if not
	${RUFF} format --check --diff ${PY_FILES}

.PHONY: lint-py-fix
lint-py-fix: ## Format Python with ruff, configured by ruff.toml
	${RUFF} format ${PY_FILES}

.PHONY: lint-md
lint-md: ## Lint Markdown with markdownlint-cli2, configured by .markdownlint.yaml
	@$(call path-or-container,markdownlint-cli2,${MARKDOWNLINT_CLI2_IMAGE},/workdir,ro,${MD_FILES})

.PHONY: lint-md-fix
lint-md-fix: ARGS = --fix ${MD_FILES}
lint-md-fix: ## Apply markdownlint-cli2's fixes to Markdown, configured by .markdownlint.yaml
	@$(call path-or-container,markdownlint-cli2,${MARKDOWNLINT_CLI2_IMAGE},/workdir,rw,${ARGS})

# Indent size is left to ruff and markdownlint: editorconfig-checker reads every file as plain
# lines, so it counts the hanging indent of a docstring or a list item as a wrong indent.
EDITORCONFIG_CHECKER_FLAGS = -disable-indent-size

.PHONY: lint-editorconfig
lint-editorconfig: ARGS = ${EDITORCONFIG_CHECKER_FLAGS} ${ALL_FILES}
lint-editorconfig: ## Check every tracked file against .editorconfig
	@$(call path-or-container,editorconfig-checker,${EDITORCONFIG_CHECKER_IMAGE},/check,ro,${ARGS})

.PHONY: lint-sh
lint-sh: ## Lint shell scripts with shellcheck
	@$(call path-or-container,shellcheck,${SHELLCHECK_IMAGE},/mnt,ro,${SH_FILES})

.PHONY: lint-gh-workflows
lint-gh-workflows: ## Lint the GitHub Actions workflows with actionlint
	@$(call path-or-container,actionlint,${ACTIONLINT_IMAGE},/repo,ro,${WORKFLOW_FILES})

.PHONY: lint-json
lint-json: ## Check that every JSON file parses
	@for file in ${JSON_FILES}; do \
		${PYTHON} -m json.tool "$${file}" >/dev/null || { echo "invalid JSON: $${file}" >&2; exit 1; }; \
	done

# `-B`: as for `test`, though `tools/explain.py` also sees to it for the hook it loads
.PHONY: explain
explain: ## Print the hook's verdict and reason for each command on stdin
	${PYTHON} -I -B tools/explain.py --project "${PROJECT}" --cwd "${CWD}" --hook "${HOOK}"

.PHONY: validate
validate: ## Run `claude plugin validate` (needs `claude` on PATH)
	bash ci/validate-plugin.sh plugin

# For a .venv that broke, e.g. when the Python it was made with is gone. It holds only what
# uv.lock pins, so nothing is lost.
.PHONY: delete-venv
delete-venv: ## Delete .venv, where uv installs the dev tools; the next ruff run recreates it
	rm -rf .venv
