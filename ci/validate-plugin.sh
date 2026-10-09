#!/usr/bin/env bash
# Validate the plugin with `claude plugin validate`, failing on errors and on
# every warning except the missing-version one. `version` is deliberately
# absent (see CLAUDE.md), so `--strict` would always fail here.
set -euo pipefail

plugin_dir="${1:-plugin}"

if ! out="$(claude plugin validate "$plugin_dir" 2>&1)"; then
	printf '%s\n' "$out"
	exit 1
fi
printf '%s\n' "$out"

unexpected="$(
	grep -E '^[[:space:]]*> ' <<<"$out" \
		| grep -vE '^[[:space:]]*> version: No version specified' \
		|| true
)"
if [[ -n "$unexpected" ]]; then
	echo "Unexpected validation warnings:" >&2
	printf '%s\n' "$unexpected" >&2
	exit 1
fi
