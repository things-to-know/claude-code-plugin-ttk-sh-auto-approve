# Canonical-grammar prototype

A prototype, not wired into the hook. Instead of approving the text Claude wrote, the hook would
parse it with a small static grammar, validate the argv it gets, and approve its own
re-serialization through `hookSpecificOutput.updatedInput.command`. What runs is the hook's text,
so safety rests on two things:

1. The serializer is exact: in bash and zsh, its text runs the argv and redirections the
   validators saw, and nothing else
2. The validators are right about that argv: program semantics and paths, unchanged from today

The parser no longer has to agree with bash or zsh for safety: a misreading only changes what
runs to something the validators approved. It has to agree with bash for usability, which
`equiv.py` measures.

Stdlib only, Python 3.12+, run with `-I` like the hook.

## Files

- `canon.py`: the grammar (`parse`), the serializer (`serialize`), rejection categories
- `harvest.py`: reads the suite's `assert_allowed`, `assert_refused`, `assert_refused_outright`
  and `assert_no_opinion` literals, and the verdict each asserts, with `ast`; no test code runs
- `coverage.py`: grammar outcome per verdict, rejections by category, into a JSON report
- `equiv.py`: runs original and canonical text in bash, or canonical only in zsh, with every
  program replaced by an argv-logging shim; plus a serializer fuzz
- `measure_explain.py`: the same measurement on real sessions, from `make -s explain`

## Grammar

Accepted:

- Simple commands joined by `|`, `&&`, `||`, `;` and newlines
- Words of unquoted literal characters, `'...'`, `"..."` without `$` or a backquote, and
  backslash escapes
  - Mid-word `~` and `^` (`HEAD~1`, `HEAD^`) and braces without a comma or `..` (`@{u}`) are
    literal in both shells
  - A lone `[` is the test command
- Comments
- `[n]< file`; `>`, `>>`, `>|`, `&>` and `&>>` to `/dev/null` only; `[n]>&m` for digits `m`

Rejected, by category:

- Expansion: `glob`, `tilde` (leading, or after `=` or `:`), `brace-expansion`,
  `parameter-expansion`, `command-substitution`, `arithmetic`, `ansi-c-quote`, `locale-quote`,
  `zsh-equals` (`=cmd`)
- Structure: `heredoc`, `herestring`, `process-substitution`, `subshell-or-group`, `group`,
  `background`, `pipe-stderr`, `case-terminator`, `reserved-word`, `assignment`, `precommand`
  (`command`, `builtin`, `exec`, `eval`, `noglob`, …)
- Redirection: `output-redirect` (anything but `/dev/null`), `read-write-redirect`,
  `input-fd-dup`, `fd-close`, `duplicate-fd-redirect` (zsh's `MULTIOS` tees or concatenates a
  doubly redirected fd, where bash keeps the last)
- `control-character`, `syntax`

Serialization:

- Every word single-quoted, `'` as `'\''`. zsh's `RC_QUOTES` reads `''` inside a quoted string
  as a quote, but every `''` this produces is followed by a backslash or ends the text
- The command word behind `command`: zsh runs the external program (`/usr/bin/printf`, not the
  builtin that evaluates arithmetic, #8), bash its builtin or the external; neither runs an alias
  or a function. `cd`, `pwd` and `type` go behind `builtin`
- Redirections with explicit fds: `0<'f'`, `2>'/dev/null'`, `2>&1`

## Results

At `0070d62`. The corpus is the suite's 743 assertion literals, 670 distinct commands; each
verdict is the assertion's, since the suite passes on `main`, not a re-run of the hook.

Grammar outcome per asserted verdict:

- allow: 169 of 195 kept (86.7%); 171 with hook-side expansion of a leading `~` and globs
  - Without the classes that install operator rules or a remote: 108 of 128 (84.4%); 109
- refused: 155 of 440 (35.2%) rejected by the grammar itself; 285 reach the validators
- no-opinion: 26 of 45 kept; 35 with hook-side expansion

The 26 approved commands the grammar rejects:

- 12 statically evaluable: `for` loops over literal lists, literal assignments used later,
  `${r%%:*}` on literals, `$((1+1))`. A hook-side evaluator could unroll them into canonical text
- 5 read a variable the command never sets (`"$x"`, `"${arr[@]}"`, `"$n"`)
- 5 command substitutions: their values exist only at run time
- 2 a leading `~`
- 1 `command -v …`, 1 `time …`

Against bash 5.2.21, every program a shim:

- Fidelity, bash on the original text logs the argv `parse` read: 470 of 470
- Exactness, bash on the canonical text logs the same argv: 470 of 470
- 10 accepted commands not run: 5 name a program by its path, 5 redirect from a file absent there
- Fuzz, 2,000 random argv with every metacharacter, quotes, newlines, control characters and
  multibyte text: no failure, the canonical text parsing back to the same argv included

zsh: not run yet. `equiv.py … zsh` runs the canonical text under
`zsh -f -c 'setopt NO_EXTENDED_GLOB NO_BARE_GLOB_QUAL [extra]; eval "$1"'`, the wrapper the hook's
docstring records, with the extra option sets `RC_QUOTES` and
`RC_QUOTES SH_WORD_SPLIT GLOB_SUBST MAGIC_EQUAL_SUBST EXTENDED_GLOB KSH_GLOB`.

## Reproduce

From the repository root, with `out` any directory outside the repository:

```sh
python3 -I tools/canonical/harvest.py "$out/asserted.jsonl"
python3 -I tools/canonical/coverage.py "$out/asserted.jsonl" "$out/report.json"
python3 -I tools/canonical/equiv.py "$out/report.json" "$out/work" 2000
python3 -I tools/canonical/equiv.py "$out/report.json" "$out/work-zsh" 2000 zsh
```

Real traffic:

```sh
make -s explain PROJECT=<dir> TRANSCRIPT=<session>.jsonl \
  | python3 -I tools/canonical/measure_explain.py
```

## Limits

- The corpus is the suite's literals: weighted toward adversarial cases and controls, not toward
  what sessions send. `measure_explain.py` gives the number that matters
- Hook-side expansion of globs, `~` and `{a,b}` is measured, not implemented: `serialize` refuses
  a word that still holds a pattern
- A function or alias named `command` or `builtin` in the operator's own startup files shadows
  the prefix; quoting doesn't change that
- Evaluating environment variables in the hook would be safety-neutral, as the output is still
  literal, but would copy values such as tokens into the command text the transcript records
- A rejected command falls back either to today's text validation, which keeps coverage and the
  expansion risk on that path, or to a prompt, which closes it and costs the 13% above
