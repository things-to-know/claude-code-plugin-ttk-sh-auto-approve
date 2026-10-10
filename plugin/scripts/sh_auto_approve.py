#!/usr/bin/env python3
"""Approve read-only Bash commands that a permission rule cannot express.

A Claude Code ``PreToolUse`` hook. It reads the tool call on stdin and prints an ``allow``
decision when every command in it is provably read-only; otherwise it prints nothing,
falling through to the normal user confirmation prompt.

.. warning::

   The "Bash" tool is not always bash. Claude Code runs the command in the operator's login
   shell when that is bash or zsh -- zsh is the macOS default -- or in the one
   ``CLAUDE_CODE_SHELL`` names. The aliases and functions of the operator's shell startup file
   apply as well, e.g. ``grep`` may be ``grep --color=auto ...``.

Under zsh the command is wrapped as
``zsh -c 'source <snapshot>; setopt NO_EXTENDED_GLOB NO_BARE_GLOB_QUAL; ... eval <command>'``.
This module reads a program name as the program itself, and cannot see an alias that makes it write.

Sources: ``CLAUDE_CODE_SHELL`` in https://code.claude.com/docs/en/env-vars, and "Bash tool
behavior" in https://code.claude.com/docs/en/tools-reference. The wrapper is observed, not
documented: ``ps -o args= -p $$`` run through the Bash tool prints it, options included.

Thus, every rule here has to hold under both grammars. Decisions for this hook:

- The grammar modeled is bash's
- What only zsh expands is refused wherever it is spelled. Examples:
  - ``${(e)x}``
  - ``$~x``
  - glob qualifiers
  - ``=(...)``
  - ``echo`` interpreting escapes without ``-e``
  - ``printf '%d'`` evaluating its argument

A command is approved when every simple command in it clears one of two tiers:

    1. nothing in it can write a file, change a resource, or run a program this
        module did not read; or
    2. the module has no reading of it at all, and the operator's own rules in
        ``.claude/settings.json`` and ``.claude/settings.local.json`` already allow that
        exact command text.

Tier 1 is a superset of the host's own built-in read-only set, because a pipeline is only
useful if ``cut``, ``printf``, ``sort`` and ``tr`` are reachable inside it. It reads the
``gh api`` GETs and the ``gh pr|run|issue|repo`` reads (``GH_READ_SPECS``) flag by flag, and
refuses a ``--jq`` that reads the environment on every ``gh`` subcommand.

Tier 2 grants nothing new: each of those commands is one Claude Code would run with no
prompt if it stood on its own, and the host already requires every sub-command of a
compound to match a rule independently. What it fixes is the pipeline that loses its
grant because one filter in the middle -- a ``sed`` stripping ANSI escapes from a help page
-- has no rule of its own. It is bounded in the one direction that matters: an allow rule
may supply a program this module has never heard of, and may never overrule a validator
that read the command and found a write. ``NoOpinion`` is where that line is drawn, and a
deny rule refuses whatever else would have approved.

Hardened against:
- Shlex/Bash grammar discrepancies (comments, newlines, punctuation gluing)
- Command substitution whose body or position cannot be vouched for, and every other
    spelling of it: backticks, process substitution, the Bash 5.3 ``${ ...; }`` forms
- Dynamic linker/environment variable injection (LD_PRELOAD, PATH, BASH_ENV, etc.)
- Program path spoofing: a non-bare executable, and a program name that is quoted,
    escaped or expanded rather than written
- Embedded DSL exploits in ``sed``, ``awk``, ``gawk``, including ``@include`` inside the program
- Parameter-shifting bypasses and mutating subcommands in ``git``, ``aws``, and ``gcloud``, plus the
    flags that move where a call goes or who it goes as (``--endpoint-url``, ``--git-dir``,
    ``--configuration``, ``--cli-input-json``)
- A writing flag the shell supplies: bundled behind another short option (``sed -ni``,
    ``sort -uo``), or produced by an expansion in the word itself
- An assignment with no ``=`` to find: ``printf -v``, and ``${name:=value}``
- Flag-expanding unquoted globs and non-terminating commands

Quoting is resolved before the command reaches the lexer, by ``_scan``. That is not a
detail: ``posix=True`` strips quotes and returns a token identical to an unquoted one, so
without it every ``>`` in an ``awk`` comparison and every ``|`` closing a ``sed`` script reads as
syntax, and everyday idioms are refused for characters they only contain. What the lexer
sees has nothing quoted left in it, so a ``>`` that survives is one bash will act on.

Why it exists: an allow rule matches the literal command text, so it can never cover a
command the shell builds at runtime. For example:

    for p in $(gcloud projects list --format='value(projectId)');
        do gcloud projects get-iam-policy "${p}-x";
    done

has no text to match and prompts every time, however many rules are added.
This hook reads the whole command instead and decides on what it does.

Requires Python ``MINIMUM_PYTHON`` or later on Linux or macOS. Anywhere else it stays silent,
which is the same as not being installed: every command prompts.

Wiring: ``hooks/hooks.json`` in the plugin runs ``python3 -I`` on this file for every Bash
tool call. Test it by hand from the repository root with the payload Claude Code sends:

    echo '{"tool_name":"Bash","tool_input":{"command":"wc -l README.md"}}' \
        | CLAUDE_PROJECT_DIR="$PWD" python3 -I plugin/scripts/sh_auto_approve.py

``tests/`` holds the cases that pin the behavior down.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
from pathlib import Path
from stat import S_ISREG

# Maximum command length inspected before defaulting to user prompt (matches host caution)
HOST_COMMAND_LENGTH_CAP = 10_000

# Where this module is supported. Anywhere else it stays silent, so every command prompts as
# if the hook were not installed: the shells and tools it models are the ones found here,
# and an older interpreter is one nobody has run the tests on.
MINIMUM_PYTHON = (3, 12)
SUPPORTED_PLATFORMS = ("linux", "darwin")

# The project the session works in:
# - What a `cd` is measured against
# - What a reader may read inside
# - Where the settings files are read from
# `main` sets it per call with `_project_root`, since a plugin's copy of this file sits in a cache
# that belongs to no project. The value here is where the file sits in its own repository,
# `plugin/scripts/` being two levels below the root, which is what the tests import it against.
REPO_ROOT = Path(__file__).resolve().parents[2]

# Set by Claude Code for hooks: the directory the session was started in, which a later `cd`
# does not move.
PROJECT_DIR_ENV = "CLAUDE_PROJECT_DIR"

# Where the operator's own rules live, and the variable a test points somewhere else. An
# empty value turns the second tier off, which is how the classifier is exercised alone.
SETTINGS_ENV = "SH_AUTO_APPROVE_SETTINGS"
SETTINGS_FILES = (".claude/settings.json", ".claude/settings.local.json")

# A settings file larger than this is not one anyone wrote, and reading it costs the Bash call
# it was supposed to approve. A hand-written one is a few KB, so the cap is some tens of times
# that and still small enough to read on every call.
SETTINGS_SIZE_CAP = 256 * 1024

# Base programs that only ever read. Must be invoked by bare name (no slashes).
READ_ONLY = {
    "basename",
    "cat",
    "cmp",
    "column",
    "comm",
    "cut",
    "diff",
    "dirname",
    "du",
    "echo",
    "egrep",
    "false",
    "fgrep",
    "grep",
    "head",
    "id",
    "join",
    "jq",
    "ls",
    "md5sum",
    "nl",
    "od",
    "paste",
    "printf",
    "pwd",
    "readlink",
    "realpath",
    "rev",
    "shasum",
    "sha1sum",
    "sha256sum",
    "stat",
    "tac",
    "tail",
    "test",
    "tr",
    "true",
    "uname",
    "wc",
    "which",
    "whoami",
}

# Shell control structure keywords that can precede a simple command
STRUCTURE = {
    "do",
    "done",
    "elif",
    "else",
    "esac",
    "fi",
    "if",
    "then",
    "time",
    "until",
    "while",
    "{",
    "}",
    "!",
    "[[",
    "]]",
}

# Head keywords that introduce a loop variable list
WORD_LIST_HEADS = {"for"}

# Exactly recognized shell separators
SEPARATORS = {";", "|", "&&", "||", "&", "|&", "\n"}

# Shell punctuation characters handled by punctuation_chars=True
PUNCTUATION_CHARS = set("();<>|&")

# Stream redirections that safely discard or merge output streams without file creation
SAFE_REDIRECTS = re.compile(
    r"(?<![^\s;|&(])(?:[12]?>&[12]|&>\s*/dev/null|[12]?>\s*/dev/null|<\s*/dev/null)"
    r"(?=[\s;|&)]|$)"
)

# Reading a file through `<` is a read. The target is left in the reduced command when it
# is literal and is a placeholder when it is quoted; either way nothing is created. The
# forms this must not swallow are `<<`, `<<<`, `<&` and `2<`, each of which fails the
# character class or the lookbehind and stays punctuation for `_segments` to refuse.
FILE_INPUT_REDIRECT = re.compile(r"(?<![^\s;|&(])<\s*([^\s;|&()<>]+)(?=[\s;|&)]|$)")

# A socket the shell opens itself, with no program involved. `cat /dev/tcp/h/p` is egress
# spelled as a read, so the path is refused wherever it appears rather than per-program.
NETWORK_DEVICE = re.compile(r"/dev/(?:tcp|udp)/")

# Output is not inert:
# - A terminal acts on an escape sequence
# - OSC 52 writes the clipboard
# - OSC 8 turns any text into a link
# - Some terminals report their title back as input
# A raw ESC or C1 control byte has no business in a command, so it is refused anywhere.
# Spelled out, `\033` is only text until `echo` or `printf` interprets it (zsh's `echo` does
# without `-e`), so a spelling is refused in what either is given, and so is any value either
# expands when the command spells one somewhere, since that value may be the escape.
# Elsewhere it is left alone: `sed 's/\x1b\[[0-9;]*m//g'` is how a help page loses its colors.
TERMINAL_CONTROL_BYTE = re.compile("[\x1b\x9b\x9d]")
TERMINAL_CONTROL_SPELLED = re.compile(
    r"\\(?:0{0,2}33|0{0,2}23[35]|x1[bB]|x9[bBdD]|[uU]0*(?:1[bB]|9[bBdD])|[eE])"
)
INTERPRETS_ESCAPES = ("echo", "printf")

# Claude Code gives each session a scratch directory and tells the model to use it. Writes
# that land inside it are contained by construction: the path carries the session id, the
# directory dies with the session, and nothing reads from it afterwards. The shape below is
# the observed layout; `SH_AUTO_APPROVE_SCRATCH` replaces it with an exact directory.
SCRATCH_ENV = "SH_AUTO_APPROVE_SCRATCH"

# One path component that is not `..`, spelled only in characters the shell passes through
# untouched. Without the lookahead the trailing `(?:/COMPONENT)+` happily matches
# `scratchpad/../../escape.txt`; without the character class it matches a quoted
# `"../../x"` (a placeholder by now), a `$d` the shell fills in, and a `..*` the shell globs,
# each of which lands wherever it likes.
SCRATCH_COMPONENT = r"(?:/(?!\.\.?(?:/|$|[\s;|&)]))[A-Za-z0-9._@%+=,-]+)"
SCRATCH_PATH = (
    r"/tmp/claude-\d+/(?!\.\.?/)[A-Za-z0-9._-]+/[0-9a-fA-F-]{36}/scratchpad"
    + SCRATCH_COMPONENT
    + r"+"
)

# --------------------------------------------------------------------------------------
# Read scope
#
# Reading is what this module approves, and under a poisoned prompt the read is the attack:
# a credential printed to stdout lands in Claude's context, where the injected instruction
# is waiting for it. Two layers keep a read where it belongs.
#
# Layer B refuses a short list of known credential stores wherever their path appears -- any
# word of any command, before the operator tier is consulted -- because a program the module
# cannot read can still be told to open one: `shellcheck ~/.aws/credentials` echoes the
# lines it flags, `dig -f FILE` reads its queries from a file, and both pass on an operator
# rule. It is a denylist and is fragile the way denylists are, so it is the backstop and not
# the boundary.
#
# Layer A is the boundary, for the readers this module knows: a file operand must resolve
# inside the project, an `additionalDirectories` entry, or this session's scratch
# directory. Anything else, and anything the module cannot resolve, is not this module's to
# approve and falls through to the operator's own rules.
# --------------------------------------------------------------------------------------

# Relative to the home directory. Each is a directory or file whose contents are a secret or
# hand one out: cloud and VCS credentials, key material, package-registry tokens, database
# passwords, Claude Code's own credentials, and the shell histories that hold whatever was
# typed on a command line.
# TODO(decision): this hook only ever allows or stays silent, so refusing a credential read
# here stops the hook from approving it -- it does not stop Claude Code. `cat` is in Claude
# Code's built-in read-only set and runs without a prompt, and a native allow rule such as
# `Bash(shellcheck *)` approves its program whatever path it is given. What blocks the read:
#   * native `Read()` deny rules (evaluated even when a hook says allow), e.g. in
#     ~/.claude/settings.json: ~/.aws/sso/cache, ~/.aws/cli/cache, ~/.ssh/**,
#     ~/.config/gh, ~/.config/op, ~/.docker/config.json, ~/.terraform.d/credentials.tfrc.json,
#     ~/.pgpass, ~/.git-credentials, ~/.claude/.credentials.json, ~/.zsh_history
#   * narrowing broad native allow rules, such as `Bash(shellcheck *)`, `Bash(dig *)`,
#     `Bash(git log *)` or `Bash(git diff *)`
#   * or flipping this module's allow-or-silent invariant so layer B emits `deny`, which
#     the tests currently forbid
# TODO(option): read the operator's own `Read()` deny rules from all four settings files and
# refuse any operand that matches them, instead of keeping a second list here.
# TODO(verify): which programs Claude Code's native Read-deny matcher recognizes beyond the
# documented cat/head/tail/sed/tee. Probe: deny `Read(~/deny-probe/**)`, place a junk file
# there, and ask Claude to read it with jq, sort, diff, wc and grep.
CREDENTIAL_HOME_PATHS = (
    ".aws",
    ".ssh",
    ".gnupg",
    ".kube",
    ".azure",
    ".docker/config.json",
    ".config/gcloud",
    ".config/gh",
    ".config/op",
    ".config/hub",
    ".netrc",
    ".git-credentials",
    ".npmrc",
    ".pypirc",
    ".vault-token",
    ".pgpass",
    ".my.cnf",
    ".terraform.d/credentials.tfrc.json",
    ".claude/.credentials.json",
    ".claude.json",
    ".bash_history",
    ".zsh_history",
    ".psql_history",
    ".mysql_history",
    ".python_history",
    ".node_repl_history",
    ".lesshst",
)

# Absolute. `/root` is another user's home; the rest hold system credentials.
CREDENTIAL_SYSTEM_PATHS = ("/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/root")

# A process's environment and memory. `/proc/self/environ` is the hook's own environment,
# which is where the session's tokens live.
PROCESS_SECRETS = re.compile(r"^/proc/(?:self|thread-self|\d+)/(?:environ|mem|cmdline|auxv)\b")

# Paths that read nothing from disk.
DEVICE_READS = frozenset({"/dev/null", "/dev/stdin", "/dev/stdout", "/dev/stderr"})

# A redirection operator glued to its target, as in `2>~/x` or `<~/x`.
REDIRECTION_PREFIX = re.compile(r"^[0-9]*[<>&|]+")

# Characters after which a path's final text is left for the shell to decide.
PATH_SPECIAL = re.compile(r"[$*?\[{`]")

# The working directory Claude Code reports in the hook payload. Set by `main()`; when it is
# set, a relative operand must be in scope from there too.
_SESSION_CWD: str | None = None

# Variable assignment matching
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\+?=")

# `${var@P}` expands its value as a prompt string, and prompt expansion performs command
# substitution, so the payload need never contain `$(` itself. `${arr[@]}` is not this:
# a transformation is an `@` followed by an operator letter, not by `]`.
PARAMETER_TRANSFORM = re.compile(r"\$\{[^{}]*@[A-Za-z]")

# `${name=value}` and `${name:=value}` assign as a side effect of being expanded, so a command
# that only prints can still hand the next one a writing flag, or a new `PATH`.
# The other `${name:X...}` operators substitute without assigning and must not match:
# only `=`, optionally preceded by the `:` that also tests for empty, is an assignment.
PARAMETER_ASSIGN = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*(?:\[[^]{}]*\])?:?=")

# Arithmetic evaluates a variable's *value* as an expression, and an array subscript in that
# value runs the command substitution inside it: `x='a[$(touch PWNED)]'; echo $((x))` writes
# in bash and in zsh. So every place the shell evaluates arithmetic on something the module
# did not read is refused -- `$((...))` naming a variable (in `_skip_arithmetic`), `$[...]`,
# a subscript or a `${name:offset}` that is not a literal integer, and `${!name}`, which
# evaluates a subscript in the name it looks up. `[@]`, `[*]`, `[3]`, `${x:0:8}` and the
# `${!arr[@]}` key listing evaluate nothing and stay approved.
PARAM_NAME = r"(?:[A-Za-z_][A-Za-z0-9_]*|\d+|[@*#?$!-])"
ARITHMETIC_BRACKET = re.compile(r"\$\[")
SUBSCRIPT = re.compile(
    r"\$\{[#+]?[A-Za-z_][A-Za-z0-9_]*\[(?!(?:[@*]|-?\d+)\])"
    r"|\$[A-Za-z_][A-Za-z0-9_]*\[(?!(?:[@*]|-?\d+)\])"
)
SUBSTRING = re.compile(
    r"\$\{#?" + PARAM_NAME + r"(?:\[(?:[@*]|-?\d+)\])?:"
    r"(?![-=+?]|\s*-?\d+\s*(?::\s*-?\d+\s*)?\})"
)
INDIRECT = re.compile(r"\$\{!(?![A-Za-z_][A-Za-z0-9_]*(?:\[[@*]\]|[@*])\})")

# zsh is one of the 2 shells Claude Code runs these commands in (see the module docstring), and it
# has expansions bash does not. `${(e)x}` re-expands the value -- command substitution included --
# and any `${(...)` flag set is refused rather than read letter by letter. `${~x}` and `$~x`
# turn the value into a glob, and a zsh glob qualifier `*(e:cmd:)` runs a command.
ZSH_PARAMETER_FLAGS = re.compile(r"\$\{\s*\(")
ZSH_GLOB_SUBST = re.compile(r"\$\{?~")

# A `printf` conversion whose argument zsh evaluates as arithmetic: a numeric type, or any
# conversion taking its width or precision from an argument (`%*s`, `%.*f`).
PRINTF_NUMERIC = re.compile(
    r"%[-+ #0']*(?:\d+)?(?:\.\d*)?[diouxXeEfFgGaA]|%[-+ #0']*(?:\d*\*|\d*\.\*)"
)

# A field wider than this is not alignment:
# - `printf '%099999999d' 1` allocates 100 MB and prints them into Claude's context
# - `find -printf` takes the same widths
# A `*` takes the width from an argument, so a number above the cap is refused beside one.
PRINTF_WIDTH_CAP = 1000
PRINTF_WIDTH = re.compile(r"%[-+ #0']*(\d+)?(?:\.(\d+))?")
PRINTF_STAR = re.compile(r"%[-+ #0']*\d*\.?\*")
PRINTF_INTEGER_ARGUMENT = re.compile(r"[-+]?\d+")

# Text that is parameter expansions and nothing else, so that the shell supplies all of it.
# `$(` never survives the scan, so only the parameter forms are here.
EXPANSION_ONLY = re.compile(r"(?:\$[A-Za-z_][A-Za-z0-9_]*|\$\{[^{}]*\}|\$[0-9@*#?$!-])+")

# Bash opens a socket for a path under these, with no program involved. Only a redirection
# reaches them, and a redirection is refused already -- but a word that names one has no reading
# other than the one bash would give it.
# TODO: `PSEUDO_DEVICE` and `NETWORK_DEVICE` are the same pattern from the two sides of a
# merge. Keep `NETWORK_DEVICE`, whose check in `_classify` also sees redirect targets, and
# drop this one with its loop in `_check_command`.
PSEUDO_DEVICE = re.compile(r"/dev/(?:tcp|udp)/")

# The Bash 5.3 substitution forms, which spell no `$(` of their own.
BRACE_SUBSTITUTION = re.compile(r"\$\{\s*\||\$\{\s+[a-zA-Z0-9_]")

# The scanner below rewrites every quoted span, escape and command substitution to a placeholder
# of this shape, so that what reaches the lexer is unquoted shell syntax and nothing else.
# `\x01` is not a character a command can contain: one that does is refused rather than rewritten,
# so a placeholder can never be forged from the command text.
PLACEHOLDER_MARK = "\x01"
PLACEHOLDER = re.compile(r"\x01(\d+)\x01")

# A part is inert text, text the shell will still expand, or a command to run. The middle
# one exists because `"${x@P}"` is not a substitution the scanner can extract and is not
# inert either: what is quoted there is the `"`, and the expansion inside it runs anyway.
LITERAL = "literal"
DOUBLE_QUOTED = "double-quoted"
SUBSTITUTION = "substitution"
PROCESS_SUBSTITUTION = "process-substitution"

# Both substitution kinds run a command; `RUNS_A_COMMAND` is what must be recursed into,
# refused in a program-name position, and counted as work that was inspected.
RUNS_A_COMMAND = (SUBSTITUTION, PROCESS_SUBSTITUTION)

# What a substitution contributes to the word it sits in. A value the module never read
# cannot be argued about, so it must be text no validator can mistake for permission.
SUBSTITUTION_MARKER = "__substitution__"

# `$( $( ... ) )` is legal and pointless. The cap bounds the recursion rather than
# the nesting anyone writes.
MAX_SUBSTITUTION_DEPTH = 4

# Dangerous environment variables that must never be set (bare or prefix)
DANGEROUS_ENV_VARS = {
    "PATH",
    "BASH_ENV",
    "ENV",
    "CDPATH",
    "IFS",
    "SHELLOPTS",
    "BASHOPTS",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "GIT_EXTERNAL_DIFF",
    "GIT_CONFIG",
    "GIT_EXEC_PATH",
    "PYTHONPATH",
    "PYTHONHOME",
    "PERL5LIB",
    "RUBYLIB",
    "NODE_OPTIONS",
    "AWS_CONFIG_FILE",
    "CLOUDSDK_CONFIG",
    # Where a later command in the same session sends its traffic, and what it will
    # trust when it gets there. These are the ones normally spelled in lower case, and
    # the membership test upper-cases the name, so both spellings are covered.
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "FTP_PROXY",
    "NO_PROXY",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "CURL_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    # Where a later command looks for its configuration, and what runs before it
    "HOME",
    "TMPDIR",
    "PROMPT_COMMAND",
    "GLIBC_TUNABLES",
    "GCONV_PATH",
    "LOCPATH",
}

# `aws` read operations pattern
AWS_READ_OP = re.compile(r"^(?:describe|get|list|lookup|search|batch-get|help)\b|^help$")

# `aws` global options that take an argument (to avoid positional shift)
AWS_GLOBAL_OPTS_WITH_ARG = {
    "--profile",
    "--region",
    "--output",
    "--color",
    "--query",
    "--cli-read-timeout",
    "--cli-connect-timeout",
    "--user-agent",
}

# `aws` global options that decide where a signed request goes, what it will trust when it
# arrives, or what the argument list even is. A read verb is still a read; the credential
# it is read with is the operator's, and `--cli-input-json` replaces every other argument
# from a file this module never opened, so the verb it checked is not the verb that runs.
AWS_BLOCKED_OPTS = (
    "--endpoint-url",
    "--ca-bundle",
    "--no-verify-ssl",
    "--cli-input-json",
    "--cli-input-yaml",
)

# Options blocked for one service
AWS_BLOCKED_SERVICE_OPTS = {
    "ssm": (
        # Makes every `ssm get-parameter*` print a `SecureString` in plain text, and a Secrets
        # Manager secret too (read through the reserved `/aws/reference/secretsmanager/` path).
        # Without it, the same reads return ciphertext.
        "--with-decryption",
    )
}

# AWS operations that output files, mint credentials, or print a secret
AWS_BLOCKED_OPS = {
    "batch-get-secret-value",
    "get-object",
    "get-login-password",
    "get-secret-value",
    "get-session-token",
}

# Operations blocked for one service only, because the verb alone is the read everywhere else
AWS_BLOCKED_SERVICE_OPS = {
    # `aws configure get` prints a key from the credentials file.
    # It also refuses the harmless `aws configure get region`, which costs a prompt.
    ("configure", "get")
}

# `gcloud` verbs that strictly only read
GCLOUD_READ_VERBS = {
    "analyze-iam-policy",
    "describe",
    "get",
    "get-ancestors",
    "get-iam-policy",
    "get-value",
    "list",
    "lookup",
    "search-all-iam-policies",
    "search-all-resources",
    "test-iam-permissions",
    "version",
}

# `gcloud` global flags that move where the call goes or who it goes as. A named
# configuration can carry `api_endpoint_overrides`, so `--configuration` is an endpoint
# flag spelled indirectly, and the credential flags run the read as somebody else.
GCLOUD_BLOCKED_OPTS = (
    "--configuration",
    "--account",
    "--impersonate-service-account",
    "--access-token-file",
    "--credential-file-override",
    "--billing-project",
)

# `gcloud` mutating, executing, or credential verbs that must be refused
GCLOUD_BLOCKED_VERBS = {
    "add",
    "add-iam-policy-binding",
    "attach-disk",
    "auth",
    "call",
    "copy-files",
    "cp",
    "create",
    "delete",
    "deploy",
    "detach-disk",
    "disable",
    "enable",
    "grant",
    "import",
    "invoke",
    "login",
    "move",
    "patch",
    "print-access-token",
    "publish",
    "remove",
    "remove-iam-policy-binding",
    "reset",
    "restart",
    "restore",
    "resume",
    "revoke",
    "rm",
    "run",
    "scp",
    "set",
    "set-iam-policy",
    "ssh",
    "start",
    "stop",
    "submit",
    "suspend",
    "sync",
    "terminate",
    "undelete",
    "update",
    "upload",
}

# An `awk` string literal, which is the one place in a program where `>` and `|` are only
# characters. Taken out before either rule below reads the program.
JQ_STRING = re.compile(r'"(?:[^"\\]|\\.)*"')
AWK_STRING = re.compile(r'"(?:\\.|[^"\\])*"')

# A `print` or `printf` statement is the only thing in `awk` that can redirect to a file or
# pipe to a shell, and a statement ends at `;`, `{` or `}`. `||` is the logical or, which
# is how a line selector is spelled; `|&` is `gawk`'s coprocess, which is not.
AWK_OUTPUT = re.compile(r"\b(?:print|printf)\b[^;{}]*(?:>|(?<!\|)\|(?!\|))")

# `gawk`'s `@include` and `@load` are `--include` and `--load` written inside the program,
# where the flag table cannot see them: one pulls in another program file, the other a
# shared object. Neither is a flag, so neither is refused by refusing the flags.
AWK_EXTENSION = re.compile(r"@\s*(?:include|load|namespace)\b")

# `sed` script commands that can neither write a file nor run a program. `w`, `W`, `r`,
# `R`, `e`, `F` and `v` are left out on purpose, and so are the branch commands `b`, `t`,
# `T`, `:` and the `{` `}` group, whose labels would need a parser of their own to read.
SED_SAFE_COMMANDS = set("=DGHNPQdghlnpqsxyz")

# Git options that write a file or run a program: `--ext-diff`, `--textconv` and `--filters`
# run whatever the repository's own config or `.gitattributes` names, and
# `--open-files-in-pager` runs the program it is given. The `--no-` spellings are the safe
# ones and match none of these.
GIT_EXECUTION_OPTS = (
    "--output",
    "--exec-path",
    "--open-files-in-pager",
    "--ext-diff",
    "--textconv",
    "--filters",
    "--upload-pack",
    "--receive-pack",
)

# Git options that point it at a repository whose config this module never read
GIT_LOCATION_OPTS = ("--git-dir", "--work-tree", "--namespace")

# Exact options that are also a prefix of one above, which git reads as themselves:
# `git grep --text` and `git diff --text` treat binary files as text.
GIT_EXACT_SAFE_OPTS = frozenset({"--text"})

# Git subcommands that read repository state
GIT_READ_SUBCOMMANDS = {
    "blame",
    "cat-file",
    "check-ignore",
    "describe",
    "diff",
    "grep",
    "log",
    "ls-files",
    "ls-tree",
    "rev-parse",
    "shortlog",
    "show",
    "show-ref",
    "status",
    "tag",
    "worktree",
}


class NotReadOnly(Exception):
    """Raised when any command component is not provably read-only."""


class NoOpinion(NotReadOnly):
    """Raised where the module has no reading of the command rather than a bad one.

    The distinction is what bounds the second tier. An operator's allow rule may supply a
    program this module has never heard of -- ``gh``, ``shellcheck``, a script in ``scripts/``
    -- because there the module is admitting it cannot tell. It may not overrule a
    validator that read the command and found a write: ``git diff --output=`` and
    ``find . -delete`` stay refused whatever the rule file says, so a broad rule cannot
    quietly cancel a finding.
    """


def _skip_single_quoted(text: str, index: int) -> int:
    """``index`` is the character after the opening quote; return the index after the close.

    Nothing is special inside ``'...'``, a backslash least of all, which is why this is the
    one span the scanner can find with a search rather than a walk.
    """
    end = text.find("'", index)
    if end < 0:
        raise NotReadOnly("unbalanced single quote")
    return end + 1


def _skip_double_quoted(text: str, index: int) -> int:
    """The same, for ``"..."``, whose contents can still run a command."""
    length = len(text)
    while index < length:
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == '"':
            return index + 1
        if char == "`":
            raise NotReadOnly("backtick command substitution")
        if text.startswith("$((", index):
            index = _skip_arithmetic(text, index + 3)
            continue
        if text.startswith("$(", index):
            index = _skip_substitution(text, index + 2)
            continue
        index += 1
    raise NotReadOnly("unbalanced double quote")


def _skip_substitution(text: str, index: int) -> int:
    """``index`` is the character after ``$(``; return the index after the matching ``)``.

    The body is a command in its own right, so its quoting starts over: a ``)`` inside
    ``'...'`` or ``"..."`` does not close the substitution, and ``$(echo 'a)b')`` is one span.
    Counting parentheses without reading quotes is what would end the span early and
    leave the rest of the body outside anything this module inspects.
    """
    length, depth = len(text), 1
    while index < length:
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == "'":
            index = _skip_single_quoted(text, index + 1)
            continue
        if char == '"':
            index = _skip_double_quoted(text, index + 1)
            continue
        if char == "`":
            raise NotReadOnly("backtick command substitution")
        if text.startswith("$((", index):
            index = _skip_arithmetic(text, index + 3)
            continue
        if text.startswith("$(", index):
            index = _skip_substitution(text, index + 2)
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    raise NotReadOnly("unterminated command substitution")


def _skip_arithmetic(text: str, index: int) -> int:
    """``index`` is the character after ``$((``; return the index after the matching ``))``.

    Arithmetic may not carry an expansion: the body of ``$(($(id)))`` has to stay visible to
    the substitution scan rather than be swallowed here. Nor may it name a variable, because
    arithmetic evaluates the variable's value as an expression of its own, and a subscript in
    that value runs the substitution inside it -- ``x='a[$(touch PWNED)]'; echo $((x))``.
    """
    length, depth = len(text), 2
    while index < length:
        char = text[index]
        if char == "$":
            raise NotReadOnly("expansion inside arithmetic")
        if char.isalpha() or char == "_":
            raise NotReadOnly("variable inside arithmetic")
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    raise NotReadOnly("unterminated arithmetic expansion")


def _scan_double_quoted(text: str, index: int, emit) -> int:
    """Scan a ``"..."`` span at word level, emitting its literal runs and substitutions.

    Each piece is emitted separately and the placeholders land side by side in the same
    word, so ``"a$(id)b"`` stays one word and its command is still reachable.
    """
    buffer: list[str] = []
    length = len(text)
    while index < length:
        char = text[index]
        if char == "\\" and index + 1 < length:
            following = text[index + 1]
            if following == "\n":  # a line continuation, inside quotes as well
                index += 2
                continue
            if following in '$`"\\':
                buffer.append(following)
                index += 2
                continue
        if char == '"':
            emit(DOUBLE_QUOTED, "".join(buffer))
            return index + 1
        if char == "`":
            raise NotReadOnly("backtick command substitution")
        if text.startswith("$((", index):
            index = _skip_arithmetic(text, index + 3)
            buffer.append("0")
            continue
        if text.startswith("$(", index):
            end = _skip_substitution(text, index + 2)
            emit(DOUBLE_QUOTED, "".join(buffer))
            buffer.clear()
            emit(SUBSTITUTION, text[index + 2 : end - 1])
            index = end
            continue
        buffer.append(char)
        index += 1
    raise NotReadOnly("unbalanced double quote")


def _scan(command: str) -> tuple[str, list[tuple[str, str]]]:
    """Separate what the shell will read as syntax from what it will pass through.

    Returns the command with every quoted span, escape, arithmetic expansion and command
    substitution replaced by a placeholder, and the table those placeholders index. What
    remains is unquoted syntax: every ``>``, ``|``, ``;`` and ``(`` left in it is one bash will
    act on, and every one that is quoted is inside the table instead.

    This is what the lexer alone cannot tell anyone. ``posix=True`` strips the quotes and
    hands back a token identical to an unquoted one, so ``sed 's|a|b|'`` and a trailing pipe
    are the same object by the time ``_segments`` sees them -- and an ``awk`` program that
    compares with ``>`` is indistinguishable from a redirection. Resolving quoting first is
    what lets both be read correctly rather than both be refused.
    """
    parts: list[tuple[str, str]] = []
    out: list[str] = []
    index, length = 0, len(command)

    def emit(kind: str, value: str) -> None:
        parts.append((kind, value))
        out.append(f"{PLACEHOLDER_MARK}{len(parts) - 1}{PLACEHOLDER_MARK}")

    while index < length:
        char = command[index]
        if char == "\\":
            if index + 1 >= length:
                raise NotReadOnly("trailing backslash")
            if command[index + 1] == "\n":  # a line continuation joins the two lines
                index += 2
                continue
            emit(LITERAL, command[index + 1])
            index += 2
            continue
        if char == "'":
            end = _skip_single_quoted(command, index + 1)
            emit(LITERAL, command[index + 1 : end - 1])
            index = end
            continue
        if char == '"':
            index = _scan_double_quoted(command, index + 1, emit)
            continue
        if char == "`":
            raise NotReadOnly("backtick command substitution")
        if command.startswith("$'", index) or command.startswith('$"', index):
            raise NotReadOnly("ANSI-C or locale quoting")
        if command.startswith("$((", index):
            end = _skip_arithmetic(command, index + 3)
            emit(LITERAL, "0")
            index = end
            continue
        if command.startswith("$(", index):
            end = _skip_substitution(command, index + 2)
            emit(SUBSTITUTION, command[index + 2 : end - 1])
            index = end
            continue
        if command.startswith(">(", index):
            # An output process substitution is a command in a redirect position: it both
            # runs a program and receives a stream. The input form below only runs one.
            raise NotReadOnly("output process substitution")
        if command.startswith("<(", index):
            end = _skip_substitution(command, index + 2)
            emit(PROCESS_SUBSTITUTION, command[index + 2 : end - 1])
            index = end
            continue
        out.append(char)
        index += 1

    return "".join(out), parts


def _expand(token: str, parts: list[tuple[str, str]]) -> str:
    """The word bash will hand the program, with substitutions standing in for themselves."""

    def replace(match: re.Match) -> str:
        kind, value = parts[int(match.group(1))]
        return SUBSTITUTION_MARKER if kind in RUNS_A_COMMAND else value

    return PLACEHOLDER.sub(replace, token)


def _carries_substitution(token: str, parts: list[tuple[str, str]]) -> bool:
    """Whether any part of this word is produced by running a command."""
    return any(parts[int(index)][0] in RUNS_A_COMMAND for index in PLACEHOLDER.findall(token))


def _carries_live_glob(token: str) -> bool:
    """Whether the shell will expand a wildcard in this word.

    `find . -name '*.md'` and `find . -name *.md` are the same characters by the time a
    validator sees them and are not the same command: in the first the shell passes the
    star through and `find` does the matching, in the second the shell has already
    replaced the word with whatever the directory held -- which is how an operand becomes
    a flag. Only the unquoted one is a hazard, and only the reduced token can tell them
    apart, because quoting put the quoted one in the parts table.
    """
    return any(char in "*?" for char in PLACEHOLDER.sub("", token))


# A brace expansion the shell performs before the command runs: `{a,b}`, `{a,}`, `{1..3}`,
# `a{b,c}d`. It needs a comma or a `..` range inside unnested braces; `{a}`, `{}` and
# `a{}b` are left literal by bash and do not match. The `(?<!\$)` lookbehind keeps a
# parameter expansion -- `${x:-a}`, `${x:+a,b}` -- out, since its `{` follows a `$`.
BRACE_EXPANSION = re.compile(r"(?<!\$)\{[^{}]*(?:,[^{}]*|\.\.[^{}]*)+\}")


def _carries_brace_expansion(token: str) -> bool:
    """Whether the shell will split this word into several by brace expansion.

    The same hazard as `_carries_live_glob`, in the other expansion `_scan` passes
    through: `cat {AGENTS,extra}.md` is one word to an operand check and two files to the
    program, the second placed wherever the brace says. Only the reduced token is tested,
    so a quoted `'{a,b}'` -- which bash leaves as one literal word -- sits in the parts
    table as a placeholder and is not matched.
    """
    return BRACE_EXPANSION.search(PLACEHOLDER.sub("", token)) is not None


# A word that is exactly one *quoted* expansion of `name`, written `"$name"` or
# `"${name}"`, with nothing glued on. Three conditions, each load-bearing:
#
# * **Quoted.** An unquoted `$f` is re-split and re-globbed at the point of use, so even a
#   literal loop value like `*.json` can expand into filenames there, one of which could be
#   `-o`. The quoted form cannot: it is exactly the string `f` holds. The whole word being a
#   single placeholder is how "quoted" shows up after `_scan`.
# * **One expansion, nothing glued.** `"${f}-x"` and `"$f$g"` are handled by
#   `_word_the_shell_decides` already (the suffix idiom), and are not this exemption's job.
# * **A name a literal-list loop binds**, which is the caller's `names` set.
def _is_bare_expansion_of(token: str, parts: list[tuple[str, str]], names: frozenset[str]) -> bool:
    match = PLACEHOLDER.fullmatch(token)
    if match is None:
        return False  # not a single quoted word; an unquoted `$f` fails here
    kind, _ = parts[int(match.group(1))]
    if kind != DOUBLE_QUOTED:
        return False
    expanded = _expand(token, parts)
    return any(expanded == f"${name}" or expanded == "${" + name + "}" for name in names)


# A `for name in word...` header whose list is entirely literal words that do not begin
# with `-`. When that holds, every value `name` can take is spelled out in the command and
# none is a flag, so a later bare `"$name"` cannot arrive as one -- which is the single
# case `_word_the_shell_decides` may exempt. The header is read before its body because a
# segment-by-segment pass has already discarded it (`_strip_structure` returns `[]` for a
# loop head), so the safe names are collected here and passed down.
#
# The list must be literal to count: a `$(...)` body, a `${arr[@]}`, or any word the shell
# still has to build says nothing about what `name` will hold and yields no exemption. A
# `name` that any header binds unsafely is removed, so one safe and one unsafe binding of
# the same name does not leave it exempt.
def _safe_loop_names(segments: list[list[str]], parts: list[tuple[str, str]]) -> frozenset[str]:
    safe: set[str] = set()
    unsafe: set[str] = set()
    for segment in segments:
        if len(segment) < 3 or segment[0] not in WORD_LIST_HEADS or segment[2] != "in":
            continue
        name = _expand(segment[1], parts)
        values = segment[3:]
        if values and all(_value_is_literal_non_flag(word, parts) for word in values):
            safe.add(name)
        else:
            unsafe.add(name)
    return frozenset(safe - unsafe)


# A use of `name` that the shell word-splits into the argument list: `$name`, `${name}`,
# and the zsh `${=name}`. All three split an unquoted value into several words, so all
# three are spliceable when the value is one this module resolved. A quoted `"$name"` is
# not here -- it is a single word and is handled by the loop-name path -- and neither is a
# glued `${name}x`, which is one word too.
# TODO(zsh): under zsh only `${=name}` word-splits; a bare `$name` or `${name}` is one word
# (SH_WORD_SPLIT is off by default). The splice checks the split words, which is the bash
# reading. A differential test under zsh should confirm the joined word never passes where
# the split words were refused.
SPLICE_USE = re.compile(r"^\$\{=?([A-Za-z_][A-Za-z0-9_]*)\}$|^\$([A-Za-z_][A-Za-z0-9_]*)$")


def _splice_name(token: str, splice_vars: dict[str, list[str]]) -> str | None:
    """The variable name this token splices in, or None.

    A bare, unquoted `$name`, `${name}` or `${=name}` whose `name` has a resolved literal
    value. A quoted use is a placeholder, not this literal text, so it never matches here
    and stays with the loop-name path. A glued `${name}x` is not a whole-word match either.
    """
    match = SPLICE_USE.match(token)
    if match is None:
        return None
    name = match.group(1) or match.group(2)
    return name if name in splice_vars else None


def _literal_assignments(
    segments: list[list[str]], parts: list[tuple[str, str]]
) -> dict[str, list[str]]:
    """Variables assigned a fully literal value in a sibling segment, as split words.

    `_p='--profile admin --region us-east-1'` puts those three flags in `_p`, and because
    the assignment is in the same command as the `${=_p}` that uses it, the value is right
    here to read. The value counts as literal only when nothing in it is left for the shell
    to decide -- no `$(...)`, no nested `$var`, no glob, no brace -- so what it splits into
    is fixed and checkable. A name assigned more than once, or once unsafely, is dropped,
    so an attacker cannot shadow a safe value with a later dangerous one.

    The split is on the shell's default IFS (space, tab, newline), which is what an
    unquoted expansion undergoes. That is an approximation -- a custom `IFS` would split
    differently -- but a command that reset `IFS` carries that assignment too, and an
    `IFS=` assignment is refused by `_strip_structure` before this runs.
    """
    assigned: dict[str, list[str]] = {}
    seen_unsafe: set[str] = set()
    for segment in segments:
        for word in segment:
            if not ASSIGNMENT.match(word):
                break  # assignments come first in a segment; a non-assignment ends them
            name = word.split("=", 1)[0].rstrip("+")
            value_token = word[len(word.split("=", 1)[0]) + 1 :]
            expanded_value = _expand(value_token, parts)
            if (
                _carries_substitution(value_token, parts)
                or _carries_live_glob(value_token)
                or _carries_brace_expansion(value_token)
                or _has_bare_variable(value_token, parts)
                # Defense in depth: word-splitting does not re-run the parser, so a `;` in
                # the value is an inert argument rather than a new command -- but a value
                # that carries one was likely meant as a command, and splicing it is too
                # sharp an edge to auto-approve. A value destined for the argument list is
                # plain flags and operands or it is not spliced.
                or any(ch in expanded_value for ch in ";|&<>`()$\n")
            ):
                seen_unsafe.add(name)
                continue
            if name in assigned or name in seen_unsafe:
                seen_unsafe.add(name)  # a second binding: too ambiguous to trust either
                assigned.pop(name, None)
                continue
            # Bash expands a leading tilde in an assignment's value, so `x=~/a` holds the
            # home-relative path, not the two characters. Storing the expansion is what lets
            # the read scope see where `"$x"` really points.
            if value_token.startswith("~"):
                expanded_value = os.path.expanduser(expanded_value)
            assigned[name] = expanded_value.split()
    return {n: v for n, v in assigned.items() if n not in seen_unsafe}


def _has_bare_variable(token: str, parts: list[tuple[str, str]]) -> bool:
    """Whether the value itself contains an unresolved `$var`, in or out of quotes.

    A value like `--profile $other` cannot be spliced, because `$other` is a word this
    module never read; the splice would check `--profile` and a placeholder, not the real
    second flag. Both the bare `$x` left in the reduced token and a `$x` inside a
    double-quoted part count.
    """
    if "$" in PLACEHOLDER.sub("", token):
        return True
    return any(
        kind == DOUBLE_QUOTED and "$" in value
        for index in PLACEHOLDER.findall(token)
        for kind, value in [parts[int(index)]]
    )


# Stands for one directory entry's name: no `/`, never `.` or `..`. Only the read scope
# uses it, to say "some file inside this directory"; it never exempts a word from the flag
# check, because a directory can hold a file called `-rf`.
PATH_COMPONENT = "\x02entry\x02"

# A command substitution whose output is bare directory-entry names: `ls`, or `ls` with
# relative directory operands and only the flags that change layout, never `-a`.
LISTING_BODY = re.compile(r"^\s*ls(?:\s+-1)?(?:\s+[A-Za-z0-9_./-]+)*\s*$")


def _loop_value_shapes(token: str, parts: list[tuple[str, str]]) -> list[str] | None:
    """What one `for`-list word contributes to the variable, for the read scope.

    A literal word is itself. An unquoted glob is a name inside its literal directory. A
    `$(ls ...)` is a bare name. Anything else -- a substitution with another body, a
    parameter expansion, a glob that could match `.` or `..` -- is None: unresolvable.
    """
    expanded = _expand(token, parts)
    whole = PLACEHOLDER.fullmatch(token)
    if whole is not None and parts[int(whole.group(1))][0] == SUBSTITUTION:
        body = parts[int(whole.group(1))][1]
        if LISTING_BODY.match(body) and not re.search(r"\s-[A-Za-z]*a", body) and ".." not in body:
            return [PATH_COMPONENT]
        return None
    if _carries_substitution(token, parts) or _has_bare_variable(token, parts):
        return None
    if _carries_brace_expansion(token):
        return None
    if _carries_live_glob(token):
        head = PATH_SPECIAL.split(expanded, 1)[0]
        directory, _, stem = head.rpartition("/")
        if stem.startswith(".") or expanded.startswith(("/", "~")) or ".." in directory.split("/"):
            return None
        return [f"{directory}/{PATH_COMPONENT}" if directory else PATH_COMPONENT]
    return [expanded]


def _literal_loop_values(
    segments: list[list[str]], parts: list[tuple[str, str]]
) -> dict[str, list[str]]:
    """The values each `for` variable can take, for resolving it inside a path.

    Wider than `_safe_loop_names`: a glob or `$(ls)` list resolves here, so `"$f"` can be
    placed inside a directory, but it is never a reason to exempt `"$f"` from the flag check.
    A name bound by two loops, or by a loop whose list is unresolvable, is left out.
    """
    values: dict[str, list[str]] = {}
    unresolvable: set[str] = set()
    for segment in segments:
        if len(segment) < 3 or segment[0] not in WORD_LIST_HEADS or segment[2] != "in":
            continue
        name = _expand(segment[1], parts)
        shapes: list[str] = []
        for word in segment[3:]:
            shape = _loop_value_shapes(word, parts)
            if shape is None:
                unresolvable.add(name)
                break
            shapes.extend(shape)
        else:
            if name in values:
                unresolvable.add(name)
            values[name] = shapes
    return {name: v for name, v in values.items() if name not in unresolvable}


def _value_is_literal_non_flag(token: str, parts: list[tuple[str, str]]) -> bool:
    """A single loop-list value that the operator wrote out and that is not a flag.

    It must carry no expansion, substitution, glob or brace the shell would still act on --
    anything that leaves the final text up to the shell disqualifies it -- and the literal
    it does spell must not begin with `-`.
    """
    if _word_the_shell_decides(token, parts) or _carries_substitution(token, parts):
        return False
    if _carries_live_glob(token) or _carries_brace_expansion(token):
        return False
    return not _expand(token, parts).startswith("-")


def _word_the_shell_decides(token: str, parts: list[tuple[str, str]]) -> bool:
    """Whether the shell, not the operator, decides what kind of word this is.

    Every flag table reads a word that is already complete. Two shapes are not:

    * a word carrying a command substitution, because the body ran and its output is
        this word -- ``sort "$(echo -o)" PWNED`` is ``sort -o PWNED`` and says so nowhere;
    * a word that is nothing but parameter expansions, because its whole text, leading
        ``-`` included, was set by some earlier command in the same shell -- ``sort ${o}``
        is whatever ``o`` holds.

    A parameter glued to literal text is neither, and that is deliberate: the everyday idioms
    are ``"${_p}-example-project"``, a key with a suffix, and ``--project="${p}"``, a flag
    whose value is a parameter. Refusing those buys nothing -- the option is already spelled
    out in the command -- and costs every such loop.
    The residual is narrow and real: ``"${o}-x"`` is still a flag if ``o`` begins with one.
    """
    if _carries_substitution(token, parts):
        return True

    index, length, expansions = 0, len(token), False
    while index < length:
        match = PLACEHOLDER.match(token, index)
        if match is None:
            end = token.find(PLACEHOLDER_MARK, index)
            chunk = token[index : length if end < 0 else end]
            if not EXPANSION_ONLY.fullmatch(chunk):
                return False
            expansions = True
            index = length if end < 0 else end
            continue
        kind, value = parts[int(match.group(1))]
        # Single quotes and a backslash make the text literal; double quotes do not, and
        # ``"${o}"`` expands exactly as ``${o}`` does.
        if value:
            if kind != DOUBLE_QUOTED or not EXPANSION_ONLY.fullmatch(value):
                return False
            expansions = True
        index = match.end()
    return expansions


def _bundled_short(arg: str, letters: str, value_letters: str = "") -> bool:
    """Whether a short-option cluster carries one of ``letters``.

    ``-ni`` is one argument whose second letter is the write flag, so a table keyed on the
    argument as a whole does not see it and a ``startswith('-i')`` guard does not fire.
    Only the leading run of letters is read: an option that takes an inline value ends
    the cluster, so ``sort -k1,1`` is ``k`` and not an ``o`` hiding behind a digit.

    ``value_letters`` names the options whose value can be attached *letters*, which a
    non-letter test cannot see the end of: ``date -Iseconds`` is ``-I`` with the value
    ``seconds``, not ``-I -s ...``, and ``sort -to`` is ``-t`` with the separator ``o``.
    The cluster stops after one of those. A caller that passes none is saying it has none.
    """
    if not arg.startswith("-") or arg.startswith("--"):
        return False
    cluster = ""
    for char in arg[1:]:
        if not char.isalpha():
            break
        cluster += char
        if char in value_letters:
            break
    return any(letter in cluster for letter in letters)


def _tokenize(command: str) -> list[str]:
    """Tokenize command into shell words with bash-aligned punctuation and comments.

    The input is the reduced command, so there is no quoting left to interpret and the
    lexer's only remaining job is to split on whitespace and on punctuation, exactly as
    bash does.
    """
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    # Do not let shlex drop comments mid-token; '#' must be handled safely
    lexer.commenters = ""
    try:
        return list(lexer)
    except ValueError as exc:
        raise NotReadOnly(f"unparseable syntax: {exc}") from exc


def _segments(tokens: list[str]) -> list[list[str]]:
    """Split token stream into simple commands, strictly rejecting invalid punctuation."""
    out: list[list[str]] = [[]]
    for token in tokens:
        # Check if the token consists purely of punctuation characters
        if set(token).issubset(PUNCTUATION_CHARS):
            if token in SEPARATORS:
                out.append([])
            else:
                # Any punctuation run not matching exact separators (; | && || & |& \n)
                # is a redirection, subshell, or glued syntax (e.g. ';(', ';>', '<>', '&>>')
                raise NotReadOnly(f"disallowed punctuation or redirection: {token}")
        elif any(c in "<>" for c in token) or token.endswith(("&", "|", ";")):
            raise NotReadOnly(f"redirection or separator inside token: {token}")
        else:
            out[-1].append(token)
    return [segment for segment in out if segment]


def _strip_structure(words: list[str]) -> list[str]:
    """
    Strip loop control structure, rejecting dangerous environment variables and prefix assignments.
    """
    index = 0
    while index < len(words):
        word = words[index]
        if word in ("case", "select"):
            raise NotReadOnly(f"unsupported shell control structure: {word}")
        if word in WORD_LIST_HEADS:
            return []  # 'for' loop variable declarations are harmless data
        if word in STRUCTURE:
            index += 1
            continue
        if ASSIGNMENT.match(word):
            var_name = word.split("=", 1)[0].rstrip("+")
            # Refuse dangerous environment variables
            if (
                var_name.upper() in DANGEROUS_ENV_VARS
                or var_name.startswith(("LD_", "GIT_", "BASH_", "AWS_", "CLOUDSDK_"))
                or var_name != var_name.lower()
            ):
                # TODO(decision): `while IFS= read -r line; do ...; done` prompts here. An
                # *empty* `IFS=` prefixed to one command is scoped to that command and can only
                # reduce word-splitting, so it could be allowed; `read` itself only assigns
                # variables and could join READ_ONLY. A `read` variable stays unresolvable, so
                # it still prompts in a flag or file position.
                raise NotReadOnly(f"refused environment variable assignment: {var_name}")
            # Refuse prefix environment assignments before command execution
            if index + 1 < len(words) and not ASSIGNMENT.match(words[index + 1]):
                raise NotReadOnly(f"environment variable prefix on command: {word}")
            index += 1
            continue
        break
    return words[index:]


def _skip_sed_delimited(script: str, index: int, delimiter: str) -> int:
    """Advance past the next unescaped ``delimiter``, starting from inside the section."""
    length = len(script)
    while index < length:
        if script[index] == "\\":
            index += 2
            continue
        if script[index] == delimiter:
            return index + 1
        index += 1
    raise NotReadOnly("sed unterminated expression")


def _skip_sed_address(script: str, index: int) -> int:
    """Advance past one address, or return ``index`` unchanged when there is none."""
    length = len(script)
    if index >= length:
        return index
    char = script[index]
    if char.isdigit():
        while index < length and script[index].isdigit():
            index += 1
        if index < length and script[index] == "~":  # GNU `first~step`
            index += 1
            while index < length and script[index].isdigit():
                index += 1
        return index
    if char == "$":
        return index + 1
    if char == "/":
        return _skip_sed_delimited(script, index + 1, "/")
    if char == "\\":  # `\%regexp%`, with any character as the delimiter
        if index + 1 >= length:
            raise NotReadOnly("sed truncated address")
        return _skip_sed_delimited(script, index + 2, script[index + 1])
    return index


def _scan_sed_script(script: str) -> None:
    """Walk a ``sed`` script command by command, allowing only what cannot write or execute.

    An allowlist, because the denylist this replaces searched for ``w``, ``r`` or ``e`` after a
    numeric address, and ``sed`` accepts many more address forms than that. Every one of
    ``/re/w out``, ``/a/,/b/w out``, ``1!w out``, ``\\%re%w out`` and ``2d;/re/w out`` walked past
    it, and ``/re/e cmd`` runs a program rather than merely writing a file.
    """
    index, length, commands = 0, len(script), 0
    while index < length:
        char = script[index]
        if char in " \t\n;":
            index += 1
            continue
        if char == "#":
            raise NotReadOnly("sed comment")

        after = _skip_sed_address(script, index)
        if after > index:
            index = after
            while index < length and script[index] in "IM":
                index += 1
            while index < length and script[index] in " \t":
                index += 1
            if index < length and script[index] == ",":
                index += 1
                while index < length and script[index] in " \t":
                    index += 1
                second = _skip_sed_address(script, index)
                if second == index:
                    raise NotReadOnly("sed range with no second address")
                index = second
                while index < length and script[index] in "IM":
                    index += 1
        while index < length and script[index] in " \t!":
            index += 1
        if index >= length:
            raise NotReadOnly("sed address with no command")

        command = script[index]
        index += 1
        if command not in SED_SAFE_COMMANDS:
            raise NotReadOnly(f"sed command: {command}")

        if command in "sy":
            if index >= length:
                raise NotReadOnly("sed substitution with no delimiter")
            delimiter = script[index]
            if delimiter.isalnum() or delimiter in "\\\n":
                raise NotReadOnly(f"sed delimiter: {delimiter}")
            index = _skip_sed_delimited(script, index + 1, delimiter)
            index = _skip_sed_delimited(script, index, delimiter)
            start = index
            while index < length and script[index] not in ";\n":
                index += 1
            flags = script[start:index].strip()
            # `w` names a file and `e` runs the replacement as a command; neither is here
            allowed = "gpiImM0123456789" if command == "s" else ""
            if not set(flags) <= set(allowed):
                raise NotReadOnly(f"sed {command} flags: {flags}")
        else:
            start = index
            while index < length and script[index] not in ";\n":
                index += 1
            argument = script[start:index].strip()
            if argument and not argument.isdigit():
                raise NotReadOnly(f"sed argument to {command}: {argument}")
        commands += 1

    if commands == 0:
        raise NotReadOnly("empty sed script")


# sed short options whose letter takes a value, so everything after one in a bundle is
# that value rather than another option.
SED_VALUE_LETTERS = "efil"


def _bundled_shorts(arg: str) -> str:
    """The option letters bash will hand the program as one bundled short argument.

    `-ni` is not `-i` and does not start with it, which is how an in-place edit gets past
    a table keyed on whole arguments -- the reason this exists. Walking stops at the first
    letter that consumes a value, because everything after it is that value: in `sed -to`
    the `o` is the separator argument to `-t`, not a second flag, and reading it as one
    would refuse a command that writes nothing.
    """
    if not arg.startswith("-") or arg.startswith("--") or arg == "-":
        return ""
    letters: list[str] = []
    for letter in arg[1:]:
        letters.append(letter)
        if letter in SED_VALUE_LETTERS:
            break
    return "".join(letters)


def _check_sed(args: list[str], live_globs: list[bool]) -> None:
    """Validate sed: every script is read, and operands are files it may only read.

    Reading a file is what sed is for, so refusing every operand -- which left `sed` usable
    only inside a pipeline -- was never the rule this module wanted. What has to hold is
    that no *script* writes and no *flag* turns the read into an edit, and both are checked
    here: `-i` and `-f` are refused by name, and every script reaches `_scan_sed_script`,
    including the second one in `-e A -e B`, which the old operand count silently skipped.
    """
    for index, arg in enumerate(args):
        if arg.startswith(("-i", "--in-place", "-f", "--file")) or arg in ("-f", "--file"):
            raise NotReadOnly(f"sed file/in-place argument: {arg}")
        bundled = _bundled_shorts(arg)
        if "i" in bundled or "f" in bundled:
            raise NotReadOnly(f"sed file/in-place flag bundled into: {arg}")
        if live_globs[index]:
            raise NotReadOnly("unquoted glob operand in sed")

    # Every value-taking option consumes its value wherever it sits, so that no word sed
    # reads as a script can be mistaken here for a file. `sed -ne 'w PWNED' -e p f` is the
    # case that matters: the bundle ends in `e`, so `w PWNED` is a script, and treating it
    # as an operand would leave it unscanned while the `-e p` after it passed for the script.
    scripts: list[str] = []
    operands: list[str] = []
    index = 0
    while index < len(args):
        arg = args[index]
        following = args[index + 1] if index + 1 < len(args) else ""
        if arg in ("-e", "--expression"):
            scripts.append(following)
            index += 2
            continue
        if arg in ("-l", "--line-length"):
            index += 2
            continue
        if arg.startswith("--expression="):
            scripts.append(arg[len("--expression=") :])
        elif arg.startswith("--"):
            pass
        elif arg.startswith("-") and arg != "-":
            cluster = _bundled_shorts(arg)
            value = arg[1 + len(cluster) :]
            if cluster.endswith(("e", "l")) and not value:
                value = following
                index += 1
            if cluster.endswith("e"):
                scripts.append(value)
        else:
            operands.append(arg)
        index += 1

    if not scripts:
        if not operands:
            raise NotReadOnly("sed with no script")
        scripts.append(operands.pop(0))

    for script in scripts:
        _scan_sed_script(script)


def _check_awk(args: list[str]) -> None:
    """
    Validate ``awk``/``gawk``: stream computation only, no extensions, program files, or shell-outs.

    Reading the program rather than searching it for characters is what separates
    ``length($0)>100`` from ``print > "out"``. In ``awk``'s grammar, a redirection and a pipe are
    part of a ``print`` or ``printf`` statement and of nothing else, so a ``>`` that no print
    statement reaches is a comparison, which is how an over-length check is usually written.

    Both rules are applied with string literals taken out: a format string is where
    ``|`` and ``>`` appear most often and mean least.
    """
    for arg in args:
        if (
            arg.startswith(("-f", "-l", "-i", "-e", "--file", "--load", "--include", "--source"))
            or arg in ("-f", "-l", "-i", "-e", "--file", "--load", "--include", "--source")
            or _bundled_short(arg, "flie")
        ):
            raise NotReadOnly(f"awk disallowed script/library option: {arg}")

        program = AWK_STRING.sub('""', arg)
        if AWK_OUTPUT.search(program):
            raise NotReadOnly("awk redirection or pipe out of a print statement")
        if AWK_EXTENSION.search(program):
            raise NotReadOnly("awk include or load directive inside the program")
        if re.search(r"\b(?:system|getline|close|fflush|ENVIRON)\b", program):
            raise NotReadOnly("awk external access function")


def _check_git(args: list[str]) -> None:
    """Validate ``git`` subcommands, ensuring read-only behavior and safe options."""
    # Global writing / execution flags
    for arg in args:
        # `-c diff.external=cmd` and `-c core.pager=cmd` name a program to run, and
        # `--config-env` does the same by way of a variable. No read-only call needs one.
        if arg in ("-c", "--config-env") or arg.startswith("--config-env="):
            raise NotReadOnly(f"git configuration override: {arg}")
        # `--ext-diff`, `--textconv` and `--filters` run whatever the repository's own
        # config or `.gitattributes` names, so a read of a checkout is an execution of it.
        # The `--no-` spellings are the safe ones and do not match these prefixes.
        if arg.startswith("-O") or any(_git_option_is(arg, o) for o in GIT_EXECUTION_OPTS):
            raise NotReadOnly(f"git mutating or execution flag: {arg}")

        # A repository whose config this module never read names the programs `git` will
        # run: `core.pager`, `diff.external`, a hook path. Pointing at one gets the
        # execution that `-c core.pager=touch` gets, with no `-c` in the command.
        if any(_git_option_is(arg, o) for o in GIT_LOCATION_OPTS):
            raise NotReadOnly(f"git repository location override: {arg}")

    # Consume global `git` options (e.g. `-C <dir>`, `-c <name>=<value>`)
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-C", "-c"):
            i += 2
            continue
        if arg.startswith("-"):
            i += 1
            continue
        break

    if i >= len(args):
        raise NotReadOnly("git with no subcommand")

    subcommand = args[i]
    sub_args = args[i + 1 :]

    # Check for glob expansion in git arguments
    if any("*" in a or "?" in a for a in sub_args):
        raise NotReadOnly("git with glob operand")

    if subcommand == "stash":
        operands = [a for a in sub_args if not a.startswith("-")]
        if not operands or operands[0] not in {"list", "show"}:
            raise NotReadOnly("git stash modification")
        return

    if subcommand == "tag":
        # Tag is only read-only when listing (no tag creation or deletion arguments)
        if any(
            a in ("-d", "-a", "-s", "-u", "-f", "--delete", "--force") or a.startswith(("-d", "-f"))
            for a in sub_args
        ):
            raise NotReadOnly("git tag mutation flag")
        operands = [a for a in sub_args if not a.startswith("-")]
        if operands:
            raise NotReadOnly("git tag creation")
        return

    if subcommand == "worktree":
        operands = [a for a in sub_args if not a.startswith("-")]
        if not operands or operands[0] != "list":
            raise NotReadOnly("git worktree mutation")
        return

    if subcommand not in GIT_READ_SUBCOMMANDS:
        raise NotReadOnly(f"git non-read subcommand: {subcommand}")


def _git_option_is(arg: str, option: str) -> bool:
    """Whether git reads ``arg`` as ``option``, or as a longer form of it.

    A subcommand built on git's option parser (`grep`, `cat-file`, `tag`) takes any unambiguous
    prefix of a long option, as the AWS CLI does: `git grep --open=cmd` is `--open-files-in-pager`
    nd runs `cmd`, checked against git 2.48.1.

    The revision and diff options of `log`, `diff` and `show` do not, and are refused alike,
    which costs nothing: an abbreviation git rejects is one that does not run.
    """
    name = arg.partition("=")[0]
    if name in GIT_EXACT_SAFE_OPTS:
        return False
    return name.startswith(option) or (
        len(name) > 2 and name.startswith("--") and option.startswith(name)
    )


def _check_aws(args: list[str]) -> None:
    """Validate ``aws`` calls, accounting for global options and positional verbs."""
    # The usual way to record which CLI ran: it prints the version and exits before reading
    # a profile, so it reaches no account.
    if args == ["--version"]:
        return
    for arg in args:
        if any(_aws_option_is(arg, option) for option in AWS_BLOCKED_OPTS):
            raise NotReadOnly(f"aws endpoint, trust or input override: {arg}")
        # `file://` and `fileb://` hand the CLI a file as the value of any parameter, so
        # what the call does is in a document this module never opened.
        if arg.startswith(("file://", "fileb://")):
            raise NotReadOnly(f"aws argument read from a file: {arg}")

    # Filter global options that take arguments. The CLI reads one wherever it sits, after
    # the service too, and takes any prefix of it: `aws ec2 --qu list terminate-instances`
    # is a `--query` of `list` and a terminate, where an exact match read `list` as the
    # operation and approved it.
    filtered: list[str] = []
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if any(_aws_option_is(arg, option) for option in AWS_GLOBAL_OPTS_WITH_ARG):
            skip_next = "=" not in arg
            continue
        filtered.append(arg)

    operands = [arg for arg in filtered if not arg.startswith("-")]
    if not operands:
        raise NotReadOnly("aws with no operation")

    operation = operands[1] if len(operands) > 1 else operands[0]
    if operation in AWS_BLOCKED_OPS:
        raise NotReadOnly(f"aws blocked operation: {operation}")
    if (operands[0], operation) in AWS_BLOCKED_SERVICE_OPS:
        raise NotReadOnly(f"aws blocked operation: {operands[0]} {operation}")
    for arg in args:
        if any(_aws_option_is(arg, o) for o in AWS_BLOCKED_SERVICE_OPTS.get(operands[0], ())):
            raise NotReadOnly(f"aws {operands[0]} option that prints a secret: {arg}")
    if not AWS_READ_OP.match(operation):
        raise NotReadOnly(f"aws non-read operation: {operation}")


def _aws_option_is(arg: str, option: str) -> bool:
    """Whether the AWS CLI reads ``arg`` as ``option``.

    It takes any unambiguous prefix of a long option, global or not: `--endpoint` is
    `--endpoint-url` and `--with-decr` is `--with-decryption`. A prefix that is ambiguous
    is one the CLI refuses to run, so reading every prefix as the option costs nothing.
    """
    name = arg.partition("=")[0]
    return len(name) > 2 and name.startswith("--") and option.startswith(name)


def _check_gcloud(args: list[str]) -> None:
    """Validate ``gcloud`` CLI calls, enforcing read-only verbs and rejecting flags files."""
    if any(arg == "--flags-file" or arg.startswith("--flags-file=") for arg in args):
        raise NotReadOnly("gcloud --flags-file option")

    # Checked before `--help`, because these decide where the call goes and as whom, and
    # a help page is not what makes them safe.
    blocked = tuple(f"{option}=" for option in GCLOUD_BLOCKED_OPTS)
    for arg in args:
        if arg in GCLOUD_BLOCKED_OPTS or arg.startswith(blocked):
            raise NotReadOnly(f"gcloud endpoint or identity override: {arg}")

    operands = [arg for arg in args if not arg.startswith("-")]
    # `--help` is a parse-time action: `gcloud` prints the page and exits before the verb
    # runs, so it clears a blocked verb too. This has to be tested first, or the only
    # shape anyone writes -- `gcloud services disable --help` -- never reaches it.
    if "--help" in args or "help" in operands:
        return
    if any(word in GCLOUD_BLOCKED_VERBS for word in operands):
        raise NotReadOnly("gcloud disallowed verb")
    if not any(word in GCLOUD_READ_VERBS for word in operands):
        raise NotReadOnly("gcloud with no read verb")


# `gh api` flags that cannot send a body, change the method, or reach another host, split
# by whether they take a value. `-X`/`--method` is read separately: only `GET` passes.
GH_API_VALUE_FLAGS = {
    "-H",
    "--header",
    "-q",
    "--jq",
    "-t",
    "--template",
    "-p",
    "--preview",
    "--cache",
}
GH_API_BARE_FLAGS = {"-i", "--include", "--paginate", "--slurp", "--silent"}
# Only these headers may be set, because a header can carry a method override.
GH_API_HEADERS = re.compile(r"^\s*(?:accept|x-github-api-version)\s*:", re.IGNORECASE)


def _check_gh(args: list[str]) -> None:
    """Validate ``gh api``: a GET to a GitHub endpoint, reading nothing it was not asked to.

    The read-only ``pr``, ``run``, ``issue`` and ``repo`` subcommands are read by
    ``_check_gh_read`` and every other one is left to the operator's rules, both in
    ``_check_command``. ``gh api`` is a generic HTTP client holding the operator's token,
    so it is read the way ``curl`` would have to be:

    * the method is ``GET``, because ``-X``/``--method`` sets anything, and a request body
      (``-f``, ``-F``, ``--field``, ``--raw-field``, ``--input``) switches the default to POST
    * the endpoint is a path, never ``graphql`` (whose queries can be mutations) nor a full
      URL, and ``--hostname`` is refused, so the token goes to no host but the default
    * headers are limited to ``Accept`` and the API version, since a header can override a
      method; ``--verbose`` is refused, since it prints the request, credentials included
    * ``--jq`` gets the ``jq`` rule against reading the environment: gh's own jq has ``env``
    * an unknown flag, or a bundle such as ``-iX``, is refused rather than guessed at
    """
    # Merged from the parallel validator: `gh api --help` prints help and sends nothing. It is
    # the command that first prompted, and the flag loop below would refuse `--help` as unknown.
    if args[1:] in (["--help"], ["-h"]):
        return

    endpoints: list[str] = []
    fields: list[str] = []
    explicit_get = False
    index = 1
    while index < len(args):
        arg = args[index]
        name, _, attached = arg.partition("=") if arg.startswith("--") else (arg, "", "")
        if name in ("-f", "-F", "--field", "--raw-field"):
            value = attached if attached else (args[index + 1] if index + 1 < len(args) else "")
            if not attached:
                index += 1
            fields.append(value)
            # `-F key=@path` sends a local file, and `@-` stdin, as the parameter's value
            if name in ("-F", "--field") and value.partition("=")[2].startswith("@"):
                raise NotReadOnly(f"gh api field read from a file: {value}")
        elif (
            arg in ("-X", "--method")
            or name == "--method"
            or (arg.startswith("-X") and len(arg) > 2)
        ):
            if arg in ("-X", "--method"):
                value = args[index + 1] if index + 1 < len(args) else ""
                index += 1
            else:
                value = attached if name == "--method" else arg[2:]
            if value.upper() != "GET":
                raise NotReadOnly(f"gh api method other than GET: {value}")
            explicit_get = True
        elif arg in GH_API_VALUE_FLAGS or name in GH_API_VALUE_FLAGS:
            value = (
                attached
                if name in GH_API_VALUE_FLAGS and attached
                else (args[index + 1] if index + 1 < len(args) else "")
            )
            if not (name in GH_API_VALUE_FLAGS and attached):
                index += 1
            if name in ("-H", "--header") and not GH_API_HEADERS.match(value):
                raise NotReadOnly(f"gh api header outside Accept and the API version: {value}")
            if name in ("-q", "--jq"):
                _check_jq([value])
        elif arg in GH_API_BARE_FLAGS:
            pass
        elif arg.startswith("-"):
            raise NotReadOnly(f"gh api flag not known to be read-only: {arg}")
        else:
            endpoints.append(arg)
        index += 1

    # A field makes the request a POST unless the method was set: with `-X GET` the fields
    # are sent as query parameters instead, which is how the search endpoints are called.
    if fields and not explicit_get:
        raise NotReadOnly("gh api with fields and no explicit GET is a POST")
    if len(endpoints) != 1:
        raise NotReadOnly("gh api needs exactly one endpoint")
    endpoint = endpoints[0]
    # Merged from the parallel validator: `//host/path` is refused too. Whether gh reads it as
    # a host or as a path was not tested -- no REST path begins with `//`, so refusing it costs
    # nothing either way.
    if endpoint.strip("/").lower() == "graphql" or "://" in endpoint or endpoint.startswith("//"):
        raise NotReadOnly(f"gh api endpoint that is not a REST path: {endpoint}")


# The `gh` subcommands read by `_check_gh_read`, keyed by (group, verb). Each entry is the bare
# flags, the flags that take a value, and how many positional arguments the verb takes. The
# lists are `gh <group> <verb> --help` as of gh 2.102, minus what opens a browser (`-w/--web`),
# blocks (`--watch`, `-i/--interval`, `--fail-fast`), formats with a template (`-t/--template`)
# or prints terminal escapes (`--allow-escape-sequences`). A flag that is not listed gives
# `NoOpinion`, so the operator's own rules can still grant it. `-w` is `--workflow` in
# `run list` and `--web` everywhere else, which is why the tables are per verb.
_GH_JSON_FLAGS = frozenset({"--json", "-q", "--jq", "-R", "--repo"})
GH_READ_SPECS: dict[tuple[str, str], tuple[frozenset[str], frozenset[str], int]] = {
    ("pr", "view"): (frozenset({"-c", "--comments"}), _GH_JSON_FLAGS, 1),
    ("pr", "list"): (
        frozenset({"-d", "--draft"}),
        _GH_JSON_FLAGS
        | {"--app", "-a", "--assignee", "-A", "--author", "-B", "--base", "-H", "--head"}
        | {"-l", "--label", "-L", "--limit", "-S", "--search", "-s", "--state"},
        0,
    ),
    ("pr", "diff"): (
        frozenset({"--name-only", "--patch"}),
        frozenset({"-R", "--repo", "--color", "-e", "--exclude"}),
        1,
    ),
    ("pr", "checks"): (frozenset({"--required"}), _GH_JSON_FLAGS, 1),
    ("run", "list"): (
        frozenset({"-a", "--all"}),
        _GH_JSON_FLAGS
        | {"-b", "--branch", "-c", "--commit", "--created", "-e", "--event", "-L", "--limit"}
        | {"-s", "--status", "-u", "--user", "-w", "--workflow"},
        0,
    ),
    ("run", "view"): (
        frozenset({"--exit-status", "--log", "--log-failed", "-v", "--verbose"}),
        _GH_JSON_FLAGS | {"-a", "--attempt", "-j", "--job"},
        1,
    ),
    ("issue", "view"): (frozenset({"-c", "--comments"}), _GH_JSON_FLAGS, 1),
    ("issue", "list"): (
        frozenset(),
        _GH_JSON_FLAGS
        | {"--app", "-a", "--assignee", "-A", "--author", "-l", "--label", "-L", "--limit"}
        | {"--mention", "-m", "--milestone", "-S", "--search", "-s", "--state", "--type"},
        0,
    ),
    ("repo", "view"): (frozenset(), frozenset({"-b", "--branch", "--json", "-q", "--jq"}), 1),
}

# `[HOST/]OWNER/REPO` is how gh names a repository; only the two-part form stays on the host the
# token belongs to, the same reason `gh api` refuses `--hostname` and a full URL.
GH_REPO_NAME = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
# A pull request, issue or run is a number or a branch; a URL carries a host of its own.
GH_REFERENCE = re.compile(r"^[A-Za-z0-9_./@#:+-]+$")


def _check_gh_jq(args: list[str]) -> None:
    """Refuse a ``--jq``/``-q`` filter that reads the environment, whatever the subcommand.

    gh's own jq has ``env`` and ``$ENV``, so ``gh issue view 1 --jq '$ENV.GH_TOKEN'`` prints
    the token. The filter goes through ``_check_jq``, which raises ``NotReadOnly``: unlike
    ``NoOpinion`` that is not a verdict an operator's allow rule can overturn, so the hook does
    not approve it through a rule either. Every spelling is read -- ``--jq F``, ``--jq=F``,
    ``-q F``, ``-qF`` and a cluster such as ``-dq F`` -- on any subcommand, listed or not.
    """
    for index, arg in enumerate(args):
        if arg.startswith("--jq="):
            _check_jq([arg[len("--jq=") :]])
        elif arg == "--jq":
            _check_jq(args[index + 1 : index + 2])
        elif arg.startswith("-") and not arg.startswith("--") and "q" in arg[1:]:
            tail = arg[arg.index("q") + 1 :]
            _check_jq([tail] if tail else args[index + 1 : index + 2])


def _check_gh_read(args: list[str], live_globs: list[bool]) -> None:
    """Validate a read-only ``gh pr|run|issue|repo`` subcommand, flag by flag.

    ``args`` start at the group. A subcommand that is not in ``GH_READ_SPECS``, a flag that is
    not listed for it, or anything the shell still has to build -- an unquoted wildcard, an
    expansion, a substitution -- is ``NoOpinion``: the module cannot vouch for it, and the
    operator's rules decide, as they did before this existed. What is refused outright is the
    ``--jq`` that reads the environment, in ``_check_gh_jq``. The hook approves only what it
    can read in full:

    * the flags are the verb's own, each once spelled ``--flag V``, ``--flag=V`` or ``-fV``;
      a cluster of short options and a bare ``--`` are not guessed at
    * ``-R`` and a repository operand are ``OWNER/REPO``, and a pull request, issue or run is
      a plain reference; a ``HOST/OWNER/REPO`` or a URL would send the token to another host
    * ``--help`` prints help and sends nothing
    """
    spec = GH_READ_SPECS.get(tuple(args[:2]))
    if spec is None:
        raise NoOpinion(f"gh {' '.join(args[:2])} is left to the operator's rules")
    bare, valued, max_positionals = spec
    if any(live_globs):
        raise NoOpinion("gh with an unquoted wildcard")
    rest = args[2:]
    positionals: list[str] = []
    index = 0
    while index < len(rest):
        arg = rest[index]
        index += 1
        name, equals, attached = arg.partition("=") if arg.startswith("--") else (arg, "", "")
        if not arg.startswith("-"):
            positionals.append(arg)
            continue
        if arg == "--help":
            continue
        if arg.startswith("--"):
            flag = name
            if flag in bare and not equals:
                continue
            if flag not in valued:
                raise NoOpinion(f"gh {args[0]} {args[1]} flag not known to be read-only: {arg}")
            if equals:
                value = attached
            elif index < len(rest):
                value = rest[index]
                index += 1
            else:
                raise NoOpinion(f"gh {flag} without a value")
        else:
            flag = arg[:2]
            if arg in bare:
                continue
            if flag not in valued:
                raise NoOpinion(f"gh {args[0]} {args[1]} flag not known to be read-only: {arg}")
            if len(arg) > 2:
                value = arg[2:]
                if value.startswith("="):
                    raise NoOpinion(f"gh short option with an attached '=': {arg}")
            elif index < len(rest):
                value = rest[index]
                index += 1
            else:
                raise NoOpinion(f"gh {flag} without a value")
        if flag in ("-q", "--jq"):
            continue  # a filter, already read by `_check_gh_jq`; `$` is jq syntax there
        _check_gh_word(value)
        if flag in ("-R", "--repo") and not GH_REPO_NAME.match(value):
            raise NoOpinion(f"gh repository not in OWNER/REPO form: {value}")
    if len(positionals) > max_positionals:
        raise NoOpinion(f"gh {args[0]} {args[1]} with more operands than it takes")
    for operand in positionals:
        _check_gh_word(operand)
        pattern = GH_REPO_NAME if args[:2] == ["repo", "view"] else GH_REFERENCE
        if "://" in operand or not pattern.match(operand):
            raise NoOpinion(f"gh operand that is not a plain reference: {operand}")


def _check_gh_word(word: str) -> None:
    """A word the shell is still building is not one this module read."""
    if "$" in word or SUBSTITUTION_MARKER in word or PLACEHOLDER_MARK in word:
        raise NoOpinion(f"gh given a word that is expanded or substituted: {word}")


def _check_find(args: list[str], live_globs: list[bool]) -> None:
    """Validate find: prevent root traversal, execution, deletion, and file writing.

    A wildcard inside `-name '*.md'` is an argument find matches for itself and the shell
    never touches. Refusing it cost every `-name` and `-path` pattern and bought nothing, so
    only a wildcard the shell will expand is refused here.
    """
    if any(live_globs):
        raise NotReadOnly("unquoted glob operand in find")
    if "/" in args:
        raise NotReadOnly("find root directory traversal")
    for index, arg in enumerate(args):
        if arg in ("-delete", "-exec", "-execdir", "-ok", "-okdir", "-fls") or arg.startswith(
            ("-exec", "-delete", "-ok", "-fprint", "-fprintf", "-fls")
        ):
            raise NotReadOnly(f"find writing flag: {arg}")
        if arg == "-printf" and _exceeds_width_cap(args[index + 1 : index + 2]):
            raise NotReadOnly(f"find -printf field wider than {PRINTF_WIDTH_CAP}")


def _check_jq(args: list[str]) -> None:
    """Validate jq: a filter language with no write and no exec, given two restrictions.

    jq cannot create a file or run a program -- there is no `system`, no output
    redirection, and no shell-out anywhere in its grammar -- which is what makes it safe
    to add to a read-only set at all. Two things still need refusing:

    * `-f FILE` takes the program from a file this module never read, exactly as `sed -f`
      and `awk -f` do.
    * `$ENV` and `env` print the process environment, and this shell's environment is
      where the session's credentials live. That is not a write, but it puts a token in
      Claude's context, which under a poisoned prompt is the point of the exercise.

    String literals come out before the environment check, so a filter selecting a field
    named `"env"` is not mistaken for one reading it -- except a literal carrying `\\(...)`,
    which is interpolation: code that runs, kept in so that `"\\(env)"` is still seen.
    `import` and `include` load code from a file this module never read, which is `-f`
    under another name, and so does `-L`, which says where those files are looked for.
    """
    for arg in args:
        if (
            arg in ("-f", "--from-file", "-L", "--library-path")
            or arg.startswith(("-f", "--from-file=", "-L", "--library-path="))
            or _bundled_short(arg, "fL")
        ):
            raise NotReadOnly(f"jq program or library file argument: {arg}")
        filter_text = JQ_STRING.sub(
            lambda match: match.group(0) if "\\(" in match.group(0) else '""', arg
        )
        if re.search(r"\$ENV\b|\benv\b", filter_text):
            raise NotReadOnly("jq reads the process environment")
        if re.search(r"\b(?:import|include)\b", filter_text):
            raise NotReadOnly("jq loads a module from a file")


def _check_sort(args: list[str], live_globs: list[bool]) -> None:
    """Validate sort: prevent output redirection and glob expansion.

    The glob rule is the one in `_check_find`: an unquoted wildcard can expand into `-o`
    and turn a read into a write, and a quoted one cannot.
    """
    if any(live_globs):
        raise NotReadOnly("unquoted glob operand in sort")
    for arg in args:
        if (
            arg in ("-o", "--output")
            or arg.startswith(("-o", "--output="))
            # `-k`, `-t`, `-S` and `-T` take a value, so `-to` is the separator `o`
            or _bundled_short(arg, "o", "ktST")
        ):
            raise NotReadOnly(f"sort output flag: {arg}")


def _check_uniq(args: list[str]) -> None:
    """Validate uniq: reject secondary output file operand."""
    operands = [a for a in args if not a.startswith("-") or a == "-"]
    if len(operands) > 1:
        raise NotReadOnly("uniq with output file operand")


def _check_xxd(args: list[str]) -> None:
    """Validate xxd: disallow reverse/write mode and secondary output file operand."""
    if any(a == "-r" or a.startswith("-r") or _bundled_short(a, "r") for a in args):
        raise NotReadOnly("xxd reverse mode")
    operands = [a for a in args if not a.startswith("-") or a == "-"]
    if len(operands) > 1:
        raise NotReadOnly("xxd with output file operand")


def _check_tail(args: list[str]) -> None:
    """Validate tail: prevent non-terminating follow modes."""
    if any(
        a in ("-f", "-F", "--follow")
        or a.startswith(("-f", "-F", "--follow="))
        or _bundled_short(a, "fF")
        for a in args
    ):
        raise NotReadOnly("tail non-terminating follow flag")


def _check_date(args: list[str]) -> None:
    """Validate date: prevent setting system clock."""
    if any(
        a in ("-s", "--set")
        or a.startswith(("-s", "--set="))
        # `-d`, `-f`, `-r` and `-I` take a value, `-I`'s attached as in `-Iseconds`
        or _bundled_short(a, "s", "dfrI")
        for a in args
    ):
        raise NotReadOnly("date sets system time")


def _check_file(args: list[str]) -> None:
    """Validate file: prevent arbitrary file opens or compilation."""
    for arg in args:
        if (
            arg in ("-m", "-f", "-C", "--magic-file", "--files-from", "--compile")
            or arg.startswith(("-m", "-f", "-C", "--magic-file=", "--files-from="))
            or _bundled_short(arg, "mfC")
        ):
            raise NotReadOnly(f"file path/compile flag: {arg}")


def _check_printf(args: list[str]) -> None:
    """Validate printf: no ``-v``, and a format the operator wrote rather than the shell.

    ``printf -v name ...`` assigns without an ``=`` anywhere in the command, which is the
    handover ``_strip_structure`` is looking for spelled so that it cannot find it.

    The format is argument one and nothing else can be a flag, so it is the only word
    checked for a leading expansion -- which is also what keeps the safe spelling working:
    ``printf '%s\\n' "${var}"`` is approved, and ``printf "${var}"``, whose format the shell
    supplies, is not.
    """
    if any(arg == "-v" or _bundled_short(arg, "v") for arg in args):
        raise NotReadOnly("printf assigns to a variable with -v")

    # zsh's `printf` evaluates the argument of a numeric conversion -- and of a `*` width
    # -- as an arithmetic expression, so `printf '%d' "$x"` runs what `$((x))` runs. A
    # number spelled out is fine; one the shell supplies is a value this module never read.
    if any(PRINTF_NUMERIC.search(arg) for arg in args) and any(
        "$" in arg or SUBSTITUTION_MARKER in arg for arg in args
    ):
        raise NotReadOnly("printf evaluates an expanded value as arithmetic")

    if _exceeds_width_cap(args) or (
        any(PRINTF_STAR.search(arg) for arg in args)
        and any(
            PRINTF_INTEGER_ARGUMENT.fullmatch(arg) and abs(int(arg)) > PRINTF_WIDTH_CAP
            for arg in args
        )
    ):
        raise NotReadOnly(f"printf field wider than {PRINTF_WIDTH_CAP}")


def _exceeds_width_cap(formats: list[str]) -> bool:
    """Whether any conversion in these formats asks for a width or precision over the cap.

    Every argument is read as a format, which over-refuses a data argument that happens to
    look like one, rather than work out which arguments a format consumes.
    """
    return any(
        group and int(group) > PRINTF_WIDTH_CAP
        for text in formats
        for match in PRINTF_WIDTH.finditer(text)
        for group in match.groups()
    )


def _check_hostname(args: list[str]) -> None:
    """Validate hostname: allow read-only display, reject setting hostname."""
    if any(not a.startswith("-") for a in args):
        raise NotReadOnly("hostname modification")


def _check_cd(args: list[str]) -> None:
    """Validate cd: one directory operand, resolving inside the project.

    A command is better written from the project root with project-relative paths, since
    that is what permission rules are written against. What this accepts is the slip, so
    that it costs a refused approval rather than an approval the operator has to read.

    The target is measured from the project root rather than from the process's own
    working directory, which is the conservative reading: a session runs from the root, a
    relative target can only go deeper, and anything that climbs out is refused.

    It is measured with ``realpath`` rather than ``normpath``, because a textual prefix test
    answers "how is this path written" and the question is "where does it land". ``cd``
    follows a symlink by default, so a link inside the project pointing anywhere is a
    path that reads as internal and is not.
    """
    for arg in args:
        if arg.startswith("-") and arg not in ("-L", "-P", "-@", "--"):
            raise NotReadOnly(f"cd option: {arg}")

    operands = [arg for arg in args if not arg.startswith("-")]
    if len(operands) != 1:
        raise NotReadOnly("cd with no directory operand, or more than one")

    target = operands[0]
    if SUBSTITUTION_MARKER in target or "$" in target or "~" in target:
        raise NotReadOnly(f"cd to a path this module cannot resolve: {target}")

    root = os.path.realpath(REPO_ROOT)
    # `normpath` first, so that a `..` is resolved as bash's own `cd -L` resolves it, and
    # `realpath` second, so that a symlink anywhere along the way is resolved as well.
    resolved = os.path.realpath(os.path.normpath(os.path.join(root, target)))
    if resolved != root and not resolved.startswith(root + os.sep):
        raise NotReadOnly(f"cd outside the project: {target}")


def _strip_timeout(args: list[str]) -> list[str]:
    """The command ``timeout`` will run, with its own options and its duration removed.

    Claude Code strips the same wrapper before it matches a rule, so recognizing it here
    is parity rather than a widening -- and a ``timeout`` in front of a vendor call is the
    one thing that guarantees a command comes back.
    """
    index = 0
    while index < len(args) and args[index].startswith("-"):
        takes_value = args[index] in ("-k", "-s", "--kill-after", "--signal")
        index += 2 if takes_value else 1
    index += 1  # the duration
    if index >= len(args):
        raise NotReadOnly("timeout with no command")
    return args[index:]


# Programs that run the rest of the command line as a command of their own. `time`, the
# other common one, is a bash reserved word and is stripped as structure.
WRAPPERS = {
    "timeout": _strip_timeout,
}

# `timeout timeout timeout ...` parses; it just has nothing to say.
MAX_WRAPPER_DEPTH = 4

# Explicit dispatch table mapping programs to their dedicated validator functions
# Validators that need to know which words carry a wildcard the shell will expand, and
# so take the parallel `live_globs` list as a second argument.
GLOB_AWARE = frozenset({"find", "sed", "sort"})

PROGRAM_VALIDATORS = {
    "aws": _check_aws,
    "awk": _check_awk,
    "cd": _check_cd,
    "date": _check_date,
    "file": _check_file,
    "find": _check_find,
    "gawk": _check_awk,
    "gcloud": _check_gcloud,
    "gh": _check_gh,
    "git": _check_git,
    "hostname": _check_hostname,
    "jq": _check_jq,
    "printf": _check_printf,
    "sed": _check_sed,
    "sort": _check_sort,
    "tail": _check_tail,
    "uniq": _check_uniq,
    "xxd": _check_xxd,
}

# Programs whose behavior turns on whether a word is a flag, so a word whose first
# character the shell supplies is a word this module has not read. Derived rather than
# listed, so a new validator is covered the day it is added.
#
# `printf` is the exception: its format is argument one and no later word can be an
# option, so `_check_printf` reads that one word and `printf '%s\n' "${var}"` keeps
# working. Everything without a validator is out by construction --
# a program in `READ_ONLY` has no flag worth forging.
EXPANSION_UNSAFE = frozenset(PROGRAM_VALIDATORS) - {"printf"}


def _check_command(
    words: list[str],
    parts: list[tuple[str, str]],
    depth: int = 0,
    safe_names: frozenset[str] = frozenset(),
    splice_vars: dict[str, list[str]] | None = None,
    scope: "_ReadScope | None" = None,
) -> None:
    """Inspect simple command name and argument list with strict fail-closed dispatch.

    ``words`` are the reduced words; the program and its arguments are expanded back to
    what bash will hand over, so a validator reads ``s|a|b|`` and an ``awk`` program as the
    single words they are, and ``/tmp/'ls'`` as the path it is.
    """
    if depth > MAX_WRAPPER_DEPTH:
        raise NotReadOnly("wrapper nested too deeply")

    # A word the shell builds is a word this module did not read. As an operand that is
    # the accepted residual; as the program name it is the whole question, so
    # `$(echo rm) -rf .` must never reach the dispatch below -- and neither may `"ls"`,
    # `l''s` or `\ls`, which are the same lookup written so that the token the lexer
    # returns is one this module assembled rather than one the operator typed.
    if PLACEHOLDER.search(words[0]):
        raise NotReadOnly("the program name is quoted, escaped or produced by a substitution")

    program = _expand(words[0], parts)

    # Splice in the words of any `$name`/`${name}`/`${=name}` whose `name` was assigned a
    # fully literal value earlier in this same command. The value is resolved and its words
    # take the use's place, so a validator reads the flags the program will actually get --
    # `aws ... ${=_p} ...` becomes `aws ... --profile admin --region us-east-1 ...` and is
    # checked as that. `spliced` marks which resulting args came from a splice, so the
    # flag-position check below skips them: they are known literals, and the validator that
    # runs on the full list is what actually clears them. An argument that is not a splice
    # keeps its token, so quoting and placeholders are preserved for every other check.
    splice_vars = splice_vars or {}
    args: list[str] = []
    arg_tokens: list[str] = []
    live_globs: list[bool] = []
    spliced: list[bool] = []
    for word in words[1:]:
        name = _splice_name(word, splice_vars)
        if name is not None:
            for value_word in splice_vars[name]:
                args.append(value_word)
                arg_tokens.append(value_word)
                live_globs.append(False)  # a resolved literal has no live glob
                spliced.append(True)
        else:
            args.append(_expand(word, parts))
            arg_tokens.append(word)
            live_globs.append(_carries_live_glob(word))
            spliced.append(False)

    # Path spoofing check: program must be a bare command name (e.g. 'ls', not './ls' or '/tmp/ls')
    if "/" in program or "\\" in program:
        raise NoOpinion(f"non-bare program path: {program}")

    # bash opens a socket for one of these itself, with no program in the command to
    # refuse. A word naming one is refused wherever it sits.
    for word in args:
        if PSEUDO_DEVICE.search(word):
            raise NotReadOnly(f"network pseudo-device: {word}")

    # An unquoted brace expansion splits one word into several before the program sees it,
    # so an operand check that counted this as one word read the wrong command. Refused in
    # any position -- operand or program -- the way an unquoted glob is: the module reads
    # words, and this is a word the shell has not finished building. The reduced tokens are
    # tested so a quoted `'{a,b}'`, a single literal to bash, stays approved. A spliced
    # value was already cleared of braces when it was accepted as a literal assignment.
    for word in [words[0]] + [t for t, s in zip(arg_tokens, spliced) if not s]:
        if _carries_brace_expansion(word):
            raise NotReadOnly(f"unquoted brace expansion: {_expand(word, parts)}")

    # Merge note: this sits below the brace check on purpose. "The word checks below" are
    # the flag-position checks; a brace is refused for every operator-rule program, `gh`
    # included, because it is a word the shell has not finished building.
    # `gh api` is read by its own validator, below. The read-only `pr`, `run`, `issue` and `repo`
    # subcommands are read here, and every other subcommand stays the operator's rules' to
    # grant, as before `gh` had a validator, so the word checks below must not refuse what
    # those rules would. That is why this returns: `EXPANSION_UNSAFE` would refuse `gh pr view
    # "$n"` outright, where `_check_gh_read` gives it no opinion and a rule can still grant it.
    if program == "gh" and args[:1] != ["api"]:
        # The `--jq` check comes first and on every subcommand: `gh issue view 1 --jq
        # '$ENV.GH_TOKEN'` prints the token, so the hook approves it neither by reading it nor
        # through a rule. A native `Bash(gh issue view *)` rule still lets Claude Code run it
        # without asking; only a native deny rule stops that.
        _check_gh_jq(args)
        _check_gh_read(args, live_globs)
        return

    # A wrapper's own arguments are not the command; what it runs is checked in its place.
    # The wrapper sees the pre-splice tokens, since its own argument parsing happens before
    # the inner program's; the inner `_check_command` splices again with the same vars.
    if program in WRAPPERS:
        _check_command(
            WRAPPERS[program](words[1:]), parts, depth + 1, safe_names, splice_vars, scope
        )
        return

    # Every flag test below reads a word that is already complete. One that begins with
    # an expansion is not: its leading `-` arrives after this module has finished, so the
    # word the validator cleared is not the word the program receives.
    # For `printf` only argument one can be an option, and it is the format, so that is
    # the one word read -- which is what leaves `printf '%s\n' "${var}"` alone.
    if program == "printf":
        suspect = list(zip(arg_tokens[:1], spliced[:1]))
    elif program in EXPANSION_UNSAFE:
        suspect = list(zip(arg_tokens, spliced))
    else:
        suspect = []
    for word, was_spliced in suspect:
        # A spliced word is a resolved literal from a `name=<literal>` assignment in this
        # command: its text, leading `-` and all, is known, so it is not a word the shell
        # still decides. The validator below reads it as the flag it is.
        if was_spliced:
            continue
        if _word_the_shell_decides(word, parts):
            # A bare `"$f"` whose `f` a literal-list `for` header binds is the one word the
            # shell builds that the command still pins down: every value is spelled out to
            # the left and none is a flag. `"${f}-x"` and `"$f$g"` are not bare and are not
            # exempt -- `_is_bare_expansion_of` holds only for exactly `$f` or `${f}`.
            if _is_bare_expansion_of(word, parts, safe_names):
                continue
            raise NotReadOnly(
                f"an argument to {program} begins with an expansion: {_expand(word, parts)}"
            )

    # What these two print, a terminal interprets; see `TERMINAL_CONTROL_BYTE`. Read here,
    # past any wrapper, so `echo '=== EC ==='` beside a `sed` that strips colors stays approved.
    # Without a scope there is no command to have read the spelling from, so an expanded
    # value is refused rather than assumed clean -- the opposite of Layer A below, where no
    # scope means no roots to measure against, and the read is left to the validators.
    if program in INTERPRETS_ESCAPES:
        if any(TERMINAL_CONTROL_SPELLED.search(arg) for arg in args):
            raise NotReadOnly(f"{program} given a terminal escape")
        if (scope is None or scope.spells_escape) and any(
            "$" in arg or SUBSTITUTION_MARKER in arg for arg in args
        ):
            raise NotReadOnly(f"{program} expands a value in a command that spells an escape")

    # Layer A: a reader this module knows may only open files inside the working directories.
    # Outside them, or unresolvable, is not a verdict this module can give; the operator's
    # own allow rules decide, as they do for any program the module cannot read.
    if scope is not None and program in READER_SPECS:
        for index in _file_operands(program, args):
            problem = _read_scope_problem(arg_tokens[index], args[index], parts, scope)
            if problem is not None:
                raise NoOpinion(f"{program} reads {problem}")

    # Fail-closed dispatch: either a dedicated validator, a purely read-only program, or reject
    if program in PROGRAM_VALIDATORS:
        if program in GLOB_AWARE:
            PROGRAM_VALIDATORS[program](args, live_globs)
        else:
            PROGRAM_VALIDATORS[program](args)
    elif program in READ_ONLY:
        return
    else:
        raise NoOpinion(f"unrecognized program: {program}")


class _GlobRule:
    """A ``Bash(...)`` rule body as an anchored ``*``-glob, matched without a regexp.

    ``"*x" * 12 + "y"`` translated to ``.*x.*x...y`` and matched against a four-hundred
    character command takes minutes: every star can give back, and the engine tries all
    of it before reporting no match. A hook that takes minutes is a Bash call that takes
    minutes, since the host waits for the decision.

    ``*`` is the only wildcard a Bash rule has, and for a pure-``*`` glob the leftmost match
    of each piece is always the right one -- taking more of the text can only make the
    rest harder to place. So a single forward scan decides it, in time proportional to
    the command length, with no backtracking to bound.
    """

    __slots__ = ("pieces", "source")

    def __init__(self, body: str) -> None:
        self.pieces = body.split("*")
        self.source = body

    def match(self, text: str) -> bool:
        """Whether the whole of ``text`` matches, which is the rule's own semantics."""
        first, last = self.pieces[0], self.pieces[-1]
        if len(self.pieces) == 1:
            return text == first
        if not text.startswith(first) or not text.endswith(last):
            return False
        position, limit = len(first), len(text) - len(last)
        if position > limit:
            return False
        for piece in self.pieces[1:-1]:
            found = text.find(piece, position, limit)
            if found < 0:
                return False
            position = found + len(piece)
        return True


def _rule_pattern(rule: str, blanket: bool = False) -> "_GlobRule | None":
    """A ``Bash(...)`` permission rule as a pattern over one simple command's text.

    Quotes are dropped from both sides of the comparison, because the text a segment is
    matched against has already been through the lexer: the rule
    ``Bash(firebase database:get '/.settings/rules' *)`` and the command the operator wrote
    differ by the quotes alone. A rule for another tool matches nothing here and returns
    ``None``, and so does a blanket ``Bash(*)`` unless ``blanket`` is set: granting everything
    is a decision for the operator's own rule file to carry out, not for this hook to
    infer, while a blanket *deny* has to keep its reach.
    """
    if not rule.startswith("Bash(") or not rule.endswith(")"):
        return None
    body = rule[len("Bash(") : -1].strip().replace("'", "").replace('"', "")
    if not body or (not blanket and set(body) <= {"*"}):
        return None
    return _GlobRule(body)


def _operator_rules() -> tuple[list[_GlobRule], list[_GlobRule]]:
    """The allow and deny rules the operator has already written, as patterns.

    This is the second tier, and the whole of its safety argument: a command that matches
    an allow rule is one Claude Code would run with no prompt if it stood on its own. The
    host requires every sub-command of a compound to match a rule independently, which is
    exactly what the caller does with these -- so recognizing them here does not widen
    what the operator granted, it stops a pipeline losing the grant because one filter in
    the middle of it has no rule of its own.

    Nothing is cached: the file is small, it is read once per Bash call, and a rule the
    operator saved a moment ago through "yes, and don't ask again" applies immediately.

    Only a regular file under ``SETTINGS_SIZE_CAP`` is opened, and the decision is made
    from ``stat`` so that a file failing either test costs nothing at all. A named pipe
    with no writer blocks in ``open`` forever, and the host's own hook timeout is ten
    minutes: that is not a bypass, but it is the whole Bash call spent waiting for a file
    that was never going to answer.

    A file that is missing is the ordinary case and means nothing. A file that exists and
    cannot be used -- wrong kind, too large, unreadable, not JSON -- is a file whose
    rules this module cannot see, so the second tier is turned off for the call rather
    than run on a partial reading of what the operator wrote. Allow rules are what tier 2
    spends, and dropping them can only cost a prompt; deny rules that were read stay, and
    the host evaluates its own regardless of what this hook returns.
    """
    allow: list[_GlobRule] = []
    deny: list[_GlobRule] = []

    override = os.environ.get(SETTINGS_ENV)
    if override is None:
        paths = [REPO_ROOT / name for name in SETTINGS_FILES]
    else:
        paths = [Path(piece) for piece in override.split(os.pathsep) if piece]

    unusable = False
    for path in paths:
        try:
            info = path.stat()  # follows a link, and raises for one that dangles
        except OSError:
            continue  # a settings file that is simply absent, which is the normal case
        try:
            # A directory, a FIFO, a device or an oversized file is never opened: the
            # first would block for the length of the Bash call and the last would be
            # read on every one of them.
            if not S_ISREG(info.st_mode) or info.st_size > SETTINGS_SIZE_CAP:
                raise ValueError("not a settings file this module will read")
            document = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            permissions = document["permissions"]
        except (OSError, ValueError, KeyError, TypeError, RecursionError):
            unusable = True  # it is there and it cannot be read; see the docstring
            continue
        for key, target, blanket in (("allow", allow, False), ("deny", deny, True)):
            rules = permissions.get(key) if isinstance(permissions, dict) else None
            for rule in rules or []:
                if not isinstance(rule, str):
                    continue
                pattern = _rule_pattern(rule, blanket=blanket)
                if pattern is not None:
                    target.append(pattern)

    return ([] if unusable else allow), deny


def _home() -> str:
    """The home directory, read at call time so a test can point it elsewhere."""
    return os.path.expanduser("~")


def _credential_roots() -> list[str]:
    home = _home()
    roots = [os.path.join(home, relative) for relative in CREDENTIAL_HOME_PATHS]
    return roots + list(CREDENTIAL_SYSTEM_PATHS)


def _is_under(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def _expand_home(text: str, tilde: bool) -> str:
    """Replace a leading `~`, `~user`, `$HOME` or `${HOME}` with the directory it names."""
    if tilde and text.startswith("~"):
        return os.path.expanduser(text)
    for spelling in ("${HOME}", "$HOME"):
        if text.startswith(spelling):
            return _home() + text[len(spelling) :]
    return text


def _names_a_credential(text: str, tilde: bool = True) -> bool:
    try:
        return _names_a_credential_unguarded(text, tilde)
    except (OSError, ValueError):
        return True  # cannot be resolved, and this is the layer that refuses outright


def _names_a_credential_unguarded(text: str, tilde: bool = True) -> bool:
    """Whether this word reaches a credential store, however it is spelled.

    A word whose final text the shell still decides -- a glob, an expansion -- is judged by
    the literal part in front of the first special character: `~/.a*/cred*` and `/e*/shadow`
    could each expand into a credential store, so they are refused, while `/usr/share/*` could
    not and is left to the read scope. A relative path is resolved against the project, so
    a symlink inside it that points at `~/.ssh` is caught by its target.
    """
    text = REDIRECTION_PREFIX.sub("", text)
    if "=" in text and not text.startswith(("/", "~", "$")):
        # An assignment's or a `--flag=`'s right-hand side. Bash expands a tilde after the
        # `=` of an assignment, so `x=~/.aws/credentials` puts the real path in `x`; a
        # `--flag=~/x` is not expanded, and treating it as if it were costs a prompt at most.
        text = text.split("=", 1)[1]
        tilde = True
    if not text:
        return False
    text = _expand_home(text, tilde)
    roots = _credential_roots()

    special = PATH_SPECIAL.search(text)
    if special is not None:
        prefix = text[: special.start()]
        if not prefix.startswith("/"):
            return False  # relative and undecided: read scope's question, not this one's
        prefix = os.path.normpath(prefix) if prefix.endswith("/") is False else prefix
        return (
            any(root.startswith(prefix) or _is_under(prefix, root) for root in roots)
            or PROCESS_SECRETS.match(prefix) is not None
        )

    absolute = text if text.startswith("/") else os.path.join(str(REPO_ROOT), text)
    for candidate in {os.path.normpath(absolute), os.path.realpath(absolute)}:
        if PROCESS_SECRETS.match(candidate):
            return True
        if any(_is_under(candidate, root) for root in roots):
            return True
    return False


def _refuse_credential_paths(reduced: str, parts: list[tuple[str, str]]) -> None:
    """Layer B: refuse the command if any word in it names a credential store.

    Runs on the reduced command before redirections are stripped, so a `< ~/.ssh/id_rsa`
    target is a word here like any other. Every word of every segment is checked, whichever
    program it belongs to, because the operator tier never sees what a word *opens*.
    """
    for line in reduced.split("\n"):
        try:
            tokens = _tokenize(line)
        except ValueError:
            continue  # the main pass will refuse what cannot be tokenized
        for token in tokens:
            if set(token) <= PUNCTUATION_CHARS:
                continue
            # A tilde is expanded only at the start of an unquoted word, so a quoted
            # `'~/x'` is the literal path it spells. A placeholder start means quoted.
            tilde = token.startswith("~") or bool(REDIRECTION_PREFIX.match(token))
            if _names_a_credential(_expand(token, parts), tilde=tilde):
                raise NotReadOnly(f"names a credential store: {_expand(token, parts)}")


class _ReadScope:
    """Where a reader may read from, and what is known about the command's variables."""

    __slots__ = ("roots", "bases", "splice_vars", "loop_values", "spells_escape")

    def __init__(self, roots, bases, splice_vars, loop_values, spells_escape=False):
        self.roots = roots
        self.bases = bases
        self.splice_vars = splice_vars
        self.loop_values = loop_values
        # Whether any word of the command spells a terminal escape, which makes every value
        # `echo` or `printf` expands one that may carry it; see `TERMINAL_CONTROL_BYTE`.
        self.spells_escape = spells_escape


def _in_scope(absolute: str, scope: _ReadScope) -> bool:
    try:
        return _in_scope_unguarded(absolute, scope)
    except (OSError, ValueError):
        return False  # a path that cannot be resolved is not one to vouch for


def _in_scope_unguarded(absolute: str, scope: _ReadScope) -> bool:
    normal = os.path.normpath(absolute)
    if normal in DEVICE_READS:
        return True
    if _scratch_path_pattern().fullmatch(normal):
        return True
    resolved = os.path.realpath(normal)
    return any(_is_under(normal, root) and _is_under(resolved, root) for root in scope.roots)


VARIABLE_REFERENCE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")


def _resolve_variables(text: str, scope: _ReadScope) -> list[str] | None:
    """Every text this word can become, or None when one reference cannot be resolved.

    `$HOME`, a name assigned a literal value in this command, and a `for` variable whose list
    is all literals are resolved; `${x%%:*}`, `$1`, a `read` variable and every other form
    are not. The fan-out is capped, because a word built from three loop variables of twenty
    values each is not something to enumerate on every Bash call.
    """
    texts = [text]
    for _ in range(8):
        if not any("$" in candidate for candidate in texts):
            return texts
        expanded: list[str] = []
        for candidate in texts:
            match = VARIABLE_REFERENCE.search(candidate)
            if match is None:
                return None  # a `$` in some other form
            name = match.group(1) or match.group(2)
            if name == "HOME":
                values = [_home()]
            elif name in scope.splice_vars:
                values = [" ".join(scope.splice_vars[name])]
            elif name in scope.loop_values:
                values = scope.loop_values[name]
            else:
                return None
            for value in values:
                expanded.append(candidate[: match.start()] + value + candidate[match.end() :])
        if len(expanded) > 64:
            return None
        texts = expanded
    return None


def _read_scope_problem(
    token: str, text: str, parts: list[tuple[str, str]], scope: _ReadScope
) -> str | None:
    """Why a reader's file operand is not in scope, or None when it is."""
    whole = PLACEHOLDER.fullmatch(token)
    if whole is not None and parts[int(whole.group(1))][0] == PROCESS_SUBSTITUTION:
        return None  # `<(...)`: a pipe whose body was classified, not a path on disk
    if text == "-":
        return None
    if SUBSTITUTION_MARKER in text:
        return "a path produced by a command"
    if token.startswith("~"):
        text = os.path.expanduser(text)
    candidates = _resolve_variables(text, scope)
    if candidates is None:
        return "a path this module cannot resolve"
    for candidate in candidates:
        candidate = _expand_home(candidate, tilde=False)
        if _carries_live_glob(token):
            # The directory the glob runs in: everything up to the last `/` before it.
            head = PATH_SPECIAL.split(candidate, 1)[0]
            candidate = head.rsplit("/", 1)[0] if "/" in head else "."
        absolutes = (
            [candidate]
            if candidate.startswith("/")
            else [os.path.join(base, candidate) for base in scope.bases]
        )
        for absolute in absolutes:
            if not _in_scope(absolute, scope):
                return f"outside the working directories: {candidate}"
    return None


# How each known reader takes its arguments. `pattern` is a first operand that is a
# pattern, script or filter rather than a file -- unless a flag in `script_flags` supplied
# it. `values` take a following argument that is not a file; `files` take one that is.
# `pairs` take two, of which the second is a file when the flag is in `pair_files`. A flag
# missing from every set is treated as taking nothing, so its neighbour is checked as a
# file: a mistake in this table costs a prompt, never a skipped path.
READER_SPECS = {
    "cat": {},
    "tac": {"values": {"-s", "--separator"}},
    "rev": {},
    "head": {"values": {"-n", "-c", "--lines", "--bytes"}},
    "tail": {"values": {"-n", "-c", "--lines", "--bytes", "-s", "--sleep-interval", "--pid"}},
    "grep": {
        "pattern": True,
        "script_flags": {"-e", "--regexp", "-f", "--file"},
        "values": {
            "-e",
            "--regexp",
            "-m",
            "--max-count",
            "-A",
            "-B",
            "-C",
            "--after-context",
            "--before-context",
            "--context",
            "--include",
            "--exclude",
            "--exclude-dir",
            "--color",
            "--colour",
            "--label",
            "-d",
            "-D",
            "--devices",
            "--directories",
            "--binary-files",
            "--group-separator",
        },
        "files": {"-f", "--file", "--exclude-from"},
    },
    "sed": {
        "pattern": True,
        "script_flags": {"-e", "--expression", "-f", "--file"},
        "values": {"-e", "--expression", "-l", "--line-length"},
        "files": {"-f", "--file"},
    },
    "awk": {
        "pattern": True,
        "script_flags": {"-f", "--file"},
        "values": {"-v", "-F", "--assign", "--field-separator"},
        "files": {"-f", "--file"},
    },
    "jq": {
        "pattern": True,
        "script_flags": {"-f", "--from-file"},
        "values": {"--indent", "--seq"},
        "files": {"-f", "--from-file", "-L"},
        "pairs": {"--arg", "--argjson", "--slurpfile", "--rawfile"},
        "pair_files": {"--slurpfile", "--rawfile"},
        "positional_stop": {"--args", "--jsonargs"},
    },
    "wc": {"files": {"--files0-from"}},
    "sort": {
        "values": {
            "-k",
            "--key",
            "-t",
            "--field-separator",
            "-S",
            "--buffer-size",
            "-T",
            "--temporary-directory",
            "--parallel",
            "--batch-size",
        },
        "files": {"--files0-from"},
    },
    "uniq": {"values": {"-f", "-s", "-w", "--skip-fields", "--skip-chars", "--check-chars"}},
    "cut": {
        "values": {
            "-f",
            "-d",
            "-c",
            "-b",
            "--fields",
            "--delimiter",
            "--characters",
            "--bytes",
            "--output-delimiter",
        }
    },
    "diff": {
        "values": {
            "-U",
            "-C",
            "--unified",
            "--context",
            "--label",
            "-I",
            "--ignore-matching-lines",
            "-x",
            "--exclude",
            "-W",
            "--width",
        },
        "files": {"-X", "--exclude-from", "--from-file", "--to-file"},
    },
    "cmp": {"values": {"-i", "--ignore-initial", "-n", "--bytes"}},
    "comm": {"values": {"--output-delimiter"}},
    "join": {"values": {"-1", "-2", "-j", "-t", "-o", "-e"}},
    "paste": {"values": {"-d", "--delimiters"}},
    "nl": {"values": {"-b", "-d", "-f", "-h", "-i", "-l", "-n", "-s", "-v", "-w"}},
    "od": {
        "values": {
            "-A",
            "-j",
            "-N",
            "-t",
            "-w",
            "--address-radix",
            "--skip-bytes",
            "--read-bytes",
            "--format",
            "--width",
        }
    },
    "xxd": {"values": {"-c", "-g", "-l", "-s", "-o", "-cols", "-len", "-seek"}},
    "md5sum": {},
    "sha1sum": {},
    "sha256sum": {},
    "shasum": {"values": {"-a", "--algorithm"}},
    "stat": {"values": {"-c", "--format", "--printf"}},
    "file": {
        "values": {"-F", "--separator", "-e", "--exclude", "-P", "--parameter"},
        "files": {"-m", "--magic-file", "-f", "--files-from"},
    },
    "du": {
        "values": {
            "-d",
            "--max-depth",
            "-B",
            "--block-size",
            "-t",
            "--threshold",
            "--exclude",
            "--time-style",
        },
        "files": {"--files0-from", "-X", "--exclude-from"},
    },
    "ls": {
        "values": {
            "-I",
            "--ignore",
            "-w",
            "--width",
            "--format",
            "--sort",
            "--time",
            "-T",
            "--tabsize",
            "--color",
            "--block-size",
            "--hide",
            "--indicator-style",
            "--quoting-style",
            "--time-style",
        }
    },
    "column": {
        "values": {
            "-s",
            "-c",
            "-o",
            "-N",
            "-R",
            "-H",
            "-W",
            "--separator",
            "--output-separator",
            "--table-columns",
        }
    },
    "date": {
        "operands_are_not_files": True,
        "values": {"-d", "--date", "-I", "--iso-8601", "--rfc-3339"},
        "files": {"-r", "--reference", "-f", "--file"},
    },
}
READER_SPECS["egrep"] = READER_SPECS["fgrep"] = READER_SPECS["grep"]
READER_SPECS["gawk"] = READER_SPECS["awk"]


def _file_operands(program: str, args: list[str]) -> list[int]:
    """Indexes into `args` of the words this reader will open as files."""
    spec = READER_SPECS[program]
    values = spec.get("values", set())
    files = spec.get("files", set())
    pairs = spec.get("pairs", set())
    pair_files = spec.get("pair_files", set())
    script_flags = spec.get("script_flags", set())
    stop_flags = spec.get("positional_stop", set())
    operands_are_files = not spec.get("operands_are_not_files", False)

    found: list[int] = []
    pattern_pending = bool(spec.get("pattern"))
    positional_stop = False
    options_done = False
    index = 0
    while index < len(args):
        arg = args[index]
        if not options_done and arg == "--":
            options_done = True
            index += 1
            continue
        if not options_done and arg.startswith("-") and arg != "-":
            flag, _, attached = arg.partition("=") if arg.startswith("--") else (arg, "", "")
            if not arg.startswith("--") and len(arg) > 2 and arg[:2] in files | values:
                flag, attached = arg[:2], arg[2:]  # `-fFILE`, `-n5`
            if flag in script_flags:
                pattern_pending = False
            if flag in stop_flags:
                positional_stop = True
            if flag in pairs:
                if flag in pair_files and index + 2 < len(args):
                    found.append(index + 2)
                index += 3
                continue
            if flag in files:
                if attached:
                    found.append(index)
                    index += 1
                else:
                    if index + 1 < len(args):
                        found.append(index + 1)
                    index += 2
                continue
            if flag in values and not attached:
                index += 2
                continue
            index += 1
            continue
        if pattern_pending:
            pattern_pending = False
        elif operands_are_files and not positional_stop:
            found.append(index)
        index += 1
    return found


def _scratch_path_pattern() -> "re.Pattern[str]":
    """This session's scratch directory, or anything under it, as a whole-path pattern."""
    override = os.environ.get(SCRATCH_ENV, "").rstrip("/")
    path = (
        re.escape(override) + SCRATCH_COMPONENT + "*"
        if override
        else (SCRATCH_PATH.rstrip("+") + "*")
    )
    return re.compile(path)


def _scratch_redirect() -> "re.Pattern[str]":
    """The redirection shape that writes into this session's scratch directory.

    Built per call rather than at import so that `SH_AUTO_APPROVE_SCRATCH` can name an
    exact directory -- which is what the tests do, and what a deployment should do if the
    layout below ever changes. `re.compile` caches, so this costs nothing after the first.
    """
    override = os.environ.get(SCRATCH_ENV, "").rstrip("/")
    path = re.escape(override) + SCRATCH_COMPONENT + "+" if override else SCRATCH_PATH
    return re.compile(r"(?<![^\s;|&(])&?>>?\s*(?:" + path + r")(?=[\s;|&)]|$)")


def _readable_input_target(target: str, parts: list[tuple[str, str]]) -> bool:
    """Whether ``< target`` names a file the operator wrote out, not one the shell computes.

    The pseudo-device check in ``_classify`` reads literal text, so a target assembled at
    runtime -- ``"$x$y"``, ``"/dev/"'tcp/h/80'``, a glob -- is exactly what it cannot see.
    Such a target is left in place for ``_segments`` to refuse as an unaccounted ``<``.
    """
    if re.search(r"[$*?\[\]{}`\\]", PLACEHOLDER.sub("", target)):
        return False
    for index in PLACEHOLDER.findall(target):
        kind, value = parts[int(index)]
        if kind == SUBSTITUTION or (kind == DOUBLE_QUOTED and "$" in value):
            return False
    expanded = PLACEHOLDER.sub(lambda match: parts[int(match.group(1))][1], target)
    if NETWORK_DEVICE.search(expanded) is not None:
        return False
    # The read scope applies to `<` as it does to an operand: a target outside the working
    # directories is left in place, and `_segments` refuses it as an unaccounted `<`.
    if target.startswith("~"):
        expanded = os.path.expanduser(expanded)
    if expanded.startswith("/"):
        scope = _ReadScope([os.path.realpath(REPO_ROOT)], [str(REPO_ROOT)], {}, {})
        return _in_scope(expanded, scope)
    return ".." not in Path(expanded).parts


def _classify(command: str, depth: int = 0) -> None:
    """Raise ``NotReadOnly`` with the reason, or return having found none."""
    if depth > MAX_SUBSTITUTION_DEPTH:
        raise NotReadOnly("substitution nested too deeply")

    # Enforce host length cap
    if len(command) > HOST_COMMAND_LENGTH_CAP:
        raise NotReadOnly("command exceeds length cap")

    # A placeholder has to be unforgeable for the reduced command to mean anything
    if PLACEHOLDER_MARK in command:
        raise NotReadOnly("control character in command")

    # Bash ends a string at a NUL byte, so a command containing one is a different command
    # to bash than to this module; and no path containing one can be resolved to check it.
    if "\x00" in command or "\x02" in command:
        raise NotReadOnly("NUL or reserved control byte in command")

    # See `TERMINAL_CONTROL_BYTE`; the spelled forms are read in `_check_command`.
    if TERMINAL_CONTROL_BYTE.search(command):
        raise NotReadOnly("terminal control byte in command")

    reduced, parts = _scan(command)

    # A substitution runs a command wherever it sits, so each body is classified by these
    # same rules before the word it produces is looked at.
    for kind, value in parts:
        if kind in RUNS_A_COMMAND:
            _classify(value, depth + 1)

    # Layer B: no word may name a credential store, whatever program it belongs to and
    # whatever tier would otherwise approve it.
    _refuse_credential_paths(reduced, parts)

    # `/dev/tcp/host/port` opens a socket with no program involved, so it is refused
    # wherever it appears -- as an operand, behind `<`, and inside a quoted word -- rather
    # than left to a per-program validator that would never see it.
    for text in [reduced] + [value for _, value in parts]:
        if NETWORK_DEVICE.search(text):
            raise NotReadOnly("network pseudo-device")

    # `${var@P}` and the Bash 5.3 `${ ...; }` forms substitute without spelling `$(`,
    #  so they are looked for everywhere the shell would still expand: the unquoted command,
    # and inside every `"..."`. A copy inside `'...'` is the inert text bash treats it as.
    # `${name:=value}` is the third: it runs nothing, and it hands the *next* command a
    # value -- a writing flag, or a new `PATH` -- with no `name=` anywhere to be found.
    # The rest re-evaluate a value the module never read; see `SUBSCRIPT` and
    # `ZSH_PARAMETER_FLAGS` for what each one runs.
    for text in [reduced] + [value for kind, value in parts if kind == DOUBLE_QUOTED]:
        if PARAMETER_TRANSFORM.search(text) or BRACE_SUBSTITUTION.search(text):
            raise NotReadOnly("deferred command substitution")
        if PARAMETER_ASSIGN.search(text):
            raise NotReadOnly("assignment inside a parameter expansion")
        if (
            ARITHMETIC_BRACKET.search(text)
            or SUBSCRIPT.search(text)
            or SUBSTRING.search(text)
            or INDIRECT.search(text)
        ):
            raise NotReadOnly("arithmetic over a value the module did not read")
        if ZSH_PARAMETER_FLAGS.search(text) or ZSH_GLOB_SUBST.search(text):
            raise NotReadOnly("zsh expansion that re-evaluates a value")

    # Normalize stream discards before tokenization, then the two redirections that are
    # reads or contained writes. Everything `_segments` still meets after this is a `>` at
    # a path this module could not account for, which is the one it has to refuse.
    stripped = SAFE_REDIRECTS.sub(" ", reduced)
    stripped = _scratch_redirect().sub(" ", stripped)
    stripped = FILE_INPUT_REDIRECT.sub(
        lambda match: " " if _readable_input_target(match.group(1), parts) else match.group(0),
        stripped,
    )

    # A newline separates commands exactly as `;` does, but shlex counts it as
    # whitespace and glues `ls\nrm` into one word, so the split happens here. A newline
    # inside a quoted string is in the table by now, so it no longer reaches this.
    segments: list[list[str]] = []
    for line in stripped.split("\n"):
        segments.extend(_segments(_tokenize(line)))
    if not segments:
        raise NotReadOnly("no command")

    allow, deny = _operator_rules()

    # Loop variables whose `in` list is all literal non-flag words. Collected across every
    # segment first, because the header that binds a name and the body that uses it are
    # separate segments, and `_strip_structure` discards the header. A bare `"$name"` of
    # one of these is exempt from the flag check inside `_check_command`; nothing else is.
    safe_names = _safe_loop_names(segments, parts)

    # Variables assigned a fully literal value in this command. A `$name`/`${name}`/`${=name}`
    # that uses one is spliced into its words and checked as the flags it is, which is how a
    # `_p='--profile x --region y'` hoisted out of repeated vendor calls stops prompting.
    splice_vars = _literal_assignments(segments, parts)

    # Where readers may read. Relative paths are resolved against the project and against
    # every `cd` target in the command, and must be in scope from all of them: a `cd` inside a
    # subshell or a pipeline does not move the shell that runs the next command, so the module
    # does not guess which one applies.
    bases = [str(REPO_ROOT)]
    for segment in segments:
        if segment and _expand(segment[0], parts) == "cd" and len(segment) == 2:
            target = _expand(segment[1], parts)
            if "$" not in target and not target.startswith(("~", "-")):
                bases.append(os.path.normpath(os.path.join(str(REPO_ROOT), target)))
    if _SESSION_CWD and os.path.isabs(_SESSION_CWD):
        bases.append(_SESSION_CWD)
    scope = _ReadScope(
        roots=[os.path.realpath(REPO_ROOT)],
        bases=bases,
        splice_vars=splice_vars,
        loop_values=_literal_loop_values(segments, parts),
        spells_escape=bool(TERMINAL_CONTROL_SPELLED.search(command)),
    )

    # A substitution body is work that was inspected, so `x=$(grep -c . AGENTS.md)` has
    # something to show for itself even though the assignment it sits in is skipped.
    checked = sum(1 for kind, _ in parts if kind in RUNS_A_COMMAND)
    for segment in segments:
        words = _strip_structure(segment)
        if not words:
            continue
        text = " ".join(_expand(word, parts) for word in words)
        if any(pattern.match(text) for pattern in deny):
            raise NotReadOnly(f"a deny rule matches: {text}")
        try:
            _check_command(
                words, parts, safe_names=safe_names, splice_vars=splice_vars, scope=scope
            )
        except NoOpinion:
            # The module cannot read this one. It can still be something the operator has
            # already granted in this exact shape, which is the second tier.
            if not any(pattern.match(text) for pattern in allow):
                raise
        checked += 1

    if checked == 0:
        raise NotReadOnly("nothing to check")


def is_read_only(command: str) -> bool:
    """Whether every command in ``command`` is provably read-only."""
    try:
        _classify(command)
    except NotReadOnly:
        return False
    except RecursionError:
        return False
    return True


def _project_root(cwd: str | None) -> Path | None:
    """The project this session works in, or ``None`` when there is none to vouch for.

    ``$CLAUDE_PROJECT_DIR`` first, because it does not follow a ``cd``. Without it, the
    worktree enclosing the session's directory, found by looking for a ``.git`` entry
    rather than by running ``git``, which would read that repository's config. The home
    directory and ``/`` are refused even when they qualify: a dotfiles repository makes
    ``$HOME`` a worktree, and every read beneath it would be in scope.
    """
    candidate = os.environ.get(PROJECT_DIR_ENV) or None
    if candidate is None and cwd:
        here = Path(cwd)
        candidate = next(
            (str(p) for p in (here, *here.parents) if os.path.lexists(p / ".git")), None
        )
    if candidate is None or not os.path.isabs(candidate):
        return None
    root = Path(os.path.realpath(candidate))
    if not root.is_dir() or root == Path(root.anchor) or root == Path.home().resolve():
        return None
    return root


def main() -> int:
    """Claude Code PreToolUse hook entry point."""
    if sys.version_info < MINIMUM_PYTHON or sys.platform not in SUPPORTED_PLATFORMS:
        return 0
    try:
        payload = json.load(sys.stdin)
        if payload.get("tool_name") != "Bash":
            return 0
        command = payload.get("tool_input", {}).get("command", "")
        if not isinstance(command, str) or not command.strip():
            return 0
        # Claude Code's shell keeps its working directory between calls, so a relative path
        # is read from wherever the session last stood. The payload says where that is.
        global _SESSION_CWD, REPO_ROOT
        cwd = payload.get("cwd")
        _SESSION_CWD = os.path.realpath(cwd) if isinstance(cwd, str) and cwd else None
        root = _project_root(_SESSION_CWD or os.getcwd())
        if root is None:
            return 0
        REPO_ROOT = root
        if not is_read_only(command):
            return 0

        json.dump(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "allow",
                    "permissionDecisionReason": (
                        "every command only reads, or already matches an allow rule"
                    ),
                }
            },
            sys.stdout,
        )
    except Exception:
        # Fall back to silence on any unexpected error or malformed input
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
