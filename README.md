# ttk-sh-auto-approve

A [Claude Code](https://code.claude.com/docs) plugin with 2 hooks:

- A `PreToolUse` hook that auto-approves Bash commands it can prove are read-only, and `curl`
  GETs of the documentation sites a project lists (see [`curl`](#curl)). Everything else,
  including errors, timeouts and unexpected input, goes through Claude Code's normal permission
  prompt.
- A `PostToolUse` hook that restores the final newline a `Write` or `Edit` left out. A `Write`
  approved at a permission prompt saves the file without one.

> **Status:** not released yet. Requires Python 3.12 or later on Linux or macOS;
> anywhere else both hooks do nothing, and every command prompts.

## The Bash tool may run zsh

> [!WARNING]
> Despite its name, Claude Code's Bash tool runs each command in your login shell when that is
> bash or zsh (zsh is the macOS default), or in the shell `CLAUDE_CODE_SHELL` names.
> The aliases and functions from your shell startup file apply too.
>
> So the hook checks every command against both grammars, and refuses anything only one of them
> would expand. What it can't see is your aliases: if one turns a read-only program such as `ls`
> or `grep` into something that writes, the hook still approves it.

## Secrets inside your project

> [!WARNING]
> The hook approves reads anywhere inside the project, its `additionalDirectories` and the
> session's scratchpad, and a secret kept there is a file like any other: `cat .env` and
> `grep -r PASSWORD .` are approved.
>
> The hook refuses a command that names a credential store under your home directory, such as
> `~/.aws` or `~/.ssh`, but refusing only leaves the call to Claude Code. Claude Code runs a
> built-in set of read-only commands, `cat` and `grep` among them, without a permission prompt in
> every mode, except as `permissions.blockReadsOutsideWorkingDirectories` changes for paths
> outside your working directories. So it runs `cat .env` unprompted with or without the hook.
>
> What stops these reads is Claude Code's own settings
> ([permissions](https://code.claude.com/docs/en/permissions)):
>
> - A `Read()` deny rule, such as `Read(//**/.env)` in `~/.claude/settings.json`. Claude Code
>   applies it even when a hook approves: to its own file tools, to the targets of redirections,
>   and to the file commands it recognizes in Bash, such as `cat`, `head` and `tail`. It doesn't
>   apply to a command that reads a file without naming it, such as `grep -r PASSWORD .`
> - `Read(//**/.env)` matches only files named `.env`: `.env.local` and the like need a rule of
>   their own, such as `Read(//**/.env.*)`
> - `permissions.blockReadsOutsideWorkingDirectories`, for paths outside your working directories
>
> The hook reads `additionalDirectories` only from the project's `.claude/settings.json` and
> `.claude/settings.local.json`, and only where Claude Code applies them: in a workspace you
> trusted, from a setting source the session loaded. It drops an entry that is or contains your
> home directory, or that is, contains or sits inside a credential store; each entry it keeps
> widens what it may read.

## `curl`

The approval hook also approves a `curl` GET of one page on a site the project lists, such as
`curl -s 'https://docs.python.org/3/' | grep -n asyncio`. It is the one approval that makes a
network call:

- What leaves the machine: a GET, with a URL Claude wrote, to a site the project lists. A
  poisoned context can put a secret it has read into that URL, which only that site's servers
  receive. Hence exact hosts, and no userinfo, redirect, proxy or `--resolve`
- What comes in: the page, into Claude's context. Hence
  [what to leave out of the list](#what-to-leave-out-of-the-list)
- One URL per `curl`, and no `curl` the shell may not wait for, behind `&` or in a process
  substitution, so the Bash tool's timeout bounds every request

### The list

The project's `WebFetch` allow rules are the list: `curl` may fetch a site where Claude may
already fetch it without asking. The hook reads them from the files it reads `Bash` rules from,
`.claude/settings.json` and `.claude/settings.local.json` in the project, and only where Claude
Code applies them, as for `additionalDirectories` above:

```json
{
  "permissions": {
    "allow": [
      "WebFetch(domain:docs.github.com)",
      "WebFetch(domain:docs.python.org)"
    ]
  }
}
```

- A rule lists a site only when its domain is an exact host name, written as above, with no
  whitespace or capital letter. `WebFetch` alone lists nothing, and neither does a wildcard such
  as `WebFetch(domain:*.github.io)`, which would take in every user's site
- A `WebFetch` deny or ask rule takes the hosts it covers off the list, from these settings files
  and also from:
  - your user settings, `~/.claude/settings.json`, or `settings.json` in `CLAUDE_CONFIG_DIR`
  - the managed settings: `managed-settings.json` and the `*.json` files in
    `managed-settings.d/`, under `/etc/claude-code/` on Linux and
    `/Library/Application Support/ClaudeCode/` on macOS. Managed settings from the server or a
    macOS configuration profile are out of the hook's view
- An allow rule in your user settings lets `WebFetch` fetch a site and not `curl`
- With no rule, `curl` prompts as it did before. So does every `curl` while one of the files above
  exists and can't be read, and while managed settings set `allowManagedPermissionRulesOnly`
- A `Bash` ask rule such as `Bash(curl *)` still prompts: Claude Code evaluates deny and ask rules
  whatever a hook returns. Narrow it or drop it

Who can add a site: Claude Code treats `.claude/` as a protected directory, and its
[permission modes](https://code.claude.com/docs/en/permission-modes) page says that writes to
protected paths are never auto-approved except in `bypassPermissions` mode. This hook approves no
Bash command that writes there either. Answering a `WebFetch` prompt with "don't ask again" for a
domain saves its rule in `.claude/settings.local.json`, which lists the site for `curl` as well.
A repository can commit `.claude/settings.json`, so one you clone can list sites, as it can allow
`Bash` commands.

### What to leave out of the list

- Sites where anyone can publish, whose pages would enter Claude's context unreviewed:
  `github.com`, `gist.github.com`, `raw.githubusercontent.com`, `gist.githubusercontent.com`,
  `discuss.python.org`, `bugs.python.org`, `pypi.org`, `claude.ai`. A `WebFetch` rule for one of
  them goes in your user settings instead
- APIs, which aren't docs: `api.github.com` (the hook reads `gh api` GETs), `api.anthropic.com`
- Sites that only redirect, since `-L` prompts: `docs.anthropic.com` and `docs.claude.com`
  answer 301 to `platform.claude.com`, which is the host to list

### What it approves

- The flags, alone or bundled (`-sSf`): `-s`/`--silent`, `-S`/`--show-error`, `-f`/`--fail`,
  `--fail-with-body`, `-I`/`--head`, `-i`/`--include`, `--compressed`, `-m`/`--max-time` and
  `--connect-timeout` with a number of seconds, and `-q`/`--disable` as the first argument.
  A long option is read only when written whole
- One URL: `https://`, then a listed host, which ends at the first `/`, `?` or `#`, so no
  userinfo, port, IP address, trailing dot, percent-encoding or capital letter. The path and the
  query are free, save for `{`, `}`, `[` and `]` (curl's globbing), a backslash, whitespace and
  control characters
- Every word written out: no `$`, arithmetic or command substitution, unquoted wildcard or tilde,
  and no word spliced in from a variable
- No job behind `&` anywhere in the command, and no `curl` in a process substitution, `<(...)`

Anything else prompts, as it did before. That includes `-L`: curl follows a redirect to any host,
and nothing in the command says which. Rerun with the final URL, or list the final host. `-o`
prompts too; redirect stdout into the session's scratchpad instead, which the hook approves:
`curl -s '<url>' > <scratchpad>/page.html`.

### The curlrc

Unless the command starts with `curl -q`, curl reads a curlrc, which can hold any option,
`output` and `upload-file` included, and the command doesn't show it. So the hook leaves `curl`
to the prompt while any of these exists: `$CURL_HOME/.curlrc`, `$CURL_HOME/.config/curlrc`,
`$XDG_CONFIG_HOME/curlrc`, `~/.curlrc` and `~/.config/curlrc`, the last two in the account's home
directory as well. It checks that each exists, and reads none. It also leaves `curl` to the
prompt while one of these variables holds a relative path, which curl reads from wherever the
shell stands. As with aliases, an export of `CURL_HOME`, `XDG_CONFIG_HOME` or `HOME` in your shell
startup file is out of its view.

## Install

Through the things-to-know plugin catalog (not published yet). Until then, from a clone of this
repo, pinned to a commit or following the clone: see [docs/install.md](docs/install.md).

To try it for one session from a clone of this repo:

```bash
claude --plugin-dir ./plugin
```

If you registered either hook yourself, in a `settings.json` or `settings.local.json`, remove
that entry once the plugin is enabled: hooks aren't namespaced, so both copies would run.

## What runs on your machine

A plugin runs with your user privileges. This one registers 2 hooks. Both use only the Python
standard library and make no network calls; the approval hook approves the `curl` GETs above,
which do.

- Before each Bash tool call, `python3 -I plugin/scripts/sh_auto_approve.py`. It writes nothing.
- After each `Write` and `Edit`, `python3 -I plugin/scripts/ensure_final_newline.py`. It appends
  a single newline to the file just written, when that is a non-empty text file without one,
  inside the project, a git repository or `~/.claude`.

## Development

See [AGENTS.md](AGENTS.md) for the layout, the rules the hook follows and how to test it, and
[docs/release.md](docs/release.md) for how releases work.
