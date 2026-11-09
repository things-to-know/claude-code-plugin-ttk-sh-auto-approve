"""Canonical command grammar: parse a small static subset of shell, and re-emit it single-quoted.

A prototype for the approval hook, not wired into it. The hook would read Claude's command with
`parse`, validate the argv and redirections it gets, and on approval return `serialize(...)` as
``hookSpecificOutput.updatedInput.command``. What runs is the serialized text, so safety rests on
two things only:

1. `serialize` is exact: in bash and in zsh, its output evaluates to the argv and redirections the
   validators saw, and to nothing else. Every word is single-quoted, and the command word goes
   behind ``command`` (or ``builtin`` for the few that must run in the shell), which skips aliases,
   and functions in both shells.
2. The validators are right about that argv (program semantics, paths): unchanged from today.

`parse` does not have to agree with any shell for safety. A misreading only changes what runs to
something the validators approved anyway. It does have to agree with bash for usability, which is
what ``equiv.py`` measures.

Accepted: simple commands joined by ``|``, ``&&``, ``||``, ``;`` and newlines; words made of
unquoted literal characters, ``'...'`` and ``"..."`` without ``$`` or backquotes, and backslash
escapes; comments; ``[n]< file``; ``[n]>``, ``[n]>>``, ``[n]>|``, ``&>`` and ``&>>`` to
``/dev/null`` only; ``[n]>&m`` for digits m. Everything else raises `Reject` with a category.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Reserved words of bash or zsh: unquoted in command position, each starts a construct this
# grammar doesn't take
RESERVED = frozenset(
    [
        "if",
        "then",
        "else",
        "elif",
        "fi",
        "case",
        "esac",
        "for",
        "select",
        "while",
        "until",
        "do",
        "done",
        "function",
        "time",
        "coproc",
        "in",
        "repeat",
        "foreach",
        "end",
        "{",
        "}",
        "!",
        "[[",
        "]]",
        "((",
    ],
)
# Precommand modifiers and the like: each changes how the next word is run
PRECOMMAND = frozenset(
    ["command", "builtin", "exec", "eval", "noglob", "nocorrect", "-", "source", ".", "nohup"]
)

# Run as builtins: they act on the shell itself, or have no external program on a stock system.
# Everything else goes behind `command`, so zsh runs the external (`/usr/bin/printf`, not zsh's
# arithmetic-evaluating builtin) and bash its builtin or the external, never a function.
KEEP_BUILTIN = frozenset({"cd", "pwd", "type"})

ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\+?=")
OPERATOR_CHARS = frozenset("|&;<>()")
GLOB_CHARS = frozenset("*?[")
# What ends a word: whitespace and the operator characters
WORD_END = frozenset(" \t\n;|&<>")
DELETE = 127


class Reject(Exception):  # noqa: N818 - a verdict, not an error
    """The command is outside the grammar; `category` names the construct."""

    def __init__(self, category: str, detail: str = "") -> None:
        """Name the construct, with an excerpt of where it was found."""
        super().__init__(f"{category}: {detail}" if detail else category)
        self.category = category
        self.detail = detail


@dataclass
class Word:
    """A word after quote removal, and what is needed to read it in command position."""

    value: str = ""
    # The source text when no part of the word was quoted or escaped: reserved words,
    # assignments and fd prefixes are only recognized then
    plain: str | None = ""
    # Set only in lenient mode: an unquoted pattern character, a leading tilde or a brace
    # expansion, which the hook would have to expand itself before serializing
    pattern: bool = False

    def add(self, text: str, *, quoted: bool) -> None:
        """Append `text`, as written quoted or unquoted."""
        self.value += text
        if quoted:
            self.plain = None
        elif self.plain is not None:
            self.plain += text


@dataclass
class Redirect:
    """A redirection, with its fd always explicit."""

    fd: int
    op: str  # '<', '>' or '>&'
    target: str  # a path for '<' and '>' ('/dev/null' only for '>'), digits for '>&'


@dataclass
class Simple:
    """A simple command: its argv, its redirections, and which argv words hold a pattern."""

    argv: list[str]
    redirects: list[Redirect] = field(default_factory=list)
    pattern_words: list[int] = field(default_factory=list)


@dataclass
class Pipeline:
    """Simple commands joined by ``|``."""

    commands: list[Simple]


@dataclass
class CommandList:
    """Pipelines, each with the connector before it: None, then ``;``, ``&&`` or ``||``."""

    items: list[tuple[str | None, Pipeline]]


# ----------------------------------------------------------------------------------------------
# Lexer
# ----------------------------------------------------------------------------------------------


@dataclass
class Token:
    """A word, an operator or a redirection operator, the last with the fd written before it."""

    kind: str  # 'word', 'op' or 'redir'
    word: Word | None = None
    op: str = ""
    fd: int | None = None


def _dollar_category(text: str, i: int) -> str:
    follow = text[i + 1 : i + 3]
    if follow.startswith("(("):
        return "arithmetic"
    if follow.startswith("("):
        return "command-substitution"
    if follow.startswith("'"):
        return "ansi-c-quote"
    if follow.startswith('"'):
        return "locale-quote"
    return "parameter-expansion"


def _control(char: str) -> bool:
    return ord(char) < ord(" ") or ord(char) == DELETE


def lex(text: str, *, lenient: bool = False) -> list[Token]:
    """Split `text` into tokens, rejecting any construct outside the grammar.

    With `lenient`, unquoted patterns, a leading tilde and brace expansions are kept, the word
    marked `pattern`, so that coverage can count what hook-side expansion would add.
    """
    tokens: list[Token] = []
    word: Word | None = None
    i, n = 0, len(text)

    def flush() -> None:
        nonlocal word
        if word is not None:
            tokens.append(Token("word", word=word))
            word = None

    def current() -> Word:
        nonlocal word
        if word is None:
            word = Word()
        return word

    while i < n:
        c = text[i]
        if c in " \t":
            flush()
            i += 1
        elif c == "\n":
            flush()
            tokens.append(Token("op", op="\n"))
            i += 1
        elif c == "#" and word is None:
            end = text.find("\n", i)
            i = n if end < 0 else end
        elif c in OPERATOR_CHARS:
            fd = None
            if c in "<>" and word is not None and word.plain and word.plain.isdigit():
                fd = int(word.plain)  # `2>`: the digits are the redirection's fd, not a word
                word = None
            flush()
            i = _lex_operator(text, i, tokens, fd)
        elif c == "\\":
            if i + 1 >= n:
                raise Reject("syntax", "trailing backslash")
            if text[i + 1] != "\n":  # a backslash before a newline continues the line
                current().add(text[i + 1], quoted=True)
            i += 2
        elif c == "'":
            end = text.find("'", i + 1)
            if end < 0:
                raise Reject("syntax", "unterminated single quote")
            current().add(text[i + 1 : end], quoted=True)
            i = end + 1
        elif c == '"':
            i = _lex_double_quoted(text, i, current())
        elif c == "$":
            raise Reject(_dollar_category(text, i), text[i : i + 12])
        elif c == "`":
            raise Reject("command-substitution", "backquote")
        elif c in GLOB_CHARS:
            # `[` standing alone is the test command in both shells, not a pattern
            if c == "[" and word is None and (i + 1 == n or text[i + 1] in WORD_END):
                current().add("[", quoted=False)
            elif not lenient:
                raise Reject("glob", text[max(0, i - 8) : i + 8])
            else:
                current().add(c, quoted=False)
                current().pattern = True
            i += 1
        elif c in "{}":
            at_start = word is None
            i = _lex_brace(text, i, current(), lenient=lenient, at_start=at_start)
        elif c == "~":
            at_start = word is None
            w = current()
            previous = w.plain[-1:] if w.plain else ""
            # No shell expands a tilde mid-word (HEAD~1); bash does after `=` or `:`
            if at_start or previous in ("=", ":"):
                if not lenient:
                    raise Reject("tilde", text[i : i + 12])
                w.pattern = True
            w.add("~", quoted=False)
            i += 1
        elif c == "=" and word is None and i + 1 < n and text[i + 1] not in WORD_END:
            raise Reject("zsh-equals", text[i : i + 12])  # zsh's `=cmd`
        elif _control(c):
            raise Reject("control-character", repr(c))
        else:
            current().add(c, quoted=False)
            i += 1
    flush()
    return tokens


def _lex_double_quoted(text: str, i: int, word: Word) -> int:
    j = i + 1
    n = len(text)
    buffer = []
    while j < n:
        c = text[j]
        if c == '"':
            word.add("".join(buffer), quoted=True)
            return j + 1
        if c == "$":
            raise Reject(_dollar_category(text, j), text[j : j + 12])
        if c == "`":
            raise Reject("command-substitution", "backquote")
        if c == "\\" and j + 1 < n and text[j + 1] in '"\\$`\n':
            if text[j + 1] != "\n":
                buffer.append(text[j + 1])
            j += 2
            continue
        if _control(c) and c not in "\n\t":
            raise Reject("control-character", repr(c))
        buffer.append(c)
        j += 1
    raise Reject("syntax", "unterminated double quote")


def _lex_brace(text: str, i: int, word: Word, *, lenient: bool, at_start: bool) -> int:
    c = text[i]
    after = text[i + 1 : i + 2]
    if at_start and (not after or after in " \t\n;|&"):
        raise Reject("group", c)  # `{` or `}` as a reserved word
    if c == "{":
        # Brace expansion needs a comma or `..` before the closing brace, in both shells
        j = i + 1
        while j < len(text) and text[j] not in " \t\n;|&<>()'\"\\}":
            j += 1
        inner = text[i + 1 : j]
        if j < len(text) and text[j] == "}" and ("," in inner or ".." in inner):
            if not lenient:
                raise Reject("brace-expansion", text[i : j + 1])
            word.pattern = True
    word.add(c, quoted=False)
    return i + 1


def _lex_operator(text: str, i: int, tokens: list[Token], fd: int | None) -> int:
    c = text[i]
    nxt = text[i + 1 : i + 2]
    nxt2 = text[i + 2 : i + 3]
    if c in "()":
        raise Reject("subshell-or-group", c)
    if c == "|":
        if nxt == "|":
            tokens.append(Token("op", op="||"))
            return i + 2
        if nxt == "&":
            raise Reject("pipe-stderr", "|&")
        tokens.append(Token("op", op="|"))
        return i + 1
    if c == "&":
        if nxt == "&":
            tokens.append(Token("op", op="&&"))
            return i + 2
        if nxt == ">":
            op = "&>>" if nxt2 == ">" else "&>"
            tokens.append(Token("redir", op=op, fd=None))
            return i + len(op)
        raise Reject("background", "&")
    if c == ";":
        if nxt in (";", "&"):
            raise Reject("case-terminator", c + nxt)
        tokens.append(Token("op", op=";"))
        return i + 1
    # `<` or `>`, with `fd` the digits written right before it, if any
    if c == "<":
        if nxt == "<":
            raise Reject("herestring" if nxt2 == "<" else "heredoc", text[i : i + 3])
        if nxt == "(":
            raise Reject("process-substitution", "<(")
        if nxt == ">":
            raise Reject("read-write-redirect", "<>")
        if nxt == "&":
            raise Reject("input-fd-dup", "<&")
        tokens.append(Token("redir", op="<", fd=fd))
        return i + 1
    if nxt == "(":
        raise Reject("process-substitution", ">(")
    for op in (">>", ">|", ">&"):
        if text.startswith(op, i):
            tokens.append(Token("redir", op=op, fd=fd))
            return i + 2
    tokens.append(Token("redir", op=">", fd=fd))
    return i + 1


# ----------------------------------------------------------------------------------------------
# Parser
# ----------------------------------------------------------------------------------------------


def parse(text: str, *, lenient: bool = False) -> CommandList:
    """Parse `text`, or raise `Reject` naming the first construct outside the grammar."""
    tokens = lex(text, lenient=lenient)
    pos = 0
    items: list[tuple[str | None, Pipeline]] = []
    connector: str | None = None

    def skip_newlines() -> None:
        nonlocal pos
        while pos < len(tokens) and tokens[pos].kind == "op" and tokens[pos].op == "\n":
            pos += 1

    skip_newlines()
    while pos < len(tokens):
        pipeline, pos = _parse_pipeline(tokens, pos)
        items.append((connector, pipeline))
        if pos >= len(tokens):
            break
        op = tokens[pos].op  # `_parse_simple` only stops at an operator
        pos += 1
        if op in ("&&", "||"):
            connector = op
            skip_newlines()
            if pos >= len(tokens):
                raise Reject("syntax", f"nothing after {op}")
        else:  # ';' or a newline
            connector = ";"
            skip_newlines()
    if not items:
        raise Reject("syntax", "empty command")
    return CommandList(items)


def _parse_pipeline(tokens: list[Token], pos: int) -> tuple[Pipeline, int]:
    commands = []
    while True:
        simple, pos = _parse_simple(tokens, pos)
        commands.append(simple)
        if pos < len(tokens) and tokens[pos].kind == "op" and tokens[pos].op == "|":
            pos += 1
            while pos < len(tokens) and tokens[pos].kind == "op" and tokens[pos].op == "\n":
                pos += 1
            continue
        return Pipeline(commands), pos


def _parse_simple(tokens: list[Token], pos: int) -> tuple[Simple, int]:
    argv: list[str] = []
    redirects: list[Redirect] = []
    pattern_words: list[int] = []
    while pos < len(tokens) and tokens[pos].kind != "op":
        t = tokens[pos]
        if t.kind == "word" and t.word is not None:
            if not argv:
                _check_command_word(t.word)
            if t.word.pattern:
                pattern_words.append(len(argv))
            argv.append(t.word.value)
            pos += 1
            continue
        # A redirection and its target
        target = tokens[pos + 1].word if pos + 1 < len(tokens) else None
        if target is None:
            raise Reject("syntax", f"{t.op} without a target")
        if target.pattern:
            raise Reject("glob", "in a redirection target")
        redirects.extend(_redirect(t, target.value))
        pos += 2
    if not argv:
        raise Reject("syntax", "no command word")
    fds = [r.fd for r in redirects]
    if len(fds) != len(set(fds)):
        # zsh's MULTIOS tees or concatenates a doubly redirected fd; bash keeps the last one
        raise Reject("duplicate-fd-redirect", str(fds))
    return Simple(argv, redirects, pattern_words), pos


def _check_command_word(w: Word) -> None:
    if w.plain is not None:
        if ASSIGNMENT.match(w.plain):
            raise Reject("assignment", w.plain)
        if w.plain in RESERVED:
            raise Reject("reserved-word", w.plain)
        if w.plain in PRECOMMAND:
            raise Reject("precommand", w.plain)
    if not w.value or w.value.startswith("-"):
        raise Reject("syntax", f"command word {w.value!r}")


def _redirect(t: Token, target: str) -> list[Redirect]:
    if t.op == "<":
        return [Redirect(0 if t.fd is None else t.fd, "<", target)]
    if t.op in (">", ">>", ">|"):
        if target != "/dev/null":
            raise Reject("output-redirect", target)
        return [Redirect(1 if t.fd is None else t.fd, ">", target)]
    if t.op in ("&>", "&>>"):
        if target != "/dev/null":
            raise Reject("output-redirect", target)
        return [Redirect(1, ">", target), Redirect(2, ">&", "1")]
    if t.op == ">&":
        if target.isdigit():
            return [Redirect(1 if t.fd is None else t.fd, ">&", target)]
        if target == "/dev/null" and t.fd is None:  # bash reads `>&file` as `&>file`
            return [Redirect(1, ">", target), Redirect(2, ">&", "1")]
        raise Reject("fd-close" if target == "-" else "output-redirect", target)
    raise Reject("syntax", t.op)


# ----------------------------------------------------------------------------------------------
# Serializer: the part the hook's safety would rest on
# ----------------------------------------------------------------------------------------------


def quote(word: str) -> str:
    """Return one shell word that bash and zsh both read as `word` exactly, with no expansion.

    zsh's RC_QUOTES reads `''` inside a quoted string as a quote, but every `''` this produces is
    followed by a backslash or ends the text, so none sits inside one quoted string.
    """
    if "\0" in word:
        raise ValueError("NUL cannot be in an argument")
    return "'" + word.replace("'", "'\\''") + "'"


def serialize(commands: CommandList) -> str:
    """Return the canonical text for `commands`: every word quoted, every fd explicit."""
    parts = []
    for connector, pipeline in commands.items:
        if connector is not None:
            parts.append(connector)
        parts.append(" | ".join(_serialize_simple(s) for s in pipeline.commands))
    return " ".join(parts)


def _serialize_simple(simple: Simple) -> str:
    if simple.pattern_words:
        raise ValueError("a pattern word has to be expanded by the hook before serializing")
    prefix = "builtin" if simple.argv[0] in KEEP_BUILTIN else "command"
    words = [prefix, *map(quote, simple.argv)]
    for r in simple.redirects:
        if r.op == ">&":
            if not r.target.isdigit():
                raise ValueError(f"fd duplication to {r.target!r}")
            words.append(f"{r.fd}>&{r.target}")
        else:
            words.append(f"{r.fd}{r.op}{quote(r.target)}")
    return " ".join(words)


def canonical(text: str) -> str:
    """Parse `text` and return its canonical text, or raise `Reject`."""
    return serialize(parse(text))
