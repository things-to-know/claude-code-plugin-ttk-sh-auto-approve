# Install from a clone

The plugin is to be published through the `things-to-know` plugin catalog. Until then, install
it from a catalog of your own: a directory that holds `.claude-plugin/marketplace.json`, which
lists the plugin in one of two ways.

| Way                   | What your sessions run               | To update                        |
|-----------------------|--------------------------------------|----------------------------------|
| [Pinned](#pinned)     | A commit you name, copied at install | Name another commit, then update |
| [In place](#in-place) | Your clone's working copy            | `git pull` in the clone          |

Pinned is the safer of the two. The hook decides which commands run without a prompt, and in
place, every checkout and every edit in the clone changes that for each session started after it,
unreviewed.

To try the plugin for one session without installing it, from the clone's root:

```sh
claude --plugin-dir ./plugin
```

Checked with Claude Code 2.1.322, except `/reload-plugins`, which comes from
[Claude Code's docs][loading].

## Pinned

1. Write the catalog in a directory of your choice, here `~/claude-plugins`, as
   `~/claude-plugins/.claude-plugin/marketplace.json`:

   ```json
   {
     "name": "my-plugins",
     "description": "Plugins I install from clones",
     "owner": {"name": "me"},
     "plugins": [
       {
         "name": "ttk-sh-auto-approve",
         "description": "Auto-approves Bash commands it can prove are read-only",
         "source": {
           "source": "git-subdir",
           "url": "things-to-know/claude-code-plugin-ttk-sh-auto-approve",
           "path": "plugin",
           "sha": "<sha>"
         }
       }
     ]
   }
   ```

   - `<sha>` is a commit of `main`, all 40 characters: `git rev-parse origin/main` in the
     clone, after a `git fetch`
   - This `url` fetches the commit from GitHub
     - To install a commit of your clone instead: `"url": "file:///<absolute path to the clone>"`
     - Only what is committed reaches the install: an uncommitted edit in the clone doesn't

2. Check the catalog, add it, and install the plugin:

   ```sh
   claude plugin validate ~/claude-plugins
   claude plugin marketplace add ~/claude-plugins
   claude plugin install ttk-sh-auto-approve@my-plugins
   ```

   - `my-plugins` is the catalog's `name`, not its directory's
3. Start a new session, or run `/reload-plugins` in a running one

### Update a pinned install

1. Set `sha` to the new commit
2. Update the plugin:

   ```sh
   claude plugin marketplace update my-plugins
   claude plugin update ttk-sh-auto-approve@my-plugins
   ```

3. Start a new session, or run `/reload-plugins` in each running one: until then, a session keeps
   the hook it loaded

### Check which commit runs

```sh
claude plugin list --json
```

- The plugin's `version` starts with the commit's first 12 characters: `d315e2c64034-5e689e2b`
  for `d315e2c`
- Its `installPath` is the copy sessions load

## In place

The catalog's directory holds the clone: a relative `source` must start with `./`, and Claude Code
refuses one that holds `..`.

```text
~/claude-plugins/
├── .claude-plugin/
│   └── marketplace.json
└── claude-code-plugin-ttk-sh-auto-approve/     the clone
```

1. Write `marketplace.json` as in [Pinned](#pinned), with this `source` instead:

   ```json
   "source": "./claude-code-plugin-ttk-sh-auto-approve/plugin"
   ```

2. Steps 2 and 3 of [Pinned](#pinned)
   - `validate` warns that the plugin has no `version`: it has none on purpose, as `AGENTS.md`
     [§ No `version`](../AGENTS.md#no-version) says

### Update an in-place install

`git pull`, or any checkout, in the clone. It reaches each session at its start, or at
`/reload-plugins`: no `claude plugin update` is needed.

### Check where it runs from

`claude plugin list --json` shows the plugin's `readFromFolder`: the clone's `plugin/`, which
sessions load.

- Its `version` and `installPath` name a copy made at install, which sessions don't load
- A `git pull` changes neither

## Remove

```sh
claude plugin uninstall ttk-sh-auto-approve@my-plugins
claude plugin marketplace remove my-plugins
```

[loading]: https://code.claude.com/docs/en/plugins/loading.md
