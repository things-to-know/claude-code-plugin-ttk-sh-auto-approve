# Release

For the maintainer. Users get a commit of `main` once the catalog they install from names it, so
a release is a change to the catalog, made after the merge.

Checked with Claude Code 2.1.322, except `/reload-plugins`, which comes from
[Claude Code's docs][loading].

## 1. Merge

- Merge the pull request into `main` with CI green, as a merge commit: the only method the
  repository allows
- Check that each issue the pull request fixes closed
  - After #76, #29 and #89 merged, GitHub left those issues open, though it listed the pull
    request as closing each
  - Close such an issue by hand, with a comment naming the merge commit

## 2. Point the catalog at the merge

1. Set this plugin's `source.sha` in the catalog to the merge commit, all 40 characters:

   ```sh
   gh pr view <number> --json mergeCommit --jq .mergeCommit.oid
   ```

   <!-- editorconfig-checker-disable: a JSON string cannot be wrapped -->
   ```json
   {
     "name": "ttk-sh-auto-approve",
     "description": "Auto-approves Bash commands it can prove are read-only, and restores the final newline a Write loses",
     "source": {
       "source": "git-subdir",
       "url": "things-to-know/claude-code-plugin-ttk-sh-auto-approve",
       "path": "plugin",
       "sha": "<sha>"
     }
   }
   ```
   <!-- editorconfig-checker-enable -->

   - Until the `things-to-know` catalog is published, the catalog is a directory of your own, as
     in [Install from a clone](install.md#pinned)
2. Validate it:

   ```sh
   claude plugin validate <catalog directory>
   ```

## 3. Update your installed copy

```sh
claude plugin marketplace update <catalog>
claude plugin update ttk-sh-auto-approve@<catalog>
```

Then start a new session, or run `/reload-plugins` in each running one: until then, a session
keeps the hook it loaded.

## 4. Check it took

From the clone's root, with `<sha>` the merge commit and `<installPath>` the plugin's, as
`claude plugin list --json` shows it:

- The plugin's `version` starts with the merge commit's first 12 characters
- The copy holds the merge commit's hooks:

  ```sh
  cmp <installPath>/scripts/sh_auto_approve.py <(git show <sha>:plugin/scripts/sh_auto_approve.py)
  cmp <installPath>/hooks/hooks.json <(git show <sha>:plugin/hooks/hooks.json)
  ```

- The copy gives a verdict the release changed. For `d315e2c`, which refuses `cat =ls`:

  ```sh
  python3 -I -B tools/explain.py --project "$PWD" \
    --hook <installPath>/scripts/sh_auto_approve.py 'cat =ls'
  ```

  prints `refused`, with `zsh replaces a word with the path of a command: =ls`

## 5. Users

- Users of the catalog get the release through marketplace auto-update, if they turned it on, or
  with the 2 commands of step 3
- Users who install from a clone update as [Install from a clone](install.md) says
- Unreleased code runs only through `claude --plugin-dir ./plugin`, as `AGENTS.md`
  [§ Develop](../AGENTS.md#develop) says

[loading]: https://code.claude.com/docs/en/plugins/loading.md
