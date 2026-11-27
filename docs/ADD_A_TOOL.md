# Add your own discovery tool

LeakGuard can run any command-line tool that looks up an email address or a username and prints what it
finds. You describe the tool once, in the app (*Settings → Extra checks → Add a tool*) or in a small JSON file.
No Python needed. Your tool then runs in every check, with the same safety rules as the built-in tools.

## Six steps

1. **Install the tool and try it in a terminal**, on your own email:
   `forumcheck --json you@example.com`. Look at what it prints.
2. **Write the command** with `{value}` where your email or username goes: `forumcheck --json {value}`.
   LeakGuard passes the value as one argument, never through a shell.
3. **Say how it prints results:**
   - *One JSON document*: give the path to the list of results (`results`, `data.accounts`), or leave it empty
     if the whole output is the list.
   - *One JSON result per line*: nothing else needed (lines that aren't JSON are skipped).
   - *Lines of text*: a regular expression with named parts, e.g. `^\[\+\] (?P<site>\S+): (?P<url>\S+)`.
4. **Keep only real hits** (optional): *only results where* `exists` *equals* `true`.
5. **Fill in each finding** from a result's fields: title `Account on {site}`, link `{url}`, site `{site}`.
   Nested fields use dots: `{profile.name}`. Choose the kind of find and how serious it is.
6. **Test on my email, then Save.** The test runs the tool once and lists what it would report. Nothing is
   saved until you press Save. The tool is then switched on, and you can switch it off at any time.

## Worked example

`forumcheck --json you@example.com` prints:
```json
{"query": "you@example.com", "results": [
  {"site": "LabForum2", "url": "https://forum.example/u/you", "exists": true},
  {"site": "NoSuchForum", "url": "", "exists": false}]}
```
Its definition, saved as `~/.config/leakguard/tools.d/forumcheck.json` (the app writes the same file):
```json
{
  "id": "forumcheck",
  "name": "Forum check",
  "about": "Finds forum accounts made with your email.",
  "checks": ["email"],
  "command": ["forumcheck", "--json", "{value}"],
  "output": {"format": "json", "items": "results", "match": {"field": "exists", "equals": true},
             "title": "Account on {site}", "url": "{url}", "site": "{site}"},
  "category": "account",
  "severity": "low",
  "timeout": 300,
  "enabled": true
}
```
Result: one finding, *Account on LabForum2*, which goes into To do like any other. Practice mode
(`leakguard-app --practice`) has this example built in, running on recorded output.

## Reference

| Field | Meaning |
|---|---|
| `id` | short name: lowercase letters, digits, `-`, `_` (not a built-in check's name) |
| `name`, `about` | what the app shows |
| `checks` | `["email"]`, `["username"]` or both |
| `command` | the program and its arguments; `{value}` is replaced by one of your claimed emails or usernames |
| `output.format` | `json`, `jsonl` or `lines` |
| `output.items` | (json) path to the list of results; a single object counts as one result |
| `output.match` | (optional) `{"field": "...", "equals": ...}`, or just `{"field": "..."}` to keep results where it is set |
| `output.pattern` | (lines) regular expression with named groups; each group is a field |
| `output.title`, `url`, `site`, `evidence` | templates filled from each result's fields |
| `category` | `account`, `breach`, `leak`, `paste`, `profile`, `web_page`, `code` |
| `severity` | `info`, `low`, `medium`, `high` |
| `timeout` | seconds, 10 to 3600 (default 300) |
| `enabled` | your tool runs only while this is `true` |

**Safety, same as the built-in tools:** only identities you claimed are looked up; practice mode never runs a
tool; the tool's raw output is kept privately in `~/.local/share/leakguard/raw/`; errors are logged in full and
shown in *Reports → Check health*. The CLI uses your tools too: `leakguard doctor` lists them and
`leakguard scan -s forumcheck` runs one.
