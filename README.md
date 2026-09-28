# mbtleakscan

Find suspected credentials before code leaves your machine. The MoonBit engine
returns rule names and positions, never the matched value.

Current recognizers cover GitHub token prefixes, GitLab `glpat-` access tokens,
AWS access key IDs, assigned AWS secret access keys, assigned AWS session tokens,
and PEM
private-key blocks (including unclosed blocks). These
are syntax-based candidates, not proof that a credential is valid. AWS access
IDs are identifiers; the secret-key rule requires an
`aws_secret_access_key` or `AWS_SECRET_ACCESS_KEY` assignment with a 40-character
ASCII value. Other assignment names and encodings are outside this rule.
The session-token rule checks `aws_session_token` or `AWS_SESSION_TOKEN` values
with 64–8192 base64-like ASCII characters. This range is a scanner heuristic,
not a claim that AWS tokens have a fixed format.
GitLab recognition uses its default prefix and a 20-character ASCII body;
installations with a custom prefix are outside this rule.

```sh
moon run trial --target wasm-gc
moon test --target wasm --deny-warn
moon test --target wasm-gc --deny-warn
moon test --target js --deny-warn
```

Offsets and columns use UTF-16 code units; line and column numbers start at one.
Tests construct synthetic values. No live tokens, personal data or copied rule
corpus are included. Recognition logic is implemented here; Gitleaks is a
comparison tool, not a runtime dependency or a source-code port.

Supported syntax is deliberately limited. Prefix checks do not discover every
kind of secret, and a clean result does not prove that a file contains none.

`scan(text)` returns positions; `redact(text)` replaces complete detected spans
with `[REDACTED]`; `report(text, exemptions)` returns only positions and rules.
An exemption must match a rule, line and column and include a nonblank reason.
It does not affect `redact`. Exemptions must be reviewed when source lines move.
Unclosed key blocks are masked through the end of input. Public-key blocks are
not credentials and are not flagged. Key bodies are not cryptographically parsed.
# Directory checks

With MoonBit and Node.js 22 or newer installed:

```sh
moon build --target js
node tools/scan.mjs path/to/project
node tools/scan.mjs --sarif path/to/project > findings.sarif
node tools/scan.mjs --exemptions exceptions.json path/to/project
node tools/scan.mjs --tracked path/to/git/repository
node tools/scan.mjs --staged path/to/git/repository
node tools/scan.mjs --staged --changed path/to/git/repository
node tools/scan.mjs --staged --changed --fail-on-skip path/to/git/repository
node tools/scan.mjs --max-bytes 2097152 path/to/project
npm test
```

The command emits JSON containing relative file names, rule identifiers and
positions. Source excerpts and matched values are omitted. File names themselves
are not anonymized: rename sensitive file names before sharing reports.
Exit codes are 0 for a clean scan, 1 for findings, and 2 for input errors.
An error takes precedence over findings, so unreadable input cannot silently pass.

Traversal uses sorted names, ignores `.git`, `_build`, `.mooncakes`, `.moon` and
`node_modules`, and skips symbolic links, nonregular files, files over 1 MiB and
files containing NUL bytes. Other input must be valid UTF-8. Summary counts expose
skipped and failed inputs; a clean result covers only the scanned files.
The Node adapter handles filesystem access; recognition runs in the MoonBit engine.

The default per-file limit is 1 MiB. `--max-bytes` accepts a positive byte count
up to 8 MiB and applies to directory, tracked and staged scans. Files above the
chosen limit remain skipped; combine the option with `--fail-on-skip` when
incomplete coverage must fail CI.

Use `--fail-on-skip` for CI checks that require every selected file to be scanned.
If a symbolic link, oversized file, binary file or nonregular entry is skipped,
the command returns exit code 2 and marks the SARIF invocation unsuccessful.
The JSON summary still reports how many files were skipped.

`--tracked` scans paths in the Git index from the given repository directory.
It excludes untracked files and fails if Git cannot list the index. File contents
come from the working tree, so staged content that differs from the working tree
requires a separate scan. Symbolic links remain skipped.

`--staged` reads regular-file blobs from the Git index, including files changed
or removed in the working tree after staging. It excludes untracked files and
reports unresolved index entries as errors. Oversize and binary blobs are skipped
and counted. `--tracked` and `--staged` are mutually exclusive.

Add `--changed` to scan only index paths changed from `HEAD`, using their staged
content. This includes newly added files on a branch without commits and excludes
deleted paths. It is useful for pre-commit checks in repositories with older
findings. A clean changed scan describes this commit's staged files only.

`--sarif` emits SARIF 2.1.0 with relative file locations, rule IDs and fixed
redacted messages. The exit codes are the same as for JSON output. Review the
report before uploading it because file names and line numbers remain visible.

An optional exemption file has the form below. Each entry needs an exact relative
file name, rule, line and column, plus a nonblank reason. Unknown fields,
duplicates, malformed files and unused entries fail the scan with exit code 2.
Exemptions affect both JSON and SARIF reports; source values remain untouched.
With `--staged --changed`, entries for unchanged files are outside the scan and
do not count as unused. Entries for changed files still need an exact match.

```json
{"exemptions":[{"file":"sample.txt","rule":"github-token","line":3,"column":7,"reason":"synthetic test fixture"}]}
```
