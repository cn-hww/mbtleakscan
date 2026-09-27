# mbtleakscan

Find suspected credentials before code leaves your machine. The MoonBit engine
returns rule names and positions, never the matched value.

Current recognizers cover GitHub token prefixes, AWS access key IDs and PEM
private-key blocks (including unclosed blocks). These
are syntax-based candidates, not proof that a credential is valid. AWS access
IDs are identifiers; their corresponding secret keys are not detected yet.

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
