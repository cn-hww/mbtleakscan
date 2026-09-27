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
