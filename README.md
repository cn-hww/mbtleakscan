# mbtleakscan

Find suspected credentials before code leaves your machine. The MoonBit engine
returns rule names and positions, never the matched value.

Current recognizers cover GitHub token prefixes and AWS access key IDs. These
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
