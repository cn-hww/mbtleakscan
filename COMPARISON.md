# Scope compared with Gitleaks

[Gitleaks](https://github.com/gitleaks/gitleaks) is a mature secret scanner. The
comparison below is based on its published README, not a detection-rate or speed
benchmark. mbtleakscan does not use or port Gitleaks code or its rule corpus.

| Capability | mbtleakscan now | Gitleaks |
| --- | --- | --- |
| Current files | Directory, tracked working-tree files, staged Git blobs and stdin | Directory and stdin scans |
| Git history | Distinct file versions reachable from `HEAD` or all local refs, with an explicit commit limit | Git patch history, with configurable `git log` options |
| Rule coverage | Named provider tokens including PyPI and npm registry candidates, URL, JWT, PEM and conservative assigned-value candidates | A larger default rule set and user-defined rules |
| Exceptions | Exact file/rule/line/column entries with reasons for current-file scans | Allowlists, ignore fingerprints and report baselines |
| Reports | JSON and SARIF with rule, location and optional commit; no matched text field | JSON, CSV, JUnit, SARIF and templates; `--redact` is available |
| Extra input handling | UTF-8 text files within a chosen size limit; binary and links are skipped | Optional encoded-text and archive scanning |

The independent contribution is a MoonBit detection and redaction library that
builds for wasm, wasm-gc and js, with a small Node.js adapter for file and Git
access. `scan`, `redact`, `review` and `report` can be used without the CLI. Its
fixed finding shape does not carry a credential value. Gitleaks also supports
redaction; this project does not claim otherwise.

The current tool is suitable for focused local checks, integration experiments
and repositories where its documented rules match the expected credential types.
For broad rule coverage, configurable policies, archives, encoded material or
unrestricted Git history, use Gitleaks. A clean mbtleakscan result is only a
statement about files and versions actually scanned.

Source: [Gitleaks README](https://github.com/gitleaks/gitleaks/blob/master/README.md)
(commands, configuration, decoding, archives and reporting; checked 2026-09-29).
