///|
test "detect URL password and retain surrounding URL on redaction" {
  let source = "db=postgres://reader:p%40ss:word@db.example:5432/main"
  let hits = @engine.scan(source)
  assert_eq(hits.length(), 1)
  assert_eq(hits[0].rule, "url-password")
  assert_eq(hits[0].line, 1)
  assert_eq(hits[0].column, 22)
  assert_eq(
    @engine.redact(source),
    "db=postgres://reader:[REDACTED]@db.example:5432/main",
  )
  assert_eq(@engine.report(source, []), "1:22 url-password [REDACTED]\n")
}

///|
test "URL userinfo requires valid escapes and a host" {
  assert_eq(@engine.scan("https://reader@host.example"), [])
  assert_eq(@engine.scan("https://reader:@host.example"), [])
  assert_eq(@engine.scan("https://reader:pass@"), [])
  assert_eq(@engine.scan("https://reader:p%XY@host.example"), [])
  assert_eq(@engine.scan("https://reader:p@host@example"), [])
  assert_eq(@engine.scan("xhttps://reader:pass@host.example"), [])
}

///|
test "complete URL password takes precedence over embedded token" {
  let password = "ghp_" + "a".repeat(36) + "!"
  let source = "https://reader:" + password + "@host.example"
  let hits = @engine.scan(source)
  assert_eq(hits.length(), 1)
  assert_eq(hits[0].rule, "url-password")
  assert_eq(@engine.redact(source), "https://reader:[REDACTED]@host.example")
}
