///|
test "detect long assigned credentials in env and JSON syntax" {
  let value = "Ab3dE4fG5hI6jK7lM8nP9qR0"
  let source = "CLIENT_SECRET = '" + value + "'\n\"api_key\": \"" + value + "\""
  let hits = @engine.scan(source)
  assert_eq(hits.length(), 2)
  assert_eq(hits[0].rule, "assigned-credential")
  assert_eq(hits[1].rule, "assigned-credential")
  assert_eq(hits[1].line, 2)
  assert_eq(
    @engine.redact(source),
    "CLIENT_SECRET = '[REDACTED]'\n\"api_key\": \"[REDACTED]\"",
  )
}

///|
test "reject short, repetitive and partial assignment candidates" {
  assert_eq(@engine.scan("API_KEY=short123"), [])
  assert_eq(@engine.scan("API_KEY=" + "a".repeat(40)), [])
  assert_eq(@engine.scan("MY_API_KEY_SUFFIX=Ab3dE4fG5hI6jK7lM8nP9qR0"), [])
  assert_eq(@engine.scan("client_secret='Ab3dE4fG5hI6jK7lM8nP9qR0"), [])
  assert_eq(@engine.scan("api_key=${ENV_VALUE}"), [])
}

///|
test "specific token rules take precedence over assigned fallback" {
  let token = "ghp_" + "a".repeat(36)
  let source = "API_KEY=" + token
  let hits = @engine.scan(source)
  assert_eq(hits.length(), 1)
  assert_eq(hits[0].rule, "github-token")
  assert_eq(@engine.redact(source), "API_KEY=[REDACTED]")
}

///|
test "overlapping URL and provider matches remain one redacted span" {
  let token = "ghp_" + "a".repeat(36)
  let source = "https://user:" + token + "@host.example"
  let hits = @engine.scan(source)
  assert_eq(hits.length(), 1)
  assert_eq(hits[0].rule, "url-password")
  assert_eq(@engine.redact(source), "https://user:[REDACTED]@host.example")
}
