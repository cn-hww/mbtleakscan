///|
test "recognize synthetic candidates without exposing text" {
  let token = "ghp_" + "a".repeat(36)
  let hits = @engine.scan("token=" + token)
  assert_eq(hits.length(), 1)
  assert_eq(hits[0].rule, "github-token")
  assert_eq(hits[0].offset, 6)
  assert_eq(hits[0].length, 40)
}

///|
test "reject embedded prefixes and short values" {
  assert_eq(@engine.scan("xghp_" + "a".repeat(36)), [])
  assert_eq(@engine.scan("ghp_short"), [])
  assert_eq(@engine.scan("AKIAabcdefghijklmnop"), [])
  assert_eq(@engine.scan("AKIA" + "A".repeat(17)), [])
}

///|
test "track CRLF and non BMP columns" {
  let hits = @engine.scan("first\r\n😀 ghp_" + "a".repeat(36))
  assert_eq(hits.length(), 1)
  assert_eq(hits[0].line, 2)
  assert_eq(hits[0].column, 4)
}

///|
test "find adjacent candidates once each" {
  let hits = @engine.scan("ghp_" + "a".repeat(36) + ",AKIA" + "A".repeat(16))
  assert_eq(hits.length(), 2)
  assert_eq(hits[1].rule, "aws-access-id")
}

///|
test "recognize GitLab token candidates with exact body length" {
  let candidate = "glpat-" + "aB_2-".repeat(4)
  let hits = @engine.scan("value=" + candidate)
  assert_eq(hits.length(), 1)
  assert_eq(hits[0].rule, "gitlab-access-token")
  assert_eq(hits[0].offset, 6)
  assert_eq(hits[0].length, 26)
  assert_eq(@engine.redact(candidate), "[REDACTED]")
  assert_eq(@engine.scan("x" + candidate), [])
  assert_eq(@engine.scan(candidate + "A"), [])
  assert_eq(@engine.scan("glpat-" + "a".repeat(19)), [])
}
