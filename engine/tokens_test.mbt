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

///|
test "find AWS secret values only in an assignment context" {
  let value = "aB3+/".repeat(8)
  let source = "aws_secret_access_key = " + value + "\n"
  let hits = @engine.scan(source)
  assert_eq(hits.length(), 1)
  assert_eq(hits[0].rule, "aws-secret-access-key")
  assert_eq(hits[0].column, 25)
  assert_eq(@engine.redact(source), "aws_secret_access_key = [REDACTED]\n")
  let quoted = @engine.scan("AWS_SECRET_ACCESS_KEY: '" + value + "'")
  assert_eq(quoted.length(), 1)
  assert_eq(@engine.scan(value), [])
  assert_eq(@engine.scan("not_aws_secret_access_key=" + value), [])
  assert_eq(@engine.scan("aws_secret_access_key=" + value + "A"), [])
  assert_eq(@engine.scan("aws_secret_access_key='" + value + "\n"), [])
  assert_eq(@engine.scan("aws_secret_access_key=" + "_".repeat(40)), [])
}

///|
test "overlapping rules produce a single complete redaction" {
  let value = "aB3+/".repeat(8)
  let source = "-----BEGIN PRIVATE KEY-----\naws_secret_access_key=" +
    value +
    "\n-----END PRIVATE KEY-----"
  let hits = @engine.scan(source)
  assert_eq(hits.length(), 1)
  assert_eq(hits[0].rule, "private-key-block")
  assert_eq(@engine.redact(source), "[REDACTED]")
}

///|
test "many findings retain their own line and UTF-16 column" {
  let source = StringBuilder()
  let token = "ghp_" + "a".repeat(36)
  for _ in 0..<120 {
    source.write_string("😀 " + token + "\r\n")
  }
  let hits = @engine.scan(source.to_string())
  assert_eq(hits.length(), 120)
  for index in 0..<120 {
    assert_eq(hits[index].line, index + 1)
    assert_eq(hits[index].column, 4)
  }
}

///|
test "redact assigned AWS session token candidates" {
  let value = "aB3+/=_-".repeat(10)
  let source = "AWS_SESSION_TOKEN=\"" + value + "\"\n"
  let hits = @engine.scan(source)
  assert_eq(hits.length(), 1)
  assert_eq(hits[0].rule, "aws-session-token")
  assert_eq(hits[0].length, 80)
  assert_eq(@engine.redact(source), "AWS_SESSION_TOKEN=\"[REDACTED]\"\n")
  assert_eq(@engine.report(source, []), "1:20 aws-session-token [REDACTED]\n")
  assert_eq(@engine.scan("aws_session_token=" + "A".repeat(63)), [])
  assert_eq(@engine.scan("aws_session_token=" + "A".repeat(8193)), [])
  assert_eq(@engine.scan("not_aws_session_token=" + value), [])
  assert_eq(@engine.scan("aws_session_token='" + value + "\n"), [])
}
