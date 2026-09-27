///|
test "mask whole private key blocks and avoid nested duplicate findings" {
  let value = "header\n-----BEGIN RSA PRIVATE KEY-----\nghp_" +
    "a".repeat(36) +
    "\n-----END RSA PRIVATE KEY-----\ntail"
  let hits = @engine.scan(value)
  assert_eq(hits.length(), 1)
  assert_eq(hits[0].rule, "private-key-block")
  assert_eq(@engine.redact(value), "header\n[REDACTED]\ntail")
}

///|
test "mask unclosed private keys through the end of input" {
  let value = "-----BEGIN PRIVATE KEY-----\nsynthetic-body"
  assert_eq(@engine.scan(value)[0].rule, "private-key-unclosed")
  assert_eq(@engine.redact(value), "[REDACTED]")
}

///|
test "keep public key blocks and mismatched closings conservative" {
  let public_key = "-----BEGIN PUBLIC KEY-----\nexample\n-----END PUBLIC KEY-----"
  assert_eq(@engine.scan(public_key), [])
  let mismatched = "-----BEGIN EC PRIVATE KEY-----\nexample\n-----END RSA PRIVATE KEY-----"
  assert_eq(@engine.scan(mismatched)[0].rule, "private-key-unclosed")
}

///|
test "exemptions require a reason and do not disable redaction" {
  let value = "ghp_" + "a".repeat(36)
  let entry : @engine.Exemption = {
    rule: "github-token",
    line: 1,
    column: 1,
    reason: "synthetic fixture",
  }
  assert_eq(@engine.review(value, [entry]), [])
  assert_eq(@engine.report(value, [entry]), "")
  assert_eq(@engine.redact(value), "[REDACTED]")
  assert_eq(@engine.review(value, [{ ..entry, reason: " ", }]).length(), 1)
  assert_eq(@engine.review(value, [{ ..entry, column: 2, }]).length(), 1)
}

///|
test "reports never contain matched values and preserve source order" {
  let value = "ghp_" +
    "a".repeat(36) +
    "\n-----BEGIN PRIVATE KEY-----\nsynthetic"
  assert_eq(
    @engine.report(value, []),
    "1:1 github-token [REDACTED]\n2:1 private-key-unclosed [REDACTED]\n",
  )
  assert_false(@engine.report(value, []).contains("aaaa"))
}
