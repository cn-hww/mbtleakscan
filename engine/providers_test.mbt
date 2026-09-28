///|
test "detect Stripe server keys while leaving publishable keys alone" {
  let secret = "sk_live_" + "aB3".repeat(10)
  let restricted = "rk_test_" + "9xY".repeat(9)
  let source = "payment=" + secret + "\nrestricted=" + restricted
  let hits = @engine.scan(source)
  assert_eq(hits.length(), 2)
  assert_eq(hits[0].rule, "stripe-secret-key")
  assert_eq(hits[1].rule, "stripe-restricted-key")
  assert_eq(hits[1].line, 2)
  assert_eq(@engine.redact(source), "payment=[REDACTED]\nrestricted=[REDACTED]")
  assert_eq(@engine.scan("pk_live_" + "a".repeat(30)), [])
  assert_eq(@engine.scan("x" + secret), [])
  assert_eq(@engine.scan("sk_live_" + "a".repeat(19)), [])
  assert_eq(@engine.scan(secret + "_more"), [])
}

///|
test "detect segmented Slack tokens and reject fragments" {
  for prefix in ["xoxb-", "xoxp-", "xapp-", "xwfp-"] {
    let token = prefix + "12345678-" + "aBcD".repeat(5)
    let hits = @engine.scan("Bearer " + token)
    assert_eq(hits.length(), 1)
    assert_eq(hits[0].rule, "slack-token")
    assert_eq(@engine.redact("Bearer " + token), "Bearer [REDACTED]")
  }
  assert_eq(@engine.scan("xoxb-1234-short"), [])
  assert_eq(@engine.scan("xoxb-12345678-" + "a".repeat(20) + "-"), [])
  assert_eq(@engine.scan("xxoxb-12345678-" + "a".repeat(20)), [])
}
