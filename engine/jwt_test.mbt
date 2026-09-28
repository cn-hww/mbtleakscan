///|
fn jwt_fixture(header : String, payload : String, signature : String) -> String {
  let head = @base64.encode(@utf8.encode(header), padding=false)
    .replace_all(old="+", new="-")
    .replace_all(old="/", new="_")
  let body = @base64.encode(@utf8.encode(payload), padding=false)
    .replace_all(old="+", new="-")
    .replace_all(old="/", new="_")
  head + "." + body + "." + signature
}

///|
test "recognize structured JWT candidate without returning claims" {
  let candidate = jwt_fixture(
    "{\"alg\":\"HS256\",\"typ\":\"JWT\"}",
    "{\"sub\":\"synthetic\",\"scope\":\"read\"}",
    "A".repeat(43),
  )
  let source = "Authorization: Bearer " + candidate
  let hits = @engine.scan(source)
  assert_eq(hits.length(), 1)
  assert_eq(hits[0].rule, "jwt-candidate")
  assert_eq(hits[0].column, 23)
  assert_eq(@engine.redact(source), "Authorization: Bearer [REDACTED]")
  assert_eq(@engine.report(source, []), "1:23 jwt-candidate [REDACTED]\n")
}

///|
test "reject malformed or unsigned JWT shaped text" {
  let header = "{\"alg\":\"HS256\"}"
  let claims = "{\"sub\":\"synthetic\"}"
  assert_eq(
    @engine.scan(jwt_fixture("{\"alg\":\"none\"}", claims, "A".repeat(43))),
    [],
  )
  assert_eq(@engine.scan(jwt_fixture(header, "[1,2]", "A".repeat(43))), [])
  assert_eq(@engine.scan(jwt_fixture(header, claims, "short")), [])
  assert_eq(@engine.scan(jwt_fixture("not JSON", claims, "A".repeat(43))), [])
  assert_eq(@engine.scan("alpha.beta.gamma"), [])
  let candidate = jwt_fixture(header, claims, "A".repeat(43))
  assert_eq(@engine.scan(candidate + ".extra"), [])
}
