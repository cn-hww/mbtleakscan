///|
fn scan_blocks(text : String) -> Array[Finding] {
  let hits : Array[Finding] = []
  let mut index = 0
  while index < text.length() {
    let mut matched = false
    for
      kind in [
        "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "OPENSSH PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
      ] {
      let opening = "-----BEGIN " + kind + "-----"
      if starts_at(text, index, opening) {
        let closing = "-----END " + kind + "-----"
        let tail = text[index + opening.length():].to_owned()
        let end = match tail.find(closing) {
          Some(relative) =>
            index + opening.length() + relative + closing.length()
          None => text.length()
        }
        let rule = if tail.contains(closing) {
          "private-key-block"
        } else {
          "private-key-unclosed"
        }
        hits.push(finding(rule, index, end - index))
        index = end
        matched = true
        break
      }
    }
    if !matched {
      index += 1
    }
  }
  hits
}

///|
pub fn scan(text : String) -> Array[Finding] {
  let hits = scan_blocks(text)
  let candidates = scan_urls(text)
  for candidate in scan_jwts(text) {
    candidates.push(candidate)
  }
  for candidate in scan_provider_keys(text) {
    candidates.push(candidate)
  }
  for candidate in scan_aws_assignments(text) {
    candidates.push(candidate)
  }
  for token in scan_tokens(text) {
    candidates.push(token)
  }
  for token in candidates {
    let mut covered = false
    for block in hits {
      if token.offset < block.offset + block.length &&
        block.offset < token.offset + token.length {
        covered = true
        break
      }
    }
    if !covered {
      hits.push(token)
    }
  }
  hits.sort_by(fn(left, right) { left.offset.compare(right.offset) })
  let positioned : Array[Finding] = []
  let units = text.code_units()
  let mut cursor = 0
  let mut line = 1
  let mut column = 1
  for hit in hits {
    for index in cursor..<hit.offset {
      if units[index].to_int() == 10 {
        line += 1
        column = 1
      } else {
        column += 1
      }
    }
    positioned.push({
      rule: hit.rule,
      offset: hit.offset,
      length: hit.length,
      line,
      column,
    })
    cursor = hit.offset
  }
  positioned
}
