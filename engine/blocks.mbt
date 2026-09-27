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
        hits.push(finding(text, rule, index, end - index))
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
  let candidates = scan_tokens(text)
  for secret in scan_aws_secret_assignments(text) {
    candidates.push(secret)
  }
  for token in candidates {
    let mut covered = false
    for block in hits {
      if token.offset >= block.offset &&
        token.offset < block.offset + block.length {
        covered = true
        break
      }
    }
    if !covered {
      hits.push(token)
    }
  }
  hits.sort_by(fn(left, right) { left.offset.compare(right.offset) })
  hits
}
