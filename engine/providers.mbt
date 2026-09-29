///|
fn ascii_letter_or_digit(unit : UInt16) -> Bool {
  let n = unit.to_int()
  (n >= 48 && n <= 57) || (n >= 65 && n <= 90) || (n >= 97 && n <= 122)
}

///|
fn stripe_key(
  text : String,
  units : ArrayView[UInt16],
  index : Int,
) -> Finding? {
  let mut prefix = ""
  let mut rule = ""
  for candidate in ["sk_live_", "sk_test_"] {
    if starts_at(text, index, candidate) {
      prefix = candidate
      rule = "stripe-secret-key"
      break
    }
  }
  for candidate in ["rk_live_", "rk_test_"] {
    if starts_at(text, index, candidate) {
      prefix = candidate
      rule = "stripe-restricted-key"
      break
    }
  }
  if prefix.length() == 0 {
    return None
  }
  let mut end = index + prefix.length()
  while end < text.length() && ascii_letter_or_digit(units[end]) {
    end += 1
  }
  let body_length = end - index - prefix.length()
  if body_length >= 20 &&
    body_length <= 256 &&
    (end == text.length() || !word(units[end])) {
    Some(finding(rule, index, end - index))
  } else {
    None
  }
}

///|
fn slack_key(text : String, units : ArrayView[UInt16], index : Int) -> Finding? {
  let mut prefix = ""
  for candidate in ["xoxb-", "xoxp-", "xapp-", "xwfp-"] {
    if starts_at(text, index, candidate) {
      prefix = candidate
      break
    }
  }
  if prefix.length() == 0 {
    return None
  }
  let mut end = index + prefix.length()
  let mut segment_length = 0
  let mut separators = 0
  let mut valid = true
  while end < text.length() {
    if ascii_letter_or_digit(units[end]) {
      segment_length += 1
    } else if units[end].to_int() == 45 {
      if segment_length < 2 {
        valid = false
      }
      separators += 1
      segment_length = 0
    } else {
      break
    }
    end += 1
  }
  let body_length = end - index - prefix.length()
  if valid &&
    separators >= 1 &&
    segment_length >= 2 &&
    body_length >= 16 &&
    body_length <= 255 &&
    (end == text.length() || !word(units[end])) {
    Some(finding("slack-token", index, end - index))
  } else {
    None
  }
}

///|
/// PyPI documents a pypi- prefix followed by at least 85 base64url characters.
fn pypi_key(text : String, units : ArrayView[UInt16], index : Int) -> Finding? {
  let prefix = "pypi-"
  if !starts_at(text, index, prefix) {
    return None
  }
  let mut end = index + prefix.length()
  while end < text.length() &&
        (
          ascii_letter_or_digit(units[end]) ||
          units[end].to_int() == 45 ||
          units[end].to_int() == 95
        ) {
    end += 1
  }
  let size = end - index - prefix.length()
  if size >= 85 && size <= 8192 && (end == text.length() || !word(units[end])) {
    Some(finding("pypi-api-token", index, end - index))
  } else {
    None
  }
}

///|
/// Prefix rules are syntactic; they do not confirm an active provider key.
fn scan_provider_keys(text : String) -> Array[Finding] {
  let hits : Array[Finding] = []
  let units = text.code_units()
  let mut index = 0
  while index < text.length() {
    if index > 0 && (word(units[index - 1]) || units[index - 1].to_int() == 45) {
      index += 1
      continue
    }
    let hit = match stripe_key(text, units, index) {
      Some(value) => Some(value)
      None =>
        match slack_key(text, units, index) {
          Some(value) => Some(value)
          None => pypi_key(text, units, index)
        }
    }
    match hit {
      Some(value) => {
        hits.push(value)
        index += value.length
      }
      None => index += 1
    }
  }
  hits
}
