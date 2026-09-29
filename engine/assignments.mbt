///|
fn ascii_lower(unit : UInt16) -> Int {
  let value = unit.to_int()
  if value >= 65 && value <= 90 {
    value + 32
  } else {
    value
  }
}

///|
fn assignment_name(
  units : ArrayView[UInt16],
  index : Int,
  name : String,
) -> Bool {
  if index + name.length() > units.length() {
    return false
  }
  let expected = name.code_units()
  for position in 0..<name.length() {
    if ascii_lower(units[index + position]) != expected[position].to_int() {
      return false
    }
  }
  true
}

///|
fn assignment_value_char(unit : UInt16) -> Bool {
  let value = unit.to_int()
  ascii_letter_or_digit(unit) ||
  value == 45 ||
  value == 95 ||
  value == 46 ||
  value == 43 ||
  value == 47 ||
  value == 61 ||
  value == 126
}

///|
fn plausible_assignment_value(
  units : ArrayView[UInt16],
  begin : Int,
  end : Int,
) -> Bool {
  if end - begin < 24 || end - begin > 512 {
    return false
  }
  let mut letter = false
  let mut digit = false
  let distinct : Array[Int] = []
  for position in begin..<end {
    let value = units[position].to_int()
    if (value >= 65 && value <= 90) || (value >= 97 && value <= 122) {
      letter = true
    }
    if value >= 48 && value <= 57 {
      digit = true
    }
    let mut seen = false
    for item in distinct {
      if item == value {
        seen = true
        break
      }
    }
    if !seen {
      distinct.push(value)
    }
  }
  letter && digit && distinct.length() >= 8
}

///|
/// A deliberately narrow fallback for assigned credentials without a known prefix.
fn scan_assignments(text : String) -> Array[Finding] {
  let hits : Array[Finding] = []
  let units = text.code_units()
  let mut index = 0
  while index < text.length() {
    if index > 0 && word(units[index - 1]) {
      index += 1
      continue
    }
    let mut name = ""
    for
      candidate in [
        "api_key", "api_token", "client_secret", "secret_key", "access_token", "auth_token",
        "password", "db_password", "database_password", "jwt_secret", "signing_key",
      ] {
      if assignment_name(units, index, candidate) {
        name = candidate
        break
      }
    }
    if name.length() == 0 ||
      (
        index + name.length() < text.length() &&
        word(units[index + name.length()])
      ) {
      index += 1
      continue
    }
    let mut cursor = index + name.length()
    if cursor < text.length() &&
      (units[cursor].to_int() == 34 || units[cursor].to_int() == 39) {
      cursor += 1
    }
    while cursor < text.length() && horizontal_space(units[cursor]) {
      cursor += 1
    }
    if cursor == text.length() ||
      (units[cursor].to_int() != 61 && units[cursor].to_int() != 58) {
      index += 1
      continue
    }
    cursor += 1
    while cursor < text.length() && horizontal_space(units[cursor]) {
      cursor += 1
    }
    let mut quote = 0
    if cursor < text.length() &&
      (units[cursor].to_int() == 34 || units[cursor].to_int() == 39) {
      quote = units[cursor].to_int()
      cursor += 1
    }
    let begin = cursor
    while cursor < text.length() && assignment_value_char(units[cursor]) {
      cursor += 1
    }
    if plausible_assignment_value(units, begin, cursor) &&
      (
        quote == 0 ||
        (cursor < text.length() && units[cursor].to_int() == quote)
      ) {
      hits.push(finding("assigned-credential", begin, cursor - begin))
    }
    index = cursor + 1
  }
  hits
}

///|
fn ascii_hex(unit : UInt16) -> Bool {
  let value = unit.to_int()
  (value >= 48 && value <= 57) ||
  (value >= 65 && value <= 70) ||
  (value >= 97 && value <= 102)
}

///|
/// npm documents hexadecimal access tokens in registry authToken settings.
fn scan_npmrc_tokens(text : String) -> Array[Finding] {
  let hits : Array[Finding] = []
  let units = text.code_units()
  let marker = ":_authToken="
  let mut index = 0
  let mut line_start = 0
  while index < text.length() {
    if units[index].to_int() == 10 {
      line_start = index + 1
    }
    if starts_at(text, index, marker) &&
      index > line_start + 2 &&
      units[index - 1].to_int() == 47 &&
      starts_at(text, line_start, "//") {
      let begin = index + marker.length()
      let mut end = begin
      while end < text.length() && ascii_hex(units[end]) {
        end += 1
      }
      let size = end - begin
      if size >= 32 &&
        size <= 256 &&
        (end == text.length() || !word(units[end])) {
        hits.push(finding("npm-auth-token", begin, size))
      }
      index = end
    } else {
      index += 1
    }
  }
  hits
}
