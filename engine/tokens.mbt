///|
pub(all) struct Finding {
  rule : String
  offset : Int
  length : Int
  line : Int
  column : Int
} derive(Eq, Debug)

///|
pub extend Finding with Eq::{equal, not_equal}

///|
pub extend Finding with @debug.Debug::{to_repr}

///|
fn word(unit : UInt16) -> Bool {
  let n = unit.to_int()
  (n >= 48 && n <= 57) ||
  (n >= 65 && n <= 90) ||
  (n >= 97 && n <= 122) ||
  n == 95
}

///|
fn gitlab_body(unit : UInt16) -> Bool {
  word(unit) || unit.to_int() == 45
}

///|
fn aws_secret_body(unit : UInt16) -> Bool {
  let n = unit.to_int()
  (n >= 48 && n <= 57) ||
  (n >= 65 && n <= 90) ||
  (n >= 97 && n <= 122) ||
  n == 43 ||
  n == 47
}

///|
fn horizontal_space(unit : UInt16) -> Bool {
  let n = unit.to_int()
  n == 32 || n == 9
}

///|
fn starts_at(text : String, offset : Int, prefix : String) -> Bool {
  offset + prefix.length() <= text.length() &&
  text[offset:offset + prefix.length()].to_owned() == prefix
}

///|
fn finding(rule : String, offset : Int, length : Int) -> Finding {
  { rule, offset, length, line: 0, column: 0, }
}

///|
/// Recognize candidates, without returning their contents. Offsets and columns
/// use UTF-16 code units. An AWS access ID alone is not a secret access key.
fn scan_tokens(text : String) -> Array[Finding] {
  let hits : Array[Finding] = []
  let units = text.code_units()
  let mut index = 0
  while index < text.length() {
    if index > 0 && word(units[index - 1]) {
      index += 1
      continue
    }
    let mut prefix = ""
    let mut rule = ""
    for candidate in ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"] {
      if starts_at(text, index, candidate) {
        prefix = candidate
        rule = "github-token"
        break
      }
    }
    if starts_at(text, index, "AKIA") || starts_at(text, index, "ASIA") {
      prefix = text[index:index + 4].to_owned()
      rule = "aws-access-id"
    }
    if starts_at(text, index, "glpat-") {
      prefix = "glpat-"
      rule = "gitlab-access-token"
    }
    if prefix.length() == 0 {
      index += 1
      continue
    }
    let mut end = index + prefix.length()
    while end < text.length() &&
          (if rule == "gitlab-access-token" {
            gitlab_body(units[end])
          } else {
            word(units[end])
          }) {
      end += 1
    }
    let body_length = end - index - prefix.length()
    let mut accepted = rule == "github-token" &&
      body_length >= 20 &&
      body_length <= 256
    if rule == "aws-access-id" && body_length == 16 {
      accepted = true
      for pos in (index + 4)..<end {
        let n = units[pos].to_int()
        if !((n >= 48 && n <= 57) || (n >= 65 && n <= 90)) {
          accepted = false
        }
      }
    }
    if rule == "gitlab-access-token" && body_length == 20 {
      accepted = true
    }
    if accepted {
      hits.push(finding(rule, index, end - index))
    }
    index = end
  }
  hits
}

///|
/// Match only values assigned to the documented AWS secret key setting.
fn scan_aws_secret_assignments(text : String) -> Array[Finding] {
  let hits : Array[Finding] = []
  let units = text.code_units()
  let mut index = 0
  while index < text.length() {
    let mut key = ""
    for candidate in ["aws_secret_access_key", "AWS_SECRET_ACCESS_KEY"] {
      if starts_at(text, index, candidate) {
        key = candidate
        break
      }
    }
    if key.length() == 0 ||
      (index > 0 && word(units[index - 1])) ||
      (
        index + key.length() < text.length() &&
        word(units[index + key.length()])
      ) {
      index += 1
      continue
    }
    let mut cursor = index + key.length()
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
    while cursor < text.length() && aws_secret_body(units[cursor]) {
      cursor += 1
    }
    if cursor - begin == 40 &&
      (
        quote == 0 ||
        (cursor < text.length() && units[cursor].to_int() == quote)
      ) {
      hits.push(finding("aws-secret-access-key", begin, 40))
    }
    index = cursor + 1
  }
  hits
}
