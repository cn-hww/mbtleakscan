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
fn starts_at(text : String, offset : Int, prefix : String) -> Bool {
  offset + prefix.length() <= text.length() &&
  text[offset:offset + prefix.length()].to_owned() == prefix
}

///|
fn finding(text : String, rule : String, offset : Int, length : Int) -> Finding {
  let mut line = 1
  let mut column = 1
  for index in 0..<offset {
    if text.code_units()[index].to_int() == 10 {
      line += 1
      column = 1
    } else {
      column += 1
    }
  }
  { rule, offset, length, line, column, }
}

///|
/// Recognize candidates, without returning their contents. Offsets and columns
/// use UTF-16 code units. An AWS access ID alone is not a secret access key.
pub fn scan(text : String) -> Array[Finding] {
  let hits : Array[Finding] = []
  let mut index = 0
  while index < text.length() {
    if index > 0 && word(text.code_units()[index - 1]) {
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
    if prefix.length() == 0 {
      index += 1
      continue
    }
    let mut end = index + prefix.length()
    while end < text.length() && word(text.code_units()[end]) {
      end += 1
    }
    let body_length = end - index - prefix.length()
    let mut accepted = rule == "github-token" &&
      body_length >= 20 &&
      body_length <= 256
    if rule == "aws-access-id" && body_length == 16 {
      accepted = true
      for pos in (index + 4)..<end {
        let n = text.code_units()[pos].to_int()
        if !((n >= 48 && n <= 57) || (n >= 65 && n <= 90)) {
          accepted = false
        }
      }
    }
    if accepted {
      hits.push(finding(text, rule, index, end - index))
    }
    index = end
  }
  hits
}
