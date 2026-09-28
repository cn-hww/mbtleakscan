///|
fn uri_end(unit : UInt16) -> Bool {
  let n = unit.to_int()
  n <= 32 || n == 34 || n == 60 || n == 62 || n == 35 || n == 47 || n == 63
}

///|
fn hex_digit(unit : UInt16) -> Bool {
  let n = unit.to_int()
  (n >= 48 && n <= 57) || (n >= 65 && n <= 70) || (n >= 97 && n <= 102)
}

///|
fn userinfo_char(unit : UInt16, password : Bool) -> Bool {
  let n = unit.to_int()
  word(unit) ||
  n == 45 ||
  n == 46 ||
  n == 126 ||
  n == 33 ||
  n == 36 ||
  n == 38 ||
  n == 39 ||
  n == 40 ||
  n == 41 ||
  n == 42 ||
  n == 43 ||
  n == 44 ||
  n == 59 ||
  n == 61 ||
  (password && n == 58)
}

///|
fn valid_userinfo(
  text : String,
  begin : Int,
  end : Int,
  password : Bool,
) -> Bool {
  if begin == end {
    return false
  }
  let units = text.code_units()
  let mut index = begin
  while index < end {
    if units[index].to_int() == 37 {
      if index + 2 >= end ||
        !hex_digit(units[index + 1]) ||
        !hex_digit(units[index + 2]) {
        return false
      }
      index += 3
    } else if userinfo_char(units[index], password) {
      index += 1
    } else {
      return false
    }
  }
  true
}

///|
/// Find password spans in an explicit URL userinfo component.
fn scan_urls(text : String) -> Array[Finding] {
  let hits : Array[Finding] = []
  let units = text.code_units()
  let mut index = 0
  while index < text.length() {
    if index > 0 && (word(units[index - 1]) || units[index - 1].to_int() == 45) {
      index += 1
      continue
    }
    let mut scheme = ""
    for
      candidate in [
        "https://", "http://", "postgres://", "postgresql://", "mysql://", "redis://",
        "amqp://", "mongodb://", "mongodb+srv://", "ftp://", "sftp://",
      ] {
      if starts_at(text, index, candidate) {
        scheme = candidate
        break
      }
    }
    if scheme.length() == 0 {
      index += 1
      continue
    }
    let authority = index + scheme.length()
    let mut end = authority
    while end < text.length() && !uri_end(units[end]) {
      end += 1
    }
    let mut at = authority
    while at < end && units[at].to_int() != 64 {
      at += 1
    }
    if at < end && at + 1 < end {
      let mut colon = authority
      while colon < at && units[colon].to_int() != 58 {
        colon += 1
      }
      if colon < at &&
        valid_userinfo(text, authority, colon, false) &&
        valid_userinfo(text, colon + 1, at, true) {
        let mut another_at = at + 1
        while another_at < end && units[another_at].to_int() != 64 {
          another_at += 1
        }
        if another_at == end {
          hits.push(finding("url-password", colon + 1, at - colon - 1))
        }
      }
    }
    index = end + 1
  }
  hits
}
