///|
fn jwt_char(unit : UInt16) -> Bool {
  let n = unit.to_int()
  (n >= 48 && n <= 57) ||
  (n >= 65 && n <= 90) ||
  (n >= 97 && n <= 122) ||
  n == 45 ||
  n == 95
}

///|
fn decode_jwt_part(encoded : String) -> String? {
  if encoded.length() % 4 == 1 {
    return None
  }
  let normalized = encoded
    .replace_all(old="-", new="+")
    .replace_all(old="_", new="/")
  let bytes = @base64.decode(normalized) catch { _ => return None }
  let decoded = @utf8.decode(bytes) catch { _ => return None }
  Some(decoded)
}

///|
fn json_object(encoded : String) -> Json? {
  let source = match decode_jwt_part(encoded) {
    Some(value) => value
    None => return None
  }
  let value = @json.parse(source) catch { _ => return None }
  if value is Object(_) {
    Some(value)
  } else {
    None
  }
}

///|
fn plausible_jwt(header : String, payload : String, signature : String) -> Bool {
  let head = match json_object(header) {
    Some(value) => value
    None => return false
  }
  guard head is Object(fields) else { return false }
  let alg = match fields.get("alg") {
    Some(String(name)) => name
    _ => return false
  }
  if alg.is_blank() || alg == "none" {
    return false
  }
  if json_object(payload) is None {
    return false
  }
  let encoded_signature = signature
    .replace_all(old="-", new="+")
    .replace_all(old="_", new="/")
  let bytes = @base64.decode(encoded_signature) catch { _ => return false }
  bytes.length() >= 16
}

///|
fn scan_jwts(text : String) -> Array[Finding] {
  let hits : Array[Finding] = []
  let units = text.code_units()
  let mut index = 0
  while index < text.length() {
    if !jwt_char(units[index]) ||
      (
        index > 0 &&
        (jwt_char(units[index - 1]) || units[index - 1].to_int() == 46)
      ) {
      index += 1
      continue
    }
    let mut first = index
    while first < text.length() && jwt_char(units[first]) {
      first += 1
    }
    if first - index < 12 ||
      first - index > 1024 ||
      first == text.length() ||
      units[first].to_int() != 46 {
      index = first + 1
      continue
    }
    let mut second = first + 1
    while second < text.length() && jwt_char(units[second]) {
      second += 1
    }
    if second - first - 1 < 12 ||
      second - first - 1 > 8192 ||
      second == text.length() ||
      units[second].to_int() != 46 {
      index = second + 1
      continue
    }
    let mut end = second + 1
    while end < text.length() && jwt_char(units[end]) {
      end += 1
    }
    if end - second - 1 >= 22 &&
      end - second - 1 <= 4096 &&
      (end == text.length() || units[end].to_int() != 46) {
      let header = text[index:first].to_owned()
      let payload = text[first + 1:second].to_owned()
      let signature = text[second + 1:end].to_owned()
      if plausible_jwt(header, payload, signature) {
        hits.push(finding("jwt-candidate", index, end - index))
      }
    }
    index = end + 1
  }
  hits
}
