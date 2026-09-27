///|
/// Mask every detected span, including findings a caller chooses to suppress.
pub fn redact(text : String) -> String {
  let out = StringBuilder()
  let mut cursor = 0
  for hit in scan(text) {
    out.write_string(text[cursor:hit.offset].to_owned())
    out.write_string("[REDACTED]")
    cursor = hit.offset + hit.length
  }
  out.write_string(text[cursor:].to_owned())
  out.to_string()
}

///|
pub(all) struct Exemption {
  rule : String
  line : Int
  column : Int
  reason : String
} derive(Eq, Debug)

///|
pub extend Exemption with Eq::{equal, not_equal}

///|
pub extend Exemption with @debug.Debug::{to_repr}

///|
pub fn review(text : String, exemptions : Array[Exemption]) -> Array[Finding] {
  let visible : Array[Finding] = []
  for hit in scan(text) {
    let mut exempt = false
    for entry in exemptions {
      if !entry.reason.is_blank() &&
        entry.rule == hit.rule &&
        entry.line == hit.line &&
        entry.column == hit.column {
        exempt = true
        break
      }
    }
    if !exempt {
      visible.push(hit)
    }
  }
  visible
}

///|
pub fn report(text : String, exemptions : Array[Exemption]) -> String {
  let out = StringBuilder()
  for hit in review(text, exemptions) {
    out.write_string("\{hit.line}:\{hit.column} \{hit.rule} [REDACTED]\n")
  }
  out.to_string()
}
