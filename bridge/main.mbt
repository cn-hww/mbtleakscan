///|
#export_name("scan_json")
pub fn scan_json(text : String) -> String {
  let rows = @engine.scan(text).map(fn(hit) {
    {
      "rule": hit.rule.to_json(),
      "line": hit.line.to_json(),
      "column": hit.column.to_json(),
      "offset": hit.offset.to_json(),
      "length": hit.length.to_json(),
    }
  })
  rows.to_json().stringify()
}
