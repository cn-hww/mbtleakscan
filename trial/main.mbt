///|
fn main {
  let sample = "token=ghp_" + "a".repeat(36)
  for hit in @engine.scan(sample) {
    println("\{hit.rule} at \{hit.line}:\{hit.column}")
  }
}
