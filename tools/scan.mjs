import { readdir, readFile, lstat } from 'node:fs/promises';
import { resolve, relative, join, sep } from 'node:path';
import { scan_json } from '../_build/js/debug/build/bridge/bridge.js';

const ignored = new Set(['.git', '_build', '.mooncakes', 'node_modules', '.moon']);
const limit = 1024 * 1024;
const args = process.argv.slice(2);
const sarif = args.includes('--sarif');
const paths = args.filter(arg => arg !== '--sarif');
const root = resolve(paths[0] ?? '.');
const findings = [];
const stats = { scanned: 0, skipped: 0, errors: 0 };
const decoder = new TextDecoder('utf-8', { fatal: true });

async function visit(path) {
  try {
    const info = await lstat(path);
    if (info.isSymbolicLink()) { stats.skipped++; return; }
    if (info.isDirectory()) {
      const entries = (await readdir(path)).sort();
      for (const name of entries) {
        if (!ignored.has(name)) await visit(join(path, name));
      }
      return;
    }
    if (!info.isFile() || info.size > limit) { stats.skipped++; return; }
    const bytes = await readFile(path);
    if (bytes.length > limit || bytes.includes(0)) { stats.skipped++; return; }
    const source = decoder.decode(bytes);
    const hits = JSON.parse(scan_json(source));
    const file = relative(root, path).split(sep).join('/') || '.';
    for (const hit of hits) findings.push({ file, ...hit });
    stats.scanned++;
  } catch {
    stats.errors++;
  }
}

if (paths.length > 1 || paths.some(arg => arg.startsWith('--'))) {
  process.stderr.write('Usage: node tools/scan.mjs [--sarif] [directory-or-file]\n');
  process.exitCode = 2;
} else {
  await visit(root);
  const output = sarif ? {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{
      tool: { driver: { name: 'mbtleakscan', rules: [...new Set(findings.map(hit => hit.rule))].sort().map(id => ({ id })) } },
      results: findings.map(hit => ({
        ruleId: hit.rule,
        level: 'warning',
        message: { text: 'Suspected credential [REDACTED]' },
        locations: [{ physicalLocation: {
          artifactLocation: { uri: hit.file },
          region: { startLine: hit.line, startColumn: hit.column },
        } }],
      })),
      invocations: [{ executionSuccessful: stats.errors === 0 }],
    }],
  } : { findings, stats };
  process.stdout.write(JSON.stringify(output) + '\n');
  process.exitCode = stats.errors ? 2 : findings.length ? 1 : 0;
}
