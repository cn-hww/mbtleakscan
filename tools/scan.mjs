import { readdir, readFile, lstat } from 'node:fs/promises';
import { resolve, relative, join, sep } from 'node:path';
import { scan_json } from '../_build/js/debug/build/bridge/bridge.js';

const ignored = new Set(['.git', '_build', '.mooncakes', 'node_modules', '.moon']);
const limit = 1024 * 1024;
const root = resolve(process.argv[2] ?? '.');
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

if (process.argv.length > 3) {
  process.stderr.write('Usage: node tools/scan.mjs [directory-or-file]\n');
  process.exitCode = 2;
} else {
  await visit(root);
  process.stdout.write(JSON.stringify({ findings, stats }) + '\n');
  process.exitCode = stats.errors ? 2 : findings.length ? 1 : 0;
}
