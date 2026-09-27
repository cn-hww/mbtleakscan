import { readdir, readFile, lstat } from 'node:fs/promises';
import { resolve, relative, join, sep } from 'node:path';
import { scan_json } from '../_build/js/debug/build/bridge/bridge.js';

const ignored = new Set(['.git', '_build', '.mooncakes', 'node_modules', '.moon']);
const limit = 1024 * 1024;
const args = process.argv.slice(2);
let sarif = false;
let exemptionPath;
const paths = [];
for (let index = 0; index < args.length; index++) {
  if (args[index] === '--sarif') sarif = true;
  else if (args[index] === '--exemptions') exemptionPath = args[++index];
  else paths.push(args[index]);
}
const root = resolve(paths[0] ?? '.');
const findings = [];
const stats = { scanned: 0, skipped: 0, errors: 0 };
const decoder = new TextDecoder('utf-8', { fatal: true });

async function loadExemptions(path) {
  const data = JSON.parse(await readFile(path, 'utf8'));
  if (!data || Array.isArray(data) || Object.keys(data).join() !== 'exemptions' || !Array.isArray(data.exemptions)) throw Error();
  const seen = new Set();
  for (const entry of data.exemptions) {
    if (!entry || Array.isArray(entry) || Object.keys(entry).sort().join() !== 'column,file,line,reason,rule' ||
        typeof entry.file !== 'string' || !entry.file || entry.file.startsWith('/') ||
        entry.file.includes('\\') || entry.file.split('/').some(part => part === '..' || part === '') ||
        typeof entry.rule !== 'string' || !entry.rule ||
        !Number.isSafeInteger(entry.line) || entry.line < 1 ||
        !Number.isSafeInteger(entry.column) || entry.column < 1 ||
        typeof entry.reason !== 'string' || !entry.reason.trim()) throw Error();
    const key = JSON.stringify([entry.file, entry.rule, entry.line, entry.column]);
    if (seen.has(key)) throw Error();
    seen.add(key);
  }
  return data.exemptions;
}

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

if (paths.length > 1 || paths.some(arg => arg.startsWith('--')) ||
    (args.includes('--exemptions') && (!exemptionPath || exemptionPath.startsWith('--'))) ||
    args.filter(arg => arg === '--exemptions').length > 1) {
  process.stderr.write('Usage: node tools/scan.mjs [--sarif] [--exemptions file.json] [directory-or-file]\n');
  process.exitCode = 2;
} else {
  let exemptions = [];
  try {
    if (exemptionPath) exemptions = await loadExemptions(exemptionPath);
  } catch {
    process.stderr.write('Invalid exemption file\n');
    process.exitCode = 2;
  }
  if (process.exitCode !== 2) await visit(root);
  const used = new Set();
  const visible = findings.filter(hit => {
    const index = exemptions.findIndex(entry => entry.file === hit.file && entry.rule === hit.rule &&
      entry.line === hit.line && entry.column === hit.column);
    if (index < 0) return true;
    used.add(index);
    return false;
  });
  if (used.size !== exemptions.length) {
    process.stderr.write('Unused exemption entry\n');
    stats.errors++;
  }
  const output = sarif ? {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{
      tool: { driver: { name: 'mbtleakscan', rules: [...new Set(visible.map(hit => hit.rule))].sort().map(id => ({ id })) } },
      results: visible.map(hit => ({
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
  } : { findings: visible, stats: { ...stats, exempted: findings.length - visible.length } };
  if (process.exitCode !== 2) process.stdout.write(JSON.stringify(output) + '\n');
  process.exitCode = process.exitCode === 2 || stats.errors ? 2 : visible.length ? 1 : 0;
}
