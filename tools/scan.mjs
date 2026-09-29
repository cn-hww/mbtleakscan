import { readdir, readFile, lstat } from 'node:fs/promises';
import { resolve, relative, join, sep } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { scan_json } from '../_build/js/debug/build/bridge/bridge.js';

const ignored = new Set(['.git', '_build', '.mooncakes', 'node_modules', '.moon']);
let limit = 1024 * 1024;
const args = process.argv.slice(2);
let sarif = false;
let tracked = false;
let staged = false;
let changed = false;
let history = false;
let allRefs = false;
let stdin = false;
let failOnSkip = false;
let exemptionPath;
let maxBytesOption;
let maxCommitsOption;
const paths = [];
for (let index = 0; index < args.length; index++) {
  if (args[index] === '--sarif') sarif = true;
  else if (args[index] === '--tracked') tracked = true;
  else if (args[index] === '--staged') staged = true;
  else if (args[index] === '--changed') changed = true;
  else if (args[index] === '--history') history = true;
  else if (args[index] === '--all-refs') allRefs = true;
  else if (args[index] === '--stdin') stdin = true;
  else if (args[index] === '--fail-on-skip') failOnSkip = true;
  else if (args[index] === '--exemptions') exemptionPath = args[++index];
  else if (args[index] === '--max-bytes') maxBytesOption = args[++index];
  else if (args[index] === '--max-commits') maxCommitsOption = args[++index];
  else paths.push(args[index]);
}
const validMaxBytes = !args.includes('--max-bytes') ||
  typeof maxBytesOption === 'string' && /^[1-9][0-9]*$/.test(maxBytesOption) &&
  Number.isSafeInteger(Number(maxBytesOption)) &&
  Number(maxBytesOption) <= 8 * 1024 * 1024;
if (validMaxBytes && maxBytesOption !== undefined) limit = Number(maxBytesOption);
const validMaxCommits = !args.includes('--max-commits') ||
  typeof maxCommitsOption === 'string' && /^[1-9][0-9]*$/.test(maxCommitsOption) &&
  Number.isSafeInteger(Number(maxCommitsOption)) && Number(maxCommitsOption) <= 10000;
const maxCommits = Number(maxCommitsOption ?? 50);
const root = resolve(paths[0] ?? '.');
const findings = [];
const stats = { scanned: 0, skipped: 0, errors: 0 };
const decoder = new TextDecoder('utf-8', { fatal: true });
let changedNames;

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

function scanBytes(bytes, file, commit) {
  if (bytes.length > limit || bytes.includes(0)) { stats.skipped++; return; }
  const source = decoder.decode(bytes);
  for (const hit of JSON.parse(scan_json(source))) {
    findings.push(commit ? { file, commit, ...hit } : { file, ...hit });
  }
  stats.scanned++;
}

async function visitHistory() {
  try {
    if (!(await lstat(root)).isDirectory()) throw Error();
    const git = promisify(execFile);
    const options = { cwd: root, encoding: 'buffer', maxBuffer: 16 * 1024 * 1024 };
    const { stdout: rawCommits } = await git('git', [
      'rev-list', '--max-count=' + (maxCommits + 1), allRefs ? '--all' : 'HEAD',
    ], options);
    const commits = decoder.decode(rawCommits).trim().split('\n').filter(Boolean);
    if (commits.length > maxCommits) {
      stats.errors++;
      process.stderr.write('History limit reached; increase --max-commits\n');
      commits.length = maxCommits;
    }
    const seen = new Set();
    for (const commit of commits) {
      if (!/^[0-9a-f]{40}$|^[0-9a-f]{64}$/.test(commit)) throw Error();
      const { stdout: rawTree } = await git('git', ['ls-tree', '-r', '-z', commit], options);
      const entries = decoder.decode(rawTree).split('\0').filter(Boolean).sort();
      for (const entry of entries) {
        try {
          const tab = entry.indexOf('\t');
          if (tab < 0) throw Error();
          const [mode, type, hash] = entry.slice(0, tab).split(' ');
          const file = entry.slice(tab + 1);
          if (!/^[0-9a-f]{40}$|^[0-9a-f]{64}$/.test(hash) || !file ||
              file.startsWith('/') || file.split('/').some(part =>
                !part || part === '.' || part === '..' || part.includes('\\'))) throw Error();
          if (type !== 'blob' || mode !== '100644' && mode !== '100755') {
            stats.skipped++;
            continue;
          }
          const key = JSON.stringify([file, hash]);
          if (seen.has(key)) continue;
          seen.add(key);
          const { stdout: sizeText } = await git('git', ['cat-file', '-s', hash], { cwd: root });
          const size = Number(sizeText.trim());
          if (!Number.isSafeInteger(size) || size < 0) throw Error();
          if (size > limit) { stats.skipped++; continue; }
          const { stdout: bytes } = await git('git', ['cat-file', 'blob', hash], {
            cwd: root, encoding: 'buffer', maxBuffer: limit + 1024,
          });
          scanBytes(bytes, file, commit);
        } catch {
          stats.errors++;
        }
      }
    }
  } catch {
    stats.errors++;
  }
}

async function visitStdin() {
  try {
    const chunks = [];
    let size = 0;
    for await (const chunk of process.stdin) {
      size += chunk.length;
      if (size > limit) {
        stats.skipped++;
        stats.errors++;
        return;
      }
      chunks.push(chunk);
    }
    scanBytes(Buffer.concat(chunks), 'stdin');
  } catch {
    stats.errors++;
  }
}

async function visit(path, allowDirectory = true) {
  try {
    const info = await lstat(path);
    if (info.isSymbolicLink()) { stats.skipped++; return; }
    if (info.isDirectory()) {
      if (!allowDirectory) { stats.errors++; return; }
      const entries = (await readdir(path)).sort();
      for (const name of entries) {
        if (!ignored.has(name)) await visit(join(path, name));
      }
      return;
    }
    if (!info.isFile() || info.size > limit) { stats.skipped++; return; }
    const bytes = await readFile(path);
    const file = relative(root, path).split(sep).join('/') || '.';
    scanBytes(bytes, file);
  } catch {
    stats.errors++;
  }
}

async function visitStaged() {
  try {
    if (!(await lstat(root)).isDirectory()) throw Error();
    const git = promisify(execFile);
    const { stdout } = await git('git', ['ls-files', '--stage', '-z'], {
      cwd: root, encoding: 'buffer', maxBuffer: 16 * 1024 * 1024,
    });
    const entries = decoder.decode(stdout).split('\0').filter(Boolean).sort((a, b) => {
      const left = a.slice(a.indexOf('\t') + 1);
      const right = b.slice(b.indexOf('\t') + 1);
      return left < right ? -1 : left > right ? 1 : 0;
    });
    if (entries.some(entry => entry.slice(0, entry.indexOf('\t')).split(' ')[2] !== '0')) {
      stats.errors++;
      return;
    }
    if (changed) {
      const { stdout: diff } = await git('git', [
        'diff', '--cached', '--name-only', '--relative', '--no-renames',
        '--diff-filter=ACMRT', '-z',
      ], { cwd: root, encoding: 'buffer', maxBuffer: 16 * 1024 * 1024 });
      changedNames = new Set(decoder.decode(diff).split('\0').filter(Boolean));
      const indexed = new Set(entries.map(entry => entry.slice(entry.indexOf('\t') + 1)));
      if ([...changedNames].some(name => !indexed.has(name))) throw Error();
    }
    for (const entry of entries) {
      try {
        const tab = entry.indexOf('\t');
        if (tab < 0) throw Error();
        const [mode, hash, stage] = entry.slice(0, tab).split(' ');
        const file = entry.slice(tab + 1);
        if (changed && !changedNames.has(file)) continue;
        if (!/^[0-9a-f]{40}$|^[0-9a-f]{64}$/.test(hash) || stage !== '0' ||
            !file || file.startsWith('/') ||
            file.split('/').some(part => !part || part === '.' || part === '..' || part.includes('\\'))) throw Error();
        if (mode !== '100644' && mode !== '100755') { stats.skipped++; continue; }
        const { stdout: sizeText } = await git('git', ['cat-file', '-s', hash], { cwd: root });
        const size = Number(sizeText.trim());
        if (!Number.isSafeInteger(size) || size < 0) throw Error();
        if (size > limit) { stats.skipped++; continue; }
        const { stdout: bytes } = await git('git', ['cat-file', 'blob', hash], {
          cwd: root, encoding: 'buffer', maxBuffer: limit + 1024,
        });
        scanBytes(bytes, file);
      } catch {
        stats.errors++;
      }
    }
  } catch {
    stats.errors++;
  }
}

async function visitTracked() {
  try {
    if (!(await lstat(root)).isDirectory()) throw Error();
    const { stdout } = await promisify(execFile)('git', ['ls-files', '-z', '--cached'], {
      cwd: root, encoding: 'buffer', maxBuffer: 16 * 1024 * 1024,
    });
    const names = [...new Set(decoder.decode(stdout).split('\0').filter(Boolean))].sort();
    for (const name of names) {
      const parts = name.split('/');
      if (parts.some(part => !part || part === '.' || part === '..' || part.includes('\\'))) {
        stats.errors++;
        continue;
      }
      let current = root;
      let safe = true;
      for (const part of parts.slice(0, -1)) {
        current = join(current, part);
        const info = await lstat(current);
        if (!info.isDirectory() || info.isSymbolicLink()) { safe = false; break; }
      }
      if (safe) await visit(join(root, ...parts), false);
      else stats.skipped++;
    }
  } catch {
    stats.errors++;
  }
}

if (!validMaxBytes || !validMaxCommits ||
    args.filter(arg => arg === '--max-bytes').length > 1 ||
    args.filter(arg => arg === '--max-commits').length > 1 ||
    [tracked, staged, history, stdin].filter(Boolean).length > 1 ||
    changed && !staged || !history && (maxCommitsOption !== undefined || allRefs) ||
    (history || stdin) && exemptionPath || stdin && paths.length > 0 ||
    paths.length > 1 || paths.some(arg => arg.startsWith('--')) ||
    (args.includes('--exemptions') && (!exemptionPath || exemptionPath.startsWith('--'))) ||
    args.filter(arg => arg === '--exemptions').length > 1) {
  process.stderr.write('Usage: node tools/scan.mjs [--sarif] [--fail-on-skip] [--max-bytes 1..8388608] [--stdin | --tracked | --staged [--changed] | --history [--all-refs] [--max-commits 1..10000]] [--exemptions file.json] [directory-or-file]\n');
  process.exitCode = 2;
} else {
  let exemptions = [];
  try {
    if (exemptionPath) exemptions = await loadExemptions(exemptionPath);
  } catch {
    process.stderr.write('Invalid exemption file\n');
    process.exitCode = 2;
  }
  if (process.exitCode !== 2) {
    if (stdin) await visitStdin();
    else if (history) await visitHistory();
    else if (staged) await visitStaged();
    else if (tracked) await visitTracked();
    else await visit(root);
  }
  const used = new Set();
  const visible = findings.filter(hit => {
    const index = exemptions.findIndex(entry => entry.file === hit.file && entry.rule === hit.rule &&
      entry.line === hit.line && entry.column === hit.column);
    if (index < 0) return true;
    used.add(index);
    return false;
  });
  const required = exemptions
    .map((entry, index) => ({ entry, index }))
    .filter(({ entry }) => !changed || changedNames?.has(entry.file));
  if (required.some(({ index }) => !used.has(index))) {
    process.stderr.write('Unused exemption entry\n');
    stats.errors++;
  }
  const incomplete = stats.errors > 0 || failOnSkip && stats.skipped > 0;
  const output = sarif ? {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{
      tool: { driver: { name: 'mbtleakscan', rules: [...new Set(visible.map(hit => hit.rule))].sort().map(id => ({ id })) } },
      results: visible.map(hit => ({
        ruleId: hit.rule,
        level: 'warning',
        message: { text: 'Suspected credential [REDACTED]' },
        ...(hit.commit ? { properties: { commit: hit.commit } } : {}),
        locations: [{ physicalLocation: {
          artifactLocation: { uri: hit.file },
          region: { startLine: hit.line, startColumn: hit.column },
        } }],
      })),
      invocations: [{ executionSuccessful: !incomplete }],
    }],
  } : { findings: visible, stats: { ...stats, exempted: findings.length - visible.length } };
  if (process.exitCode !== 2) process.stdout.write(JSON.stringify(output) + '\n');
  process.exitCode = process.exitCode === 2 || incomplete ? 2 : visible.length ? 1 : 0;
}
