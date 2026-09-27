import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const cli = new URL('./scan.mjs', import.meta.url);
function run(...args) {
  return spawnSync(process.execPath, [fileURLToPath(cli), ...args], { encoding: 'utf8' });
}

test('reports positions in stable order without source values or absolute paths', async () => {
  const root = await mkdtemp(join(tmpdir(), 'scan-fixture-'));
  const secret = 'ghp_' + 'a'.repeat(36);
  try {
    await writeFile(join(root, 'z.txt'), secret);
    await writeFile(join(root, 'a.txt'), 'token=' + secret);
    await mkdir(join(root, '.git'));
    await writeFile(join(root, '.git', 'ignored'), secret);
    await writeFile(join(root, 'binary'), Buffer.from([0, 1, 2]));
    await writeFile(join(root, 'large'), 'x'.repeat(1024 * 1024 + 1));
    const result = run(root);
    assert.equal(result.status, 1, result.stderr);
    assert.equal(result.stdout.includes(secret), false);
    assert.equal(result.stdout.includes(root), false);
    const report = JSON.parse(result.stdout);
    assert.deepEqual(report.findings.map(x => x.file), ['a.txt', 'z.txt']);
    assert.equal(report.findings[0].column, 7);
    assert.deepEqual(report.stats, { scanned: 2, skipped: 2, errors: 0, exempted: 0 });
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('justified exemptions suppress exact matches; stale entries fail', async () => {
  const root = await mkdtemp(join(tmpdir(), 'scan-fixture-'));
  const secret = 'ghp_' + 'a'.repeat(36);
  const exemptionFile = join(root, 'exceptions.json');
  try {
    await writeFile(join(root, 'source.txt'), secret + '\n' + secret);
    const entry = { file: 'source.txt', rule: 'github-token', line: 1, column: 1, reason: 'synthetic fixture' };
    await writeFile(exemptionFile, JSON.stringify({ exemptions: [entry] }));
    let result = run('--exemptions', exemptionFile, root);
    assert.equal(result.status, 1, result.stderr);
    let report = JSON.parse(result.stdout);
    assert.equal(report.findings.length, 1);
    assert.equal(report.findings[0].line, 2);
    assert.equal(report.stats.exempted, 1);
    assert.equal(result.stdout.includes(secret), false);
    result = run('--sarif', '--exemptions', exemptionFile, root);
    assert.equal(result.status, 1, result.stderr);
    assert.equal(JSON.parse(result.stdout).runs[0].results.length, 1);
    await writeFile(exemptionFile, JSON.stringify({ exemptions: [{ ...entry, line: 3 }] }));
    result = run('--exemptions', exemptionFile, root);
    assert.equal(result.status, 2);
    assert.equal(result.stderr.includes(secret), false);
    await writeFile(exemptionFile, JSON.stringify({ exemptions: [{ ...entry, reason: ' ' }] }));
    result = run('--exemptions', exemptionFile, root);
    assert.equal(result.status, 2);
    assert.equal(result.stdout, '');
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('SARIF includes locations and rule identifiers but no matched content', async () => {
  const root = await mkdtemp(join(tmpdir(), 'scan-fixture-'));
  const secret = 'glpat-' + 'a'.repeat(20);
  try {
    await writeFile(join(root, 'sample.txt'), 'first\n' + secret);
    const result = run('--sarif', root);
    assert.equal(result.status, 1, result.stderr);
    assert.equal(result.stdout.includes(secret), false);
    assert.equal(result.stdout.includes(root), false);
    const sarif = JSON.parse(result.stdout);
    assert.equal(sarif.version, '2.1.0');
    assert.deepEqual(sarif.runs[0].tool.driver.rules, [{ id: 'gitlab-access-token' }]);
    assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, 'sample.txt');
    assert.deepEqual(sarif.runs[0].results[0].locations[0].physicalLocation.region, { startLine: 2, startColumn: 1 });
    assert.equal(sarif.runs[0].invocations[0].executionSuccessful, true);
    assert.equal(run('--unknown', root).status, 2);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('clean input succeeds; invalid UTF-8 and missing input fail closed', async () => {
  const root = await mkdtemp(join(tmpdir(), 'scan-fixture-'));
  try {
    await writeFile(join(root, 'clean'), 'hello');
    assert.equal(run(root).status, 0);
    await writeFile(join(root, 'invalid'), Buffer.from([255]));
    assert.equal(run(root).status, 2);
    const missing = run(join(root, 'absent'));
    assert.equal(missing.status, 2);
    assert.equal(JSON.parse(missing.stdout).stats.errors, 1);
    assert.equal(missing.stdout.includes(root), false);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('tracked mode scans Git index paths and excludes untracked files', async () => {
  const root = await mkdtemp(join(tmpdir(), 'scan-fixture-'));
  const secret = 'ghp_' + 'a'.repeat(36);
  try {
    await writeFile(join(root, 'clean.txt'), 'hello');
    await writeFile(join(root, 'untracked.txt'), secret);
    assert.equal(run('--tracked', root).status, 2);
    assert.equal(spawnSync('git', ['init', '-q', root]).status, 0);
    assert.equal(spawnSync('git', ['-C', root, 'add', 'clean.txt']).status, 0);
    let result = run('--tracked', root);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout).stats, { scanned: 1, skipped: 0, errors: 0, exempted: 0 });
    assert.equal(spawnSync('git', ['-C', root, 'add', 'untracked.txt']).status, 0);
    result = run('--tracked', root);
    assert.equal(result.status, 1, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout).findings.map(hit => hit.file), ['untracked.txt']);
    assert.equal(result.stdout.includes(secret), false);
  } finally { await rm(root, { recursive: true, force: true }); }
});
