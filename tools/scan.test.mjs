import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const cli = new URL('./scan.mjs', import.meta.url);
function run(path) {
  return spawnSync(process.execPath, [fileURLToPath(cli), path], { encoding: 'utf8' });
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
    assert.deepEqual(report.stats, { scanned: 2, skipped: 2, errors: 0 });
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
