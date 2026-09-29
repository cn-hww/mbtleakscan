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

function runInput(input, ...args) {
  return spawnSync(process.execPath, [fileURLToPath(cli), ...args], {
    encoding: 'utf8', input,
  });
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

test('fail-on-skip marks partial scans as incomplete in JSON and SARIF', async () => {
  const root = await mkdtemp(join(tmpdir(), 'scan-fixture-'));
  try {
    await writeFile(join(root, 'clean.txt'), 'hello');
    await writeFile(join(root, 'binary.bin'), Buffer.from([0, 1, 2]));
    assert.equal(run(root).status, 0);
    let result = run('--fail-on-skip', root);
    assert.equal(result.status, 2, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout).stats, { scanned: 1, skipped: 1, errors: 0, exempted: 0 });
    result = run('--sarif', '--fail-on-skip', root);
    assert.equal(result.status, 2, result.stderr);
    assert.equal(JSON.parse(result.stdout).runs[0].invocations[0].executionSuccessful, false);
    assert.equal(spawnSync('git', ['init', '-q', root]).status, 0);
    assert.equal(spawnSync('git', ['-C', root, 'add', 'binary.bin', 'clean.txt']).status, 0);
    result = run('--staged', '--fail-on-skip', root);
    assert.equal(result.status, 2, result.stderr);
    assert.equal(JSON.parse(result.stdout).stats.skipped, 1);
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

test('staged mode reads index blobs even after working tree changes', async () => {
  const root = await mkdtemp(join(tmpdir(), 'scan-fixture-'));
  const secret = 'glpat-' + 'a'.repeat(20);
  try {
    assert.equal(spawnSync('git', ['init', '-q', root]).status, 0);
    await writeFile(join(root, 'sample.txt'), secret);
    assert.equal(spawnSync('git', ['-C', root, 'add', 'sample.txt']).status, 0);
    await writeFile(join(root, 'sample.txt'), 'safe working copy');
    let result = run('--staged', root);
    assert.equal(result.status, 1, result.stderr);
    assert.equal(result.stdout.includes(secret), false);
    assert.deepEqual(JSON.parse(result.stdout).findings.map(hit => hit.file), ['sample.txt']);
    assert.equal(run('--tracked', root).status, 0);
    await rm(join(root, 'sample.txt'));
    result = run('--staged', root);
    assert.equal(result.status, 1, result.stderr);
    assert.equal(JSON.parse(result.stdout).stats.scanned, 1);
    assert.equal(run('--tracked', root).status, 2);
    assert.equal(run('--staged', '--tracked', root).status, 2);
    assert.equal(run('--staged', '--changed', root).status, 1);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('changed mode limits staged scanning to the next commit', async () => {
  const root = await mkdtemp(join(tmpdir(), 'scan-fixture-'));
  const secret = 'ghp_' + 'a'.repeat(36);
  try {
    assert.equal(spawnSync('git', ['init', '-q', root]).status, 0);
    await writeFile(join(root, 'historic.txt'), secret);
    assert.equal(spawnSync('git', ['-C', root, 'add', 'historic.txt']).status, 0);
    assert.equal(spawnSync('git', ['-C', root, '-c', 'user.name=Fixture',
      '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'baseline']).status, 0);
    await writeFile(join(root, 'next.txt'), secret);
    assert.equal(spawnSync('git', ['-C', root, 'add', 'next.txt']).status, 0);
    await writeFile(join(root, 'next.txt'), 'clean working copy');
    const all = JSON.parse(run('--staged', root).stdout);
    assert.deepEqual(all.findings.map(hit => hit.file), ['historic.txt', 'next.txt']);
    let result = run('--staged', '--changed', root);
    assert.equal(result.status, 1, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout).findings.map(hit => hit.file), ['next.txt']);
    assert.equal(result.stdout.includes(secret), false);
    assert.equal(run('--changed', root).status, 2);
    assert.equal(spawnSync('git', ['-C', root, 'reset', '-q', '--', 'next.txt']).status, 0);
    result = run('--staged', '--changed', root);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).stats.scanned, 0);
    assert.equal(spawnSync('git', ['-C', root, 'rm', '-q', 'historic.txt']).status, 0);
    assert.equal(run('--staged', '--changed', root).status, 0);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('changed mode ignores unrelated exemptions but checks changed locations', async () => {
  const root = await mkdtemp(join(tmpdir(), 'scan-fixture-'));
  const secret = 'ghp_' + 'a'.repeat(36);
  const exemptionFile = join(root, 'exceptions.json');
  try {
    assert.equal(spawnSync('git', ['init', '-q', root]).status, 0);
    await writeFile(join(root, 'historic.txt'), secret);
    assert.equal(spawnSync('git', ['-C', root, 'add', 'historic.txt']).status, 0);
    assert.equal(spawnSync('git', ['-C', root, '-c', 'user.name=Fixture',
      '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'baseline']).status, 0);
    await writeFile(exemptionFile, JSON.stringify({ exemptions: [{
      file: 'historic.txt', rule: 'github-token', line: 1, column: 1,
      reason: 'synthetic fixture',
    }] }));
    let result = run('--staged', '--changed', '--exemptions', exemptionFile, root);
    assert.equal(result.status, 0, result.stderr);
    await writeFile(join(root, 'next.txt'), 'safe change');
    assert.equal(spawnSync('git', ['-C', root, 'add', 'next.txt']).status, 0);
    result = run('--staged', '--changed', '--exemptions', exemptionFile, root);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).stats.scanned, 1);
    result = run('--staged', '--exemptions', exemptionFile, root);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).stats.exempted, 1);
    await writeFile(join(root, 'historic.txt'), '\n' + secret);
    assert.equal(spawnSync('git', ['-C', root, 'add', 'historic.txt']).status, 0);
    result = run('--staged', '--changed', '--exemptions', exemptionFile, root);
    assert.equal(result.status, 2);
    assert.equal(result.stdout.includes(secret), false);
    assert.equal(result.stderr.includes(secret), false);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('max-bytes raises the limit for directory and staged scans', async () => {
  const root = await mkdtemp(join(tmpdir(), 'scan-fixture-'));
  const secret = 'glpat-' + 'a'.repeat(20);
  try {
    await writeFile(join(root, 'large.txt'), 'x'.repeat(1024 * 1024) + '\n' + secret);
    let result = run('--fail-on-skip', root);
    assert.equal(result.status, 2, result.stderr);
    assert.equal(JSON.parse(result.stdout).stats.skipped, 1);
    result = run('--max-bytes', '2097152', root);
    assert.equal(result.status, 1, result.stderr);
    assert.equal(result.stdout.includes(secret), false);
    assert.equal(JSON.parse(result.stdout).findings[0].line, 2);
    assert.equal(run('--max-bytes', '0', root).status, 2);
    assert.equal(run('--max-bytes').status, 2);
    assert.equal(run('--max-bytes', root, '--max-bytes').status, 2);
    assert.equal(run('--max-bytes', '8388609', root).status, 2);
    assert.equal(run('--max-bytes', '2', '--max-bytes', '3', root).status, 2);
    assert.equal(spawnSync('git', ['init', '-q', root]).status, 0);
    assert.equal(spawnSync('git', ['-C', root, 'add', 'large.txt']).status, 0);
    result = run('--staged', '--changed', '--fail-on-skip', root);
    assert.equal(result.status, 2, result.stderr);
    result = run('--staged', '--changed', '--fail-on-skip', '--max-bytes', '2097152', root);
    assert.equal(result.status, 1, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout).findings.map(hit => hit.file), ['large.txt']);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('new engine rules pass through the CLI without exposing values', async () => {
  const root = await mkdtemp(join(tmpdir(), 'scan-fixture-'));
  const jwt = [
    Buffer.from('{"alg":"HS256"}').toString('base64url'),
    Buffer.from('{"sub":"synthetic"}').toString('base64url'),
    'A'.repeat(43),
  ].join('.');
  const values = [
    'https://reader:p%40ss@host.example',
    jwt,
    'sk_live_' + 'aB3'.repeat(10),
    'xoxb-12345678-' + 'aBcD'.repeat(5),
  ];
  try {
    await writeFile(join(root, 'sample.txt'), values.join('\n'));
    const result = run(root);
    assert.equal(result.status, 1, result.stderr);
    for (const value of values) assert.equal(result.stdout.includes(value), false);
    assert.equal(result.stdout.includes(root), false);
    assert.deepEqual(JSON.parse(result.stdout).findings.map(hit => hit.rule), [
      'url-password', 'jwt-candidate', 'stripe-secret-key', 'slack-token',
    ]);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('history mode finds removed credentials and reports the commit without the value', async () => {
  const root = await mkdtemp(join(tmpdir(), 'scan-fixture-'));
  const secret = 'ghp_' + 'a'.repeat(36);
  const commit = message => spawnSync('git', ['-C', root, '-c', 'user.name=Fixture',
    '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', message]);
  try {
    assert.equal(spawnSync('git', ['init', '-q', root]).status, 0);
    await writeFile(join(root, 'config.txt'), secret);
    assert.equal(spawnSync('git', ['-C', root, 'add', 'config.txt']).status, 0);
    assert.equal(commit('add synthetic value').status, 0);
    const first = spawnSync('git', ['-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).stdout.trim();
    await writeFile(join(root, 'config.txt'), 'clean');
    assert.equal(spawnSync('git', ['-C', root, 'add', 'config.txt']).status, 0);
    assert.equal(commit('remove synthetic value').status, 0);
    assert.equal(run(root).status, 0);
    const result = run('--history', root);
    assert.equal(result.status, 1, result.stderr);
    assert.equal(result.stdout.includes(secret), false);
    assert.equal(result.stdout.includes(root), false);
    const report = JSON.parse(result.stdout);
    assert.equal(report.findings.length, 1);
    assert.equal(report.findings[0].file, 'config.txt');
    assert.equal(report.findings[0].commit, first);
    assert.deepEqual(report.stats, { scanned: 2, skipped: 0, errors: 0, exempted: 0 });
    const sarif = JSON.parse(run('--history', '--sarif', root).stdout);
    assert.equal(sarif.runs[0].results[0].properties.commit, first);
    const truncated = run('--history', '--max-commits', '1', root);
    assert.equal(truncated.status, 2);
    assert.equal(JSON.parse(truncated.stdout).stats.errors, 1);
    assert.equal(run('--history', '--staged', root).status, 2);
    assert.equal(run('--max-commits', '2', root).status, 2);
    assert.equal(run('--history', '--max-commits', '0', root).status, 2);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('stdin mode scans bounded input without echoing it', () => {
  const secret = 'ghp_' + 'a'.repeat(36);
  let result = runInput('prefix ' + secret, '--stdin');
  assert.equal(result.status, 1, result.stderr);
  assert.equal(result.stdout.includes(secret), false);
  assert.deepEqual(JSON.parse(result.stdout).findings.map(hit => hit.file), ['stdin']);
  result = runInput('prefix ' + secret, '--stdin', '--sarif');
  assert.equal(result.status, 1, result.stderr);
  assert.equal(JSON.parse(result.stdout).runs[0].results[0].locations[0]
    .physicalLocation.artifactLocation.uri, 'stdin');
  assert.equal(runInput('clean', '--stdin').status, 0);
  assert.equal(runInput(Buffer.from([255]), '--stdin').status, 2);
  result = runInput('x'.repeat(1025), '--stdin', '--max-bytes', '1024', '--fail-on-skip');
  assert.equal(result.status, 2);
  assert.equal(JSON.parse(result.stdout).stats.skipped, 1);
  assert.equal(runInput('clean', '--stdin', '.').status, 2);
  assert.equal(runInput('clean', '--stdin', '--tracked').status, 2);
});

test('assigned credential findings pass through the CLI without the value', () => {
  const value = 'Ab3dE4fG5hI6jK7lM8nP9qR0';
  const result = runInput('API_KEY=' + value, '--stdin');
  assert.equal(result.status, 1, result.stderr);
  assert.equal(result.stdout.includes(value), false);
  assert.deepEqual(JSON.parse(result.stdout).findings.map(hit => hit.rule), [
    'assigned-credential',
  ]);
});

test('all-refs history finds an unmerged branch without exposing its value', async () => {
  const root = await mkdtemp(join(tmpdir(), 'scan-fixture-'));
  const secret = 'glpat-' + 'a'.repeat(20);
  const commit = message => spawnSync('git', ['-C', root, '-c', 'user.name=Fixture',
    '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', message]);
  try {
    assert.equal(spawnSync('git', ['init', '-q', root]).status, 0);
    await writeFile(join(root, 'base.txt'), 'clean');
    assert.equal(spawnSync('git', ['-C', root, 'add', 'base.txt']).status, 0);
    assert.equal(commit('base').status, 0);
    const branch = spawnSync('git', ['-C', root, 'branch', '--show-current'], {
      encoding: 'utf8',
    }).stdout.trim();
    assert.equal(spawnSync('git', ['-C', root, 'switch', '-qc', 'side']).status, 0);
    await writeFile(join(root, 'side.txt'), secret);
    assert.equal(spawnSync('git', ['-C', root, 'add', 'side.txt']).status, 0);
    assert.equal(commit('side').status, 0);
    assert.equal(spawnSync('git', ['-C', root, 'switch', '-q', branch]).status, 0);
    assert.equal(run('--history', root).status, 0);
    const result = run('--history', '--all-refs', root);
    assert.equal(result.status, 1, result.stderr);
    assert.equal(result.stdout.includes(secret), false);
    assert.deepEqual(JSON.parse(result.stdout).findings.map(hit => hit.file), ['side.txt']);
    assert.equal(run('--all-refs', root).status, 2);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('PyPI and npm registry candidates retain redacted CLI output', () => {
  const pypi = 'pypi-' + 'Ab3_d-'.repeat(15);
  const npm = 'a1b2c3d4'.repeat(5);
  const result = runInput(`upload=${pypi}\n//registry.npmjs.org/:_authToken=${npm}`, '--stdin');
  assert.equal(result.status, 1, result.stderr);
  assert.equal(result.stdout.includes(pypi), false);
  assert.equal(result.stdout.includes(npm), false);
  assert.deepEqual(JSON.parse(result.stdout).findings.map(hit => hit.rule), [
    'pypi-api-token', 'npm-auth-token',
  ]);
});
