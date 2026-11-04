'use strict';

// UNIFI_WRITE_LOG: file safety, line format, redaction, and what the tools log.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { InMemoryTransport } = require('@modelcontextprotocol/sdk/inMemory.js');
const { buildMcpServer } = require('../http-server-rw.cjs');
const { createUdmClient } = require('../lib/udm-client.cjs');
const { createAuditLog } = require('../lib/audit-log.cjs');
const { openWriteLog, createWriteLog } = require('../lib/write-log.cjs');
const { validateConfig, resolveWriteLog, ConfigError } = require('../lib/config.cjs');
const { tmpDir, rpc, spawnServer } = require('./helpers.cjs');

const SITE = '00000000-0000-4000-8000-000000000001';
const NET = '00000000-0000-4000-8000-000000000002';
const WIFI = '00000000-0000-4000-8000-000000000003';
const CLIENT = '00000000-0000-4000-8000-000000000004';
const CONSOLE = 'FAKECONSOLE00000000:0000';
const API_KEY = 'fake-key-0000-0000-0000-0000';
const TOKEN = 'fake-token-0000-0000-0000-0000-0000-0000';
const NETCONF = 'fa0e00000000000000000001';
const USER_ID = 'fa0e00000000000000000002';
const RULE_ID = 'fa0e00000000000000000003';
const CI = `/integration/v1/sites/${SITE}`;
const CC = '/api/s/default';
const I = `/proxy/network${CI}`;
const C = `/proxy/network${CC}`;
// Markers that only ever appear in controller responses or in bodies the server builds.
const RESPONSE_MARKER = 'controller-response-marker-0000';
const CURRENT_OBJECT_MARKER = 'current-object-marker-0000';

const posix = process.platform !== 'win32';
const modeOf = (p) => fs.statSync(p).mode & 0o777;
const readLines = (file) => fs.readFileSync(file, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);

let dir;
test.before(() => {
  // Real path, so a symlinked temp directory (macOS /var) doesn't trip the ancestor check.
  dir = fs.realpathSync(tmpDir());
});
test.after(() => fs.rmSync(dir, { recursive: true, force: true }));

// --- file safety -----------------------------------------------------------------

test('openWriteLog creates the file 0600 and missing directories 0700', { skip: !posix }, () => {
  const file = path.join(dir, 'new', 'deeper', 'writes.jsonl');
  const log = openWriteLog(file);
  assert.equal(log.file, file);
  assert.equal(modeOf(file), 0o600);
  assert.equal(modeOf(path.dirname(file)), 0o700);
  log.record({ tool: 't', args: {}, outcome: 'ok' });
  log.record({ tool: 't', args: {}, outcome: 'ok' });
  assert.equal(readLines(file).length, 2);
  // reopening appends, never truncates
  openWriteLog(file).record({ tool: 't', args: {}, outcome: 'ok' });
  assert.equal(readLines(file).length, 3);
});

test('openWriteLog refuses relative paths', () => {
  for (const p of ['writes.jsonl', './writes.jsonl', '~/writes.jsonl', '']) assert.throws(() => openWriteLog(p), /absolute path/, p);
});

test('openWriteLog refuses a symlink, even one pointing at a good file', { skip: !posix }, () => {
  const target = path.join(dir, 'real.jsonl');
  fs.writeFileSync(target, '', { mode: 0o600 });
  const link = path.join(dir, 'link.jsonl');
  fs.symlinkSync(target, link);
  assert.throws(() => openWriteLog(link), /symlink/);
  // a dangling symlink is not followed into creating its target
  const dangling = path.join(dir, 'dangling.jsonl');
  fs.symlinkSync(path.join(dir, 'nowhere.jsonl'), dangling);
  assert.throws(() => openWriteLog(dangling), /symlink/);
  assert.equal(fs.existsSync(path.join(dir, 'nowhere.jsonl')), false);
});

test('openWriteLog refuses a group- or world-writable file and leaves its mode alone (as upstream)', { skip: !posix }, () => {
  for (const mode of [0o620, 0o602, 0o666]) {
    const file = path.join(dir, `wide-${mode.toString(8)}.jsonl`);
    fs.writeFileSync(file, '');
    fs.chmodSync(file, mode);
    assert.throws(() => openWriteLog(file), /group- or world-writable .*chmod 600/, mode.toString(8));
    assert.equal(modeOf(file), mode);
  }
  // readable by others is the operator's choice
  const readable = path.join(dir, 'readable.jsonl');
  fs.writeFileSync(readable, '');
  fs.chmodSync(readable, 0o644);
  openWriteLog(readable).record({ tool: 't', args: {}, outcome: 'ok' });
  assert.equal(modeOf(readable), 0o644);
});

test('openWriteLog refuses a directory, and a file with other hard links', { skip: !posix }, () => {
  const d = path.join(dir, 'a-dir');
  fs.mkdirSync(d);
  assert.throws(() => openWriteLog(d));
  const file = path.join(dir, 'linked.jsonl');
  fs.writeFileSync(file, '', { mode: 0o600 });
  fs.linkSync(file, path.join(dir, 'linked-2.jsonl'));
  assert.throws(() => openWriteLog(file), /hard links/);
});

test('openWriteLog refuses a path with a symlinked directory anywhere above the file', { skip: !posix }, () => {
  const real = path.join(dir, 'real-dir');
  fs.mkdirSync(path.join(real, 'sub'), { recursive: true, mode: 0o700 });
  fs.symlinkSync(real, path.join(dir, 'link-dir'));
  // the parent itself, an ancestor further up, and a missing directory under a link
  for (const file of [
    path.join(dir, 'link-dir', 'writes.jsonl'),
    path.join(dir, 'link-dir', 'sub', 'writes.jsonl'),
    path.join(dir, 'link-dir', 'new', 'writes.jsonl'),
  ]) {
    assert.throws(() => openWriteLog(file), /link-dir\) is a symlink/, file);
  }
  assert.equal(fs.existsSync(path.join(real, 'writes.jsonl')), false);
  assert.equal(fs.existsSync(path.join(real, 'sub', 'writes.jsonl')), false);
  assert.equal(fs.existsSync(path.join(real, 'new')), false);
  // the real path works
  openWriteLog(path.join(real, 'sub', 'writes.jsonl')).record({ tool: 't', args: {}, outcome: 'ok' });
  // a file standing where a directory should be
  fs.writeFileSync(path.join(dir, 'plain-file'), '');
  assert.throws(() => openWriteLog(path.join(dir, 'plain-file', 'writes.jsonl')), /plain-file\) is not a directory/);
});

test('openWriteLog refuses a parent directory others can write to, unless it is sticky', { skip: !posix }, () => {
  for (const mode of [0o770, 0o707, 0o777]) {
    const d = path.join(dir, `wide-dir-${mode.toString(8)}`);
    fs.mkdirSync(d);
    fs.chmodSync(d, mode);
    assert.throws(() => openWriteLog(path.join(d, 'writes.jsonl')), /group- or world-writable without the sticky bit/, mode.toString(8));
    assert.equal(fs.existsSync(path.join(d, 'writes.jsonl')), false);
  }
  // sticky, like /tmp: others can't rename or remove our file
  const sticky = path.join(dir, 'sticky-dir');
  fs.mkdirSync(sticky);
  fs.chmodSync(sticky, 0o1777);
  openWriteLog(path.join(sticky, 'writes.jsonl')).record({ tool: 't', args: {}, outcome: 'ok' });
  // readable by others is fine
  const readable = path.join(dir, 'readable-dir');
  fs.mkdirSync(readable);
  fs.chmodSync(readable, 0o755);
  openWriteLog(path.join(readable, 'writes.jsonl')).record({ tool: 't', args: {}, outcome: 'ok' });
});

test('openWriteLog refuses a parent directory owned by another user (not root)', { skip: !posix }, (t) => {
  const d = path.join(dir, 'owned-dir');
  fs.mkdirSync(d, { mode: 0o700 });
  const owner = fs.statSync(d).uid;
  // Pretend to be someone else rather than chown, which needs root.
  const other = owner === 0 ? 4242 : owner + 4242;
  t.mock.method(process, 'getuid', () => other);
  if (owner === 0) {
    // root-owned directories are accepted for any user
    openWriteLog(path.join(d, 'writes.jsonl')).record({ tool: 't', args: {}, outcome: 'ok' });
    return;
  }
  assert.throws(() => openWriteLog(path.join(d, 'writes.jsonl')), new RegExp(`owned by uid ${owner}, not by this user or root`));
  assert.equal(fs.existsSync(path.join(d, 'writes.jsonl')), false);
});

test('openWriteLog refuses a FIFO without blocking on it', { skip: !posix }, () => {
  const fifo = path.join(dir, 'fifo.jsonl');
  require('node:child_process').execFileSync('mkfifo', ['-m', '600', fifo]);
  // Before the fix this open never returned, so the test would time out.
  assert.throws(() => openWriteLog(fifo), /not a regular file/);
});

// --- line format and redaction ----------------------------------------------------

function memoryLog(extra = {}) {
  const lines = [];
  const errors = [];
  const log = createWriteLog({ sink: (l) => lines.push(l), secrets: [API_KEY, TOKEN], onError: (m) => errors.push(m), ...extra });
  return { log, lines, errors, parsed: () => lines.map((l) => JSON.parse(l)) };
}

test('record: one JSON line with timestamps, tool, redacted args, request, outcome, status, duration', () => {
  const { log, lines, parsed } = memoryLog();
  const startedAt = new Date('2026-10-19T12:00:00.000Z');
  log.record({ tool: 'unifi_rw_set_fixed_ip', args: { mac: 'aa:bb:cc:00:00:01', fixed_ip: '192.0.2.10' }, method: 'PUT', endpoint: `${CC}/rest/user/${USER_ID}?x=1`, outcome: 'ok', status: 200, startedAt, durationMs: 12 });
  assert.equal(lines.length, 1);
  assert.ok(lines[0].endsWith('\n') && !lines[0].slice(0, -1).includes('\n'));
  const [l] = parsed();
  assert.equal(l.ts, '2026-10-19T12:00:00.000Z');
  assert.match(l.ts_local, /^2026-10-1\dT\d\d:\d\d:\d\d\.000[+-]\d\d:\d\d$/);
  assert.deepEqual(
    { ...l, ts: undefined, ts_local: undefined },
    { ts: undefined, ts_local: undefined, tool: 'unifi_rw_set_fixed_ip', args: { mac: 'aa:bb:cc:00:00:01', fixed_ip: '192.0.2.10' }, method: 'PUT', endpoint: `${CC}/rest/user/${USER_ID}`, dry_run: false, outcome: 'ok', status: 200, duration_ms: 12 }
  );
});

test('record: secrets in args are redacted by key, and secret values anywhere are scrubbed', () => {
  const { log, parsed } = memoryLog();
  log.record({
    tool: 'unifi_rw_create_wifi_broadcast',
    args: {
      broadcast: { name: 'Lab', securityConfiguration: { type: 'WPA2_PERSONAL', passphrase: 'fake-passphrase-0000' }, x_passphrase: 'fake-x-passphrase-0000' },
      password: 'fake-password-0000',
      api_key: 'fake-other-key-0000',
      token: 'fake-other-token-0000',
      note: `pasted ${API_KEY} and ${TOKEN}`,
    },
    outcome: 'refused',
    reason: 'guard',
    error: `bad thing near ${API_KEY}`,
  });
  const text = JSON.stringify(parsed());
  for (const s of ['fake-passphrase-0000', 'fake-x-passphrase-0000', 'fake-password-0000', 'fake-other-key-0000', 'fake-other-token-0000', API_KEY, TOKEN]) assert.ok(!text.includes(s), s);
  const [l] = parsed();
  assert.equal(l.args.broadcast.securityConfiguration.passphrase, '[REDACTED]');
  assert.equal(l.args.broadcast.x_passphrase, '[REDACTED]');
  assert.equal(l.args.password, '[REDACTED]');
  assert.equal(l.args.note, 'pasted [REDACTED] and [REDACTED]');
  assert.equal(l.args.broadcast.name, 'Lab');
  assert.equal(l.error, 'bad thing near [REDACTED]');
  assert.equal(l.reason, 'guard');
});

test('record: long errors are cut to 300 characters after scrubbing', () => {
  const { log, parsed } = memoryLog();
  log.record({ tool: 't', args: {}, outcome: 'error', error: `${'x'.repeat(295)}${API_KEY}${'y'.repeat(50)}` });
  const { error } = parsed()[0];
  assert.equal(error.length, 303);
  assert.ok(!error.includes('fake-key'));
});

test('record never throws: a failing sink is reported once, and later lines are still attempted', () => {
  let calls = 0;
  const errors = [];
  const log = createWriteLog({
    sink: () => {
      calls++;
      throw new Error(`disk full near ${API_KEY}`);
    },
    secrets: [API_KEY],
    onError: (m) => errors.push(m),
  });
  log.record({ tool: 't', args: {}, outcome: 'ok' });
  log.record({ tool: 't', args: {}, outcome: 'ok' });
  assert.equal(calls, 2);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /write log: cannot append \(disk full near \[REDACTED\]\); tool calls continue/);
  // an invalid outcome is a bug, reported the same way
  const m = memoryLog();
  m.log.record({ tool: 't', args: {}, outcome: 'maybe' });
  assert.equal(m.lines.length, 0);
  assert.match(m.errors[0], /unknown outcome/);
});

// --- config ------------------------------------------------------------------------

test('config: UNIFI_WRITE_LOG must be absolute; unset/empty means off; ignored (with a warning) when read-only', () => {
  assert.equal(resolveWriteLog({}), null);
  assert.equal(resolveWriteLog({ UNIFI_WRITE_LOG: '' }), null);
  assert.equal(resolveWriteLog({ UNIFI_WRITE_LOG: '/var/log/x/../writes.jsonl' }), '/var/log/writes.jsonl');
  for (const v of ['writes.jsonl', './w.jsonl', '~/w.jsonl', '../w.jsonl']) {
    assert.throws(() => resolveWriteLog({ UNIFI_WRITE_LOG: v }), (e) => e instanceof ConfigError && /UNIFI_WRITE_LOG must be an absolute path/.test(e.message), v);
  }
  const rw = validateConfig({ console_id: CONSOLE, allow_writes: true }, { env: { UNIFI_WRITE_LOG: '/tmp/fake/writes.jsonl' } });
  assert.equal(rw.writeLog, '/tmp/fake/writes.jsonl');
  const ro = validateConfig({ console_id: CONSOLE }, { env: { UNIFI_WRITE_LOG: '/tmp/fake/writes.jsonl' } });
  assert.equal(ro.writeLog, null);
  assert.ok(ro.warnings.some((w) => /UNIFI_WRITE_LOG ignored: the server is read-only/.test(w)));
  assert.throws(() => validateConfig({ console_id: CONSOLE }, { env: { UNIFI_WRITE_LOG: 'relative.jsonl' } }), ConfigError);
});

// --- what the tools log ------------------------------------------------------------

const ZONE_INTERNAL = '00000000-0000-4000-8000-0000000000a1';
const ZONE_EXTERNAL = '00000000-0000-4000-8000-0000000000e1';

const fixtures = {
  [`${I}/wifi/broadcasts/${WIFI}`]: {
    status: 200,
    body: { id: WIFI, metadata: { origin: 'USER_DEFINED' }, type: 'STANDARD', name: 'Lab', enabled: true, network: { type: 'SPECIFIC', networkId: NET }, securityConfiguration: { type: 'WPA2_PERSONAL', passphrase: 'fake-current-passphrase-0000' }, clientIsolationEnabled: false, hideName: false, note: CURRENT_OBJECT_MARKER },
  },
  [`${I}/networks/${NET}`]: {
    status: 200,
    body: { id: NET, management: 'GATEWAY', name: CURRENT_OBJECT_MARKER, enabled: true, vlanId: 10, metadata: { origin: 'USER_DEFINED' }, zoneId: ZONE_INTERNAL, mdnsForwardingEnabled: false },
  },
  [`${I}/firewall/zones?limit=200`]: {
    status: 200,
    body: { data: [{ id: ZONE_INTERNAL, name: 'Internal', metadata: { origin: 'SYSTEM_DEFINED' } }, { id: ZONE_EXTERNAL, name: 'External', metadata: { origin: 'SYSTEM_DEFINED' } }] },
  },
  [`${C}/rest/user`]: { status: 200, body: { meta: { rc: 'ok' }, data: [{ _id: USER_ID, mac: 'aa:bb:cc:00:00:01', name: 'printer', use_fixedip: false }] } },
  [`${C}/rest/firewallrule/${RULE_ID}`]: {
    status: 200,
    body: { meta: { rc: 'ok' }, data: [{ _id: RULE_ID, site_id: 'x', name: 'block in', ruleset: 'WAN_IN', action: 'drop', rule_index: 2000, enabled: true }] },
  },
};

async function stack(name, { writeStatus = 200 } = {}) {
  const sent = [];
  const auditLog = createAuditLog({ stateDir: path.join(dir, `${name}-state`) });
  const file = path.join(dir, `${name}.jsonl`);
  const writeLog = openWriteLog(file, { secrets: [API_KEY, TOKEN] });
  const udm = createUdmClient({
    backend: 'local',
    target: { host: 'udm.test', port: 443, isIp: false, hostHeader: 'udm.test' },
    apiKey: API_KEY,
    siteId: SITE,
    allowWrites: true,
    auditLog,
    transport: async (req) => {
      sent.push(req);
      if (req.method !== 'GET') return { status: writeStatus, text: JSON.stringify({ meta: { rc: 'ok' }, data: [{ echo: RESPONSE_MARKER }], message: RESPONSE_MARKER }) };
      const f = fixtures[req.path];
      return f ? { status: f.status, text: JSON.stringify(f.body) } : { status: 404, text: JSON.stringify({ message: RESPONSE_MARKER }) };
    },
  });
  const server = buildMcpServer({ udmClient: udm, auditLog, writeLog, secrets: [TOKEN] });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await server.connect(a);
  const client = new Client({ name: 'test', version: '1' });
  await client.connect(b);
  const call = async (tool, args) => {
    const r = await client.callTool({ name: tool, arguments: args });
    return { isError: Boolean(r.isError), text: r.content[0].text };
  };
  return { call, sent, file, lines: () => readLines(file), last: () => readLines(file).at(-1), auditLog };
}

test('tools: a successful write logs ok with method, canonical endpoint and status; no bodies', async () => {
  const s = await stack('ok');
  const r = await s.call('unifi_rw_set_fixed_ip', { mac: 'AA-BB-CC-00-00-01', fixed_ip: '192.0.2.10', network_id: NETCONF });
  assert.equal(r.isError, false, r.text);
  const l = s.last();
  assert.equal(l.tool, 'unifi_rw_set_fixed_ip');
  assert.deepEqual(l.args, { mac: 'AA-BB-CC-00-00-01', fixed_ip: '192.0.2.10', network_id: NETCONF, dry_run: false });
  assert.equal(l.method, 'PUT');
  assert.equal(l.endpoint, `${CC}/rest/user/${USER_ID}`);
  assert.equal(l.outcome, 'ok');
  assert.equal(l.status, 200);
  assert.equal(l.dry_run, false);
  assert.ok(Number.isInteger(l.duration_ms));
  assert.equal(l.reason, undefined);
  assert.equal(l.error, undefined);
  assert.ok(!fs.readFileSync(s.file, 'utf8').includes(RESPONSE_MARKER));
});

test('tools: an update logs the caller\'s args, never the merged body built from the controller object', async () => {
  const s = await stack('merge');
  let r = await s.call('unifi_rw_update_wifi_broadcast', { broadcast_id: WIFI, changes: { name: 'Lab 2', securityConfiguration: { passphrase: 'fake-new-passphrase-0000' } } });
  assert.equal(r.isError, false, r.text);
  r = await s.call('unifi_rw_update_network', { network_id: NET, changes: { mdnsForwardingEnabled: true } });
  assert.equal(r.isError, false, r.text);
  const text = fs.readFileSync(s.file, 'utf8');
  for (const m of [CURRENT_OBJECT_MARKER, RESPONSE_MARKER, 'fake-current-passphrase-0000', 'fake-new-passphrase-0000', API_KEY, 'udm.test', '/proxy/network']) assert.ok(!text.includes(m), m);
  const [wifi, network] = s.lines();
  assert.deepEqual(wifi.args.changes, { name: 'Lab 2', securityConfiguration: { passphrase: '[REDACTED]' } });
  assert.equal(wifi.endpoint, `${CI}/wifi/broadcasts/${WIFI}`);
  assert.deepEqual(network.args, { network_id: NET, changes: { mdnsForwardingEnabled: true }, dry_run: false });
  assert.equal(network.outcome, 'ok');
});

test('tools: dry_run logs dry_run and sends nothing', async () => {
  const s = await stack('dry');
  const r = await s.call('unifi_rw_clear_fixed_ip', { mac: 'aa:bb:cc:00:00:01', dry_run: true });
  assert.equal(r.isError, false, r.text);
  const l = s.last();
  assert.equal(l.outcome, 'dry_run');
  assert.equal(l.dry_run, true);
  assert.equal(l.method, 'PUT');
  assert.equal(l.endpoint, `${CC}/rest/user/${USER_ID}`);
  assert.equal(l.status, undefined);
  assert.equal(s.sent.filter((q) => q.method !== 'GET').length, 0);
});

test('tools: a guard refusal logs refused / guard with the request it refused', async () => {
  const s = await stack('guard');
  const r = await s.call('unifi_rw_update_legacy_firewall_rule', { rule_id: RULE_ID, changes: { enabled: false } });
  assert.equal(r.isError, true);
  const l = s.last();
  assert.equal(l.outcome, 'refused');
  assert.equal(l.reason, 'guard');
  assert.equal(l.method, 'PUT');
  assert.equal(l.endpoint, `${CC}/rest/firewallrule/${RULE_ID}`);
  assert.match(l.error, /Refused by guard: rule is a WAN_IN drop rule; only name, logging may change/);
  assert.equal(s.sent.filter((q) => q.method !== 'GET').length, 0);
});

test('tools: a WAN-exposure refusal logs refused / wan_exposure before anything is sent', async () => {
  const s = await stack('wan');
  const r = await s.call('unifi_rw_create_legacy_firewall_rule', { rule: { name: 'ssh in', ruleset: 'WAN_IN', action: 'accept', dst_port: '22' }, dry_run: true });
  assert.equal(r.isError, true);
  assert.match(r.text, /^Refused: legacy rule on WAN_IN with action "accept" would let traffic in from the WAN/);
  const l = s.last();
  assert.equal(l.outcome, 'refused');
  assert.equal(l.reason, 'wan_exposure');
  assert.equal(l.method, 'POST');
  assert.equal(l.endpoint, `${CC}/rest/firewallrule`);
  assert.equal(l.dry_run, true);
  assert.deepEqual(s.sent, []);
  // the audit log records the same refusal
  const audit = readLines(s.auditLog.file).at(-1);
  assert.equal(audit.status, 'refused');
  assert.equal(audit.endpoint, `${CC}/rest/firewallrule`);
});

test('tools: a controller error logs error with the HTTP status and a summary, not the response body', async () => {
  const s = await stack('err', { writeStatus: 500 });
  const r = await s.call('unifi_rw_unauthorize_guest', { client_id: CLIENT });
  assert.equal(r.isError, true);
  const l = s.last();
  assert.equal(l.outcome, 'error');
  assert.equal(l.reason, undefined);
  assert.equal(l.status, 500);
  assert.equal(l.endpoint, `${CI}/clients/${CLIENT}/actions`);
  assert.match(l.error, /"status":500/);
  assert.ok(!fs.readFileSync(s.file, 'utf8').includes(RESPONSE_MARKER));
});

test('tools: a failure before any request (lookup) logs error with no endpoint', async () => {
  const s = await stack('lookup');
  const r = await s.call('unifi_rw_clear_fixed_ip', { mac: 'aa:bb:cc:00:00:09' });
  assert.equal(r.isError, true);
  const l = s.last();
  assert.equal(l.outcome, 'error');
  assert.equal(l.method, null);
  assert.equal(l.endpoint, null);
  assert.match(l.error, /no client record for that MAC/);
});

test('tools: read tools are never logged', async () => {
  const s = await stack('reads');
  await s.call('unifi_rw_list_fixed_ips', {});
  await s.call('unifi_rw_get_network', { network_id: NET });
  assert.equal(fs.readFileSync(s.file, 'utf8'), '');
});

// --- server process ----------------------------------------------------------------

test('server process: UNIFI_WRITE_LOG is created 0600 at startup and named in the startup lines', { skip: !posix }, async () => {
  const file = path.join(dir, 'proc-log', 'logs', 'writes.jsonl');
  const s = await spawnServer(dir, 'proc-log', { config: { console_id: CONSOLE, site_id: SITE, allow_writes: true }, env: { UNIFI_WRITE_LOG: file } });
  try {
    assert.equal(await s.started, true, s.stderr());
    assert.equal(modeOf(file), 0o600);
    await rpc(s.port, s.token, 'tools/list');
    assert.match(s.stderr(), new RegExp(`write safeguards: write_tools=all write_log=${file.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')} wan_exposure=refused`));
  } finally {
    s.child.kill('SIGTERM');
    await s.exited;
  }
});

test('server process: a relative, symlinked or world-writable UNIFI_WRITE_LOG stops startup with exit 2', { skip: !posix }, async () => {
  const target = path.join(dir, 'proc-target.jsonl');
  fs.writeFileSync(target, '', { mode: 0o600 });
  const link = path.join(dir, 'proc-link.jsonl');
  fs.symlinkSync(target, link);
  const wide = path.join(dir, 'proc-wide.jsonl');
  fs.writeFileSync(wide, '');
  fs.chmodSync(wide, 0o666);
  for (const [name, value, re] of [
    ['proc-rel', 'logs/writes.jsonl', /refusing to start: UNIFI_WRITE_LOG must be an absolute path/],
    ['proc-link', link, /refusing to start: cannot use UNIFI_WRITE_LOG \(.*proc-link\.jsonl\): it is a symlink/],
    ['proc-wide', wide, /refusing to start: cannot use UNIFI_WRITE_LOG \(.*\): it is group- or world-writable/],
  ]) {
    const s = await spawnServer(dir, name, { config: { console_id: CONSOLE, site_id: SITE, allow_writes: true }, env: { UNIFI_WRITE_LOG: value } });
    assert.equal(await s.started, false, name);
    assert.deepEqual(await s.exited, { code: 2, signal: null }, name);
    assert.match(s.stderr(), re, name);
  }
});
