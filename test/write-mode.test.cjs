'use strict';

// allow_writes / UNIFI_ALLOW_WRITES, read-only mode, and the server process
// itself (startup line, config errors, SIGTERM drain).

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { InMemoryTransport } = require('@modelcontextprotocol/sdk/inMemory.js');
const { buildMcpServer, startupSummary } = require('../http-server-rw.cjs');
const { createUdmClient, PROBE_READ_ONLY } = require('../lib/udm-client.cjs');
const { createAuditLog } = require('../lib/audit-log.cjs');
const { validateConfig, ConfigError } = require('../lib/config.cjs');
const { GuardError } = require('../lib/guard.cjs');
const { READ_TOOLS, WRITE_TOOLS, TOOL_NAMES } = require('../lib/tools.cjs');
const { tmpDir, rpc } = require('./helpers.cjs');

const SITE = '88f7af54-98f8-306a-a1c7-c9349722b1f6';
const CLIENT = '7a2e4c90-1d3b-4f6a-8e25-c4b9d0f13a77';
const NET = '3f6c2a10-5b7e-4d2a-9c41-7e8d0a6b1c25';
const CONSOLE = '942A6FF664C0000000000964970E0000000009E710560000000068A9873F:9999999999';
const API_KEY = 'write-mode-api-key-0123456789abcdef';
const SERVER = path.join(__dirname, '..', 'http-server-rw.cjs');

let dir;
test.before(() => {
  dir = tmpDir();
});
test.after(() => fs.rmSync(dir, { recursive: true, force: true }));

const localClient = (extra = {}) =>
  createUdmClient({ backend: 'local', target: { host: 'udm.test', port: 443, isIp: false, hostHeader: 'udm.test' }, apiKey: API_KEY, siteId: SITE, ...extra });

async function mcp(udmClient, auditLog) {
  const server = buildMcpServer({ udmClient, auditLog });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await server.connect(a);
  const c = new Client({ name: 'test', version: '1' });
  await c.connect(b);
  return c;
}
const names = async (udm) => (await (await mcp(udm)).listTools()).tools.map((t) => t.name).sort();

test('tools/list: read-only mode registers only read tools; allow_writes registers all', async () => {
  const noSend = async () => {
    throw new Error('must not send');
  };
  assert.deepEqual(await names(localClient({ transport: noSend })), [...READ_TOOLS].sort());
  for (const v of [false, 'true', 1, null]) assert.deepEqual(await names(localClient({ transport: noSend, allowWrites: v })), [...READ_TOOLS].sort(), String(v));
  assert.deepEqual(await names(localClient({ transport: noSend, allowWrites: true })), [...TOOL_NAMES].sort());
  // cloud without classic capabilities: read tools minus the classic ones
  const cloud = createUdmClient({ backend: 'cloud', consoleId: CONSOLE, apiKey: API_KEY, siteId: SITE, transport: noSend });
  const got = await names(cloud);
  assert.ok(got.every((n) => READ_TOOLS.includes(n)) && got.includes('unifi_rw_get_network') && !got.includes('unifi_rw_list_fixed_ips'));
  // a write tool is not callable in read-only mode
  const c = await mcp(localClient({ transport: noSend }));
  const r = await c.callTool({ name: 'unifi_rw_unauthorize_guest', arguments: { client_id: CLIENT, dry_run: true } }).catch((e) => ({ isError: true, content: [{ text: e.message }] }));
  assert.equal(r.isError, true);
  assert.match(r.content[0].text, /not found/i);
});

test('read-only client refuses every non-GET before any socket, dry_run included', async () => {
  const sent = [];
  const udm = localClient({ transport: async (req) => (sent.push(req), { status: 200, headers: {}, text: '{"data":[]}' }) });
  assert.equal(udm.writesEnabled, false);
  for (const method of ['POST', 'PUT', 'PATCH', 'DELETE', 'post', 'HEAD']) {
    for (const dryRun of [true, false]) {
      await assert.rejects(udm.request({ method, path: `/integration/v1/sites/${SITE}/clients/${CLIENT}/actions`, body: { action: 'UNAUTHORIZE_GUEST_ACCESS' }, dryRun }), (e) => e instanceof GuardError && /read-only mode/.test(e.message), `${method} ${dryRun}`);
    }
  }
  assert.equal(sent.length, 0);
  // reads still work
  await udm.request({ method: 'GET', path: '/integration/v1/info' });
  assert.equal(sent.length, 1);
  // the probe client never becomes write-enabled
  const probe = localClient({ allowWrites: true, [PROBE_READ_ONLY]: true, transport: async () => ({ status: 200, headers: {}, text: '{}' }) });
  assert.equal(probe.writesEnabled, false);
});

test('a write tool invoked against a read-only client is refused by the client and logged (second check)', async () => {
  const sent = [];
  const auditLog = createAuditLog({ stateDir: path.join(dir, 'state-ro') });
  const real = localClient({
    auditLog,
    transport: async (req) => {
      sent.push(req);
      return { status: 200, headers: {}, text: JSON.stringify({ id: NET, name: 'Default', mdnsForwardingEnabled: false }) };
    },
  });
  // A client object that wrongly claims to be write-enabled, so the tools get
  // registered; every request still goes through the real read-only client.
  const lying = { ...real, writesEnabled: true };
  const c = await mcp(lying, auditLog);
  for (const dry_run of [true, false]) {
    const r = await c.callTool({ name: 'unifi_rw_update_network', arguments: { network_id: NET, changes: { mdnsForwardingEnabled: true }, dry_run } });
    assert.equal(r.isError, true);
    assert.match(r.content[0].text, /Refused by guard: server is in read-only mode/);
  }
  assert.ok(sent.every((q) => q.method === 'GET'));
  const last = fs.readFileSync(auditLog.file, 'utf8').trim().split('\n').map(JSON.parse).at(-1);
  assert.equal(last.status, 'refused');
  assert.equal(last.method, 'PUT');
});

test('beginShutdown: new writes are refused, reads continue', async () => {
  const sent = [];
  const udm = localClient({ allowWrites: true, transport: async (req) => (sent.push(req), { status: 200, headers: {}, text: '{}' }) });
  const req = { method: 'POST', path: `/integration/v1/sites/${SITE}/clients/${CLIENT}/actions`, body: { action: 'UNAUTHORIZE_GUEST_ACCESS' } };
  await udm.request(req);
  udm.beginShutdown();
  await assert.rejects(udm.request(req), /shutting down/);
  await assert.rejects(udm.request({ ...req, dryRun: true }), /shutting down/);
  await udm.request({ method: 'GET', path: '/integration/v1/info' });
  assert.deepEqual(sent.map((q) => q.method), ['POST', 'GET']);
});

test('allow_writes: config value, env override in both directions, default off', () => {
  const mode = (cfg, envValue) => {
    const env = envValue === undefined ? {} : { UNIFI_ALLOW_WRITES: envValue };
    const c = validateConfig({ console_id: CONSOLE, ...cfg }, { env });
    return [c.allowWrites, c.allowWritesSource, c.warnings.some((w) => /UNIFI_ALLOW_WRITES/.test(w))];
  };
  assert.deepEqual(mode({}), [false, 'default', false]);
  assert.deepEqual(mode({ allow_writes: false }), [false, 'config allow_writes', false]);
  assert.deepEqual(mode({ allow_writes: true }), [true, 'config allow_writes', false]);
  for (const v of ['true', '1', 'TRUE', ' 1 ', 'True']) {
    for (const cfg of [{}, { allow_writes: false }, { allow_writes: true }]) assert.deepEqual(mode(cfg, v), [true, 'env UNIFI_ALLOW_WRITES', false], `${v} ${JSON.stringify(cfg)}`);
  }
  for (const v of ['false', '0', 'FALSE', ' 0']) {
    for (const cfg of [{}, { allow_writes: false }, { allow_writes: true }]) assert.deepEqual(mode(cfg, v), [false, 'env UNIFI_ALLOW_WRITES', false], `${v} ${JSON.stringify(cfg)}`);
  }
  // empty = unset; anything else falls back to the config, with a warning
  assert.deepEqual(mode({ allow_writes: true }, ''), [true, 'config allow_writes', false]);
  assert.deepEqual(mode({ allow_writes: true }, 'yes'), [true, 'config allow_writes', true]);
  assert.deepEqual(mode({}, 'on'), [false, 'default', true]);
  for (const bad of ['true', 1, 'yes', [], {}]) {
    assert.throws(() => validateConfig({ console_id: CONSOLE, allow_writes: bad }, { env: {} }), (e) => e instanceof ConfigError && e.message === 'allow_writes must be true or false', JSON.stringify(bad));
  }
});

test('config: file path keys must be strings; errors name the key', () => {
  for (const key of ['rw_token_file', 'cloud_rw_key_file']) {
    assert.throws(() => validateConfig({ console_id: CONSOLE, [key]: 5 }, { env: {} }), (e) => e instanceof ConfigError && e.message === `${key} must be a file path (string)`);
  }
  assert.throws(() => validateConfig({ backend: 'local', local_host: 'udm.lan', local_rw_key_file: ['x'] }, { env: {} }), /^ConfigError: local_rw_key_file must be a file path/);
  assert.equal(validateConfig({ console_id: CONSOLE, rw_token_file: '' }, { env: {} }).tokenFile.endsWith('mcp-rw-token'), true);
});

test('startup summary: mode and backend, no secrets', () => {
  const cfg = { ...validateConfig({ console_id: CONSOLE, allow_writes: true }, { env: {} }), configPath: '/tmp/my config.json' };
  const line = startupSummary(cfg, { writesEnabled: true, classicCapabilities: ['firewallrule'] });
  assert.match(line, /^version=\d+\.\d+\.\d+ node=v\d+\S* listen=http:\/\/127\.0\.0\.1:18778 public_host=none backend=cloud mode=read-write allow_writes_source="config allow_writes" classic=firewallrule config="\/tmp\/my config\.json" console_id=\S+$/);
  assert.match(startupSummary(cfg, { writesEnabled: false, classicCapabilities: [] }), / mode=read-only .* classic=off /);
});

// ---------------------------------------------------------------------------
// The real server process (main()): loopback only, nothing upstream is contacted.
// ---------------------------------------------------------------------------
const freePort = () =>
  new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });

function writeSecret(file, value) {
  fs.writeFileSync(file, `${value}\n`, { mode: 0o600 });
  fs.chmodSync(file, 0o600);
}

// A failed assertion skips the test's own kill; a live server would keep the runner waiting until the job times out.
const children = new Set();
test.after(() => {
  for (const c of children) if (c.exitCode === null && c.signalCode === null) c.kill('SIGKILL');
});

async function spawnServer(name, cfgExtra, env = {}) {
  const d = path.join(dir, name);
  fs.mkdirSync(d, { mode: 0o700 });
  const token = crypto.randomBytes(32).toString('hex');
  writeSecret(path.join(d, 'token'), token);
  writeSecret(path.join(d, 'key'), API_KEY);
  const port = await freePort();
  const cfg = { console_id: CONSOLE, site_id: SITE, rw_token_file: path.join(d, 'token'), cloud_rw_key_file: path.join(d, 'key'), rw_listen_port: port, ...cfgExtra };
  fs.writeFileSync(path.join(d, 'config.json'), JSON.stringify(cfg));
  const childEnv = { ...process.env, UNIFI_MCP_RW_CONFIG: path.join(d, 'config.json'), UNIFI_MCP_RW_STATE_DIR: path.join(d, 'state'), ...env };
  if (!('UNIFI_ALLOW_WRITES' in env)) delete childEnv.UNIFI_ALLOW_WRITES;
  const child = spawn(process.execPath, [SERVER], { env: childEnv, stdio: ['ignore', 'ignore', 'pipe'] });
  children.add(child);
  let stderr = '';
  child.stderr.on('data', (c) => (stderr += c));
  const exited = new Promise((resolve) => child.on('exit', (code, signal) => resolve({ code, signal })));
  const started = new Promise((resolve) => {
    const check = () => (/started /.test(stderr) ? resolve(true) : null);
    child.stderr.on('data', check);
    exited.then(() => resolve(false));
  });
  return { child, port, token, exited, started, stderr: () => stderr };
}

test('server process: read-only by default, tools/list has read tools only, SIGTERM drains and exits 0', async () => {
  const s = await spawnServer('proc-ro', {});
  assert.equal(await s.started, true, s.stderr());
  assert.match(s.stderr(), /started version=\S+ .*backend=cloud mode=read-only allow_writes_source=default classic=off/);
  assert.match(s.stderr(), /read-only mode: no write tools are registered/);
  assert.ok(!s.stderr().includes(API_KEY) && !s.stderr().includes(s.token));
  const r = await rpc(s.port, s.token, 'tools/list');
  assert.equal(r.status, 200);
  const listed = r.json.result.tools.map((t) => t.name);
  assert.ok(listed.length > 0 && listed.every((n) => READ_TOOLS.includes(n)), listed.join(','));
  assert.ok(!listed.some((n) => WRITE_TOOLS.includes(n)));
  s.child.kill('SIGTERM');
  assert.deepEqual(await s.exited, { code: 0, signal: null });
  assert.match(s.stderr(), /SIGTERM received: refusing new writes, draining/);
  assert.match(s.stderr(), /drained, exiting/);
});

test('server process: UNIFI_ALLOW_WRITES=1 enables writes; env "false" overrides allow_writes: true', async () => {
  const on = await spawnServer('proc-rw', {}, { UNIFI_ALLOW_WRITES: '1' });
  assert.equal(await on.started, true, on.stderr());
  assert.match(on.stderr(), /mode=read-write allow_writes_source="env UNIFI_ALLOW_WRITES"/);
  const listed = (await rpc(on.port, on.token, 'tools/list')).json.result.tools.map((t) => t.name);
  assert.ok(listed.includes('unifi_rw_update_network') && listed.includes('unifi_rw_create_wifi_broadcast'));
  on.child.kill('SIGTERM');
  assert.equal((await on.exited).code, 0);

  const off = await spawnServer('proc-forced-off', { allow_writes: true }, { UNIFI_ALLOW_WRITES: 'false' });
  assert.equal(await off.started, true, off.stderr());
  assert.match(off.stderr(), /mode=read-only allow_writes_source="env UNIFI_ALLOW_WRITES"/);
  off.child.kill('SIGTERM');
  assert.equal((await off.exited).code, 0);
});

test('server process: a config error exits 2 with one line naming the key, no stack trace', async () => {
  const s = await spawnServer('proc-bad', { allow_writes: 'yes' });
  assert.equal(await s.started, false);
  assert.deepEqual(await s.exited, { code: 2, signal: null });
  assert.equal(s.stderr(), 'unifi-mcp-rw: refusing to start: allow_writes must be true or false\n');
});
