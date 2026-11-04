'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { InMemoryTransport } = require('@modelcontextprotocol/sdk/inMemory.js');
const { buildMcpServer } = require('../http-server-rw.cjs');
const { createUdmClient } = require('../lib/udm-client.cjs');
const { checkRequest, GuardError } = require('../lib/guard.cjs');
const { tmpDir } = require('./helpers.cjs');

const API_KEY = 'review-api-key-0123456789abcdef';
const TOKEN = 'review-bearer-token-0123456789abcdef';
const SITE = 'aaaaaaaa-0000-4000-8000-000000000001';
const localClient = (extra = {}) => createUdmClient({
  backend: 'local', target: { host: 'udm.test', port: 443, hostHeader: 'udm.test' },
  apiKey: API_KEY, siteId: SITE, allowWrites: true, ...extra,
});

test('legacy rule field allowlist refuses inherited Object.prototype names', () => {
  for (const field of ['toString', 'valueOf', 'hasOwnProperty', '__defineGetter__']) {
    assert.throws(() => checkRequest({
      method: 'POST', path: '/api/s/default/rest/firewallrule',
      body: { ruleset: 'LAN_IN', action: 'drop', [field]: 'unexpected' },
    }), (e) => e instanceof GuardError && /is not allowed/.test(e.message), field);
  }
});

test('fixed-IP tools refuse malformed client lists before creating or updating a record', async () => {
  let response;
  const sent = [];
  const entries = [];
  const auditLog = { write: (entry) => entries.push(entry) };
  const udm = localClient({ auditLog, transport: async (req) => {
    sent.push(req);
    return { status: 200, text: JSON.stringify(response) };
  } });
  const server = buildMcpServer({ udmClient: udm, auditLog });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await server.connect(a);
  const client = new Client({ name: 'review-test', version: '1' });
  await client.connect(b);
  try {
    for (response of [null, {}, { data: null }, { data: {} }, { data: [null] }, { data: [{}] }]) {
      for (const dry_run of [true, false]) {
        for (const name of ['unifi_rw_set_fixed_ip', 'unifi_rw_clear_fixed_ip']) {
          const args = { mac: 'aa:bb:cc:dd:ee:ff', dry_run };
          if (name === 'unifi_rw_set_fixed_ip') Object.assign(args, { fixed_ip: '192.168.1.50', network_id: 'a'.repeat(24) });
          const result = await client.callTool({ name, arguments: args });
          assert.equal(result.isError, true);
          assert.match(result.content[0].text, /client list could not be determined/);
          assert.equal(entries.at(-1).status, 'refused');
        }
      }
    }
    assert.ok(sent.every((req) => req.method === 'GET'));
  } finally {
    await client.close();
    await server.close();
  }
});

test('shutdown waits for upstream writes and their audit entries after the caller disconnects', async () => {
  for (const fail of [false, true]) {
    let release;
    const entries = [];
    const udm = localClient({
      auditLog: { write: (entry) => entries.push(entry) },
      transport: () => new Promise((resolve, reject) => { release = () => fail ? reject(new Error('upstream failed')) : resolve({ status: 200, text: '{}' }); }),
    });
    const pending = udm.request({
      method: 'POST', path: `/integration/v1/sites/${SITE}/clients/${SITE}/actions`,
      body: { action: 'UNAUTHORIZE_GUEST_ACCESS' }, audit: { tool: 'test', args: {} },
    });
    const result = pending.catch((e) => e);
    let drained = false;
    const drain = Promise.resolve(udm.beginShutdown()).then(() => { drained = true; });
    await Promise.resolve();
    assert.equal(drained, false);
    assert.equal(entries.length, 0);
    release();
    await drain;
    await result;
    assert.equal(entries.length, 1);
    assert.equal(entries[0].status, fail ? 'error' : 200);
  }
});

test('audit failure warnings never echo exception text containing credentials', async (t) => {
  let output = '';
  t.mock.method(process.stderr, 'write', (text) => { output += text; return true; });
  const udm = localClient({
    auditLog: { write: () => { throw new Error(`${API_KEY} ${TOKEN}`); } },
    transport: async () => ({ status: 200, text: '{}' }),
  });
  await udm.request({
    method: 'POST', path: `/integration/v1/sites/${SITE}/clients/${SITE}/actions`,
    body: { action: 'UNAUTHORIZE_GUEST_ACCESS' }, audit: { tool: 'test', args: {} },
  });
  assert.match(output, /audit log write failed/);
  assert.ok(!output.includes(API_KEY) && !output.includes(TOKEN));
});

test('startup failures scrub secrets from filesystem error paths', async () => {
  const dir = tmpDir();
  try {
    const config = require('../lib/config.cjs');
    const cfg = config.validateConfig({ backend: 'local', local_host: 'udm.test', local_tls_ca_file: path.join(dir, `${API_KEY}-${TOKEN}`) }, { env: {} });
    const filename = path.join(__dirname, '..', 'http-server-rw.cjs');
    const runtimeRequire = createRequire(filename);
    const module = { exports: {} };
    const fixtureRequire = (id) => id === './lib/config.cjs'
      ? { ...config, loadConfig: () => cfg, loadSecrets: () => ({ token: TOKEN, apiKey: API_KEY }) }
      : runtimeRequire(id);
    fixtureRequire.main = module;
    let output = '', exitCode;
    // Run startup with fixture secrets; the missing CA fails before any socket opens.
    await new Promise((resolve) => vm.runInNewContext(fs.readFileSync(filename, 'utf8'), {
      require: fixtureRequire, module,
      process: { on() {}, stderr: { write: (text) => { output += text; } }, exit: (code) => { exitCode = code; resolve(); } },
    }, { filename }));
    assert.equal(exitCode, 1);
    assert.match(output, /fatal:.*ENOENT/);
    assert.ok(!output.includes(API_KEY) && !output.includes(TOKEN));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('startup installs signal handlers before started; shutdown waits after HTTP connections close', { timeout: 1000 }, async () => {
  const config = require('../lib/config.cjs');
  const cfg = config.validateConfig({ console_id: 'testconsole123', allow_writes: true }, { env: {} });
  const filename = path.join(__dirname, '..', 'http-server-rw.cjs');
  const runtimeRequire = createRequire(filename);
  const module = { exports: {} };
  let releaseWrite, markStarted, markExited, handlersReady = false, stopping = false;
  const pending = new Promise((resolve) => { releaseWrite = resolve; });
  const started = new Promise((resolve) => { markStarted = resolve; });
  const exited = new Promise((resolve) => { markExited = resolve; });
  const handlers = new Map(), exits = [];
  const server = {
    on() {}, once() {}, removeListener() {}, listen(port, host, cb) { cb(); },
    close(cb) { cb(); }, closeIdleConnections() {}, closeAllConnections() {},
  };
  const fixtureRequire = (id) => {
    if (id === 'node:http') return { createServer: () => server };
    if (id === './lib/config.cjs') return { ...config, loadConfig: () => cfg, loadSecrets: () => ({ token: TOKEN, apiKey: API_KEY }) };
    if (id === './lib/udm-client.cjs') return { createUdmClient: () => ({
      writesEnabled: true, classicCapabilities: [], beginShutdown() { stopping = true; return pending; },
    }) };
    return runtimeRequire(id);
  };
  fixtureRequire.main = module;
  vm.runInNewContext(fs.readFileSync(filename, 'utf8'), {
    require: fixtureRequire, module, setTimeout: () => ({ unref() {} }),
    process: {
      version: process.version, on: (sig, fn) => handlers.set(sig, fn), exit: (code) => { exits.push(code); markExited(); },
      stderr: { write: (text) => {
        if (text.includes('started ')) {
          handlersReady = handlers.has('SIGTERM') && handlers.has('SIGINT');
          markStarted();
        }
      } },
    },
  }, { filename });
  await started;
  assert.equal(handlersReady, true);
  handlers.get('SIGTERM')();
  await Promise.resolve();
  assert.equal(stopping, true);
  assert.deepEqual(exits, []);
  releaseWrite();
  await exited;
  assert.deepEqual(exits, [0]);
});
