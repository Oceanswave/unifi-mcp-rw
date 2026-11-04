'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const tls = require('node:tls');
const { execFileSync } = require('node:child_process');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { InMemoryTransport } = require('@modelcontextprotocol/sdk/inMemory.js');
const { buildMcpServer } = require('../http-server-rw.cjs');
const { createUdmClient, TEST_OVERRIDES, CLOUD_TARGET, UdmHttpError } = require('../lib/udm-client.cjs');
const { createAuditLog } = require('../lib/audit-log.cjs');
const guard = require('../lib/guard.cjs');
const { GuardError, CLASSIC_CAPABILITIES, classicCapabilityOf } = guard;
const { TOOL_NAMES, CLASSIC_TOOLS, CLASSIC_TOOL_CAPABILITY } = require('../lib/tools.cjs');
const { tmpDir } = require('./helpers.cjs');

const CONSOLE = '942A6FF664C0000000000964970E0000000009E710560000000068A9873F:9999999999';
const SITE = '88f7af54-98f8-306a-a1c7-c9349722b1f6';
const CLIENT = '7a2e4c90-1d3b-4f6a-8e25-c4b9d0f13a77';
const API_KEY = 'cloud-site-manager-key-0123456789abcdef';
const CLOUD_BASE = `https://api.ui.com/v1/connector/consoles/${CONSOLE}/proxy/network`;
const INFO = '/integration/v1/info';

let dir;
test.before(() => {
  dir = tmpDir();
});
test.after(() => fs.rmSync(dir, { recursive: true, force: true }));

async function mcpClient(udmClient, auditLog) {
  const server = buildMcpServer({ udmClient, auditLog });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await server.connect(a);
  const client = new Client({ name: 'test', version: '1' });
  await client.connect(b);
  return client;
}

const cloudClient = (extra = {}) => createUdmClient({ backend: 'cloud', consoleId: CONSOLE, apiKey: API_KEY, siteId: SITE, allowWrites: true, ...extra });
const localClient = (extra = {}) =>
  createUdmClient({ backend: 'local', target: { host: 'udm.test', port: 443, isIp: false, hostHeader: 'udm.test' }, apiKey: API_KEY, siteId: SITE, allowWrites: true, ...extra });

// ---------------------------------------------------------------------------
// Tool registration per mode
// ---------------------------------------------------------------------------
test('tools/list: local = all tools; cloud = no classic tools unless cloud_allow_classic', async () => {
  const noSend = async () => {
    throw new Error('must not send');
  };
  const list = async (udm) => (await (await mcpClient(udm)).listTools()).tools.map((t) => t.name).sort();

  assert.deepEqual(await list(localClient({ transport: noSend })), [...TOOL_NAMES].sort());
  const cloud = await list(cloudClient({ transport: noSend }));
  assert.deepEqual(cloud, TOOL_NAMES.filter((n) => !CLASSIC_TOOLS.includes(n)).sort());
  assert.equal(cloud.length, TOOL_NAMES.length - 10);
  for (const n of ['unifi_rw_update_ap_radios', 'unifi_rw_list_legacy_firewall_rules', 'unifi_rw_create_legacy_firewall_rule', 'unifi_rw_update_legacy_firewall_rule', 'unifi_rw_set_fixed_ip', 'unifi_rw_clear_fixed_ip', 'unifi_rw_list_fixed_ips', 'unifi_rw_list_access_points']) {
    assert.ok(!cloud.includes(n), n);
  }
  assert.deepEqual(await list(cloudClient({ allowClassic: true, transport: noSend })), [...TOOL_NAMES].sort());

  // absent tools are not callable
  const c = await mcpClient(cloudClient({ transport: noSend }));
  const r = await c.callTool({ name: 'unifi_rw_set_fixed_ip', arguments: { mac: '11:22:33:44:55:66', fixed_ip: '192.168.1.5', network_id: '5f1e2d3c4b5a69788796a5b4', dry_run: true } }).catch((e) => ({ isError: true, content: [{ text: e.message }] }));
  assert.equal(r.isError, true);
});

// Every subset of the classic capabilities (cloud_allow_classic as an array).
const SUBSETS = [[], ['firewallrule'], ['fixed_ip'], ['radio'], ['firewallrule', 'fixed_ip'], ['firewallrule', 'radio'], ['fixed_ip', 'radio'], ['firewallrule', 'fixed_ip', 'radio']];
const HEX = '5f1e2d3c4b5a69788796a5b4';
// One request per classic allowlist entry, with the capability it belongs to.
const CLASSIC_REQS = [
  [{ method: 'GET', path: '/api/s/default/rest/firewallrule' }, 'firewallrule'],
  [{ method: 'GET', path: `/api/s/default/rest/firewallrule/${HEX}` }, 'firewallrule'],
  [{ method: 'GET', path: '/api/s/default/rest/firewallgroup' }, 'firewallrule'],
  [{ method: 'GET', path: '/api/s/default/rest/networkconf' }, 'firewallrule'],
  [{ method: 'POST', path: '/api/s/default/rest/firewallrule', body: { name: 'r', ruleset: 'LAN_IN', action: 'drop' } }, 'firewallrule'],
  [{ method: 'PUT', path: `/api/s/default/rest/firewallrule/${HEX}`, body: { name: 'r', ruleset: 'LAN_IN', action: 'drop' }, context: { existing: { _id: HEX, name: 'q', ruleset: 'LAN_IN', action: 'drop' } } }, 'firewallrule'],
  [{ method: 'GET', path: '/api/s/default/rest/user' }, 'fixed_ip'],
  [{ method: 'POST', path: '/api/s/default/rest/user', body: { mac: 'aa:bb:cc:dd:ee:ff', use_fixedip: false } }, 'fixed_ip'],
  [{ method: 'PUT', path: `/api/s/default/rest/user/${HEX}`, body: { use_fixedip: false } }, 'fixed_ip'],
  [{ method: 'GET', path: '/api/s/default/stat/device' }, 'radio'],
  [{ method: 'GET', path: '/api/s/default/stat/device/aa:bb:cc:dd:ee:ff' }, 'radio'],
  [{ method: 'PUT', path: `/api/s/default/rest/device/${HEX}`, body: { radio_table: [{ radio: 'ng', channel: 1 }] }, context: { existing: { _id: HEX, type: 'uap', radio_table: [{ radio: 'ng' }] } } }, 'radio'],
];

test('every classic allowlist entry maps to exactly one capability (and the request list covers them all)', () => {
  const classicRules = guard._ALLOW.filter((a) => a.re.source.includes('\\/api\\/s\\/') || a.re.source.startsWith('^/api/s/'));
  assert.ok(classicRules.length >= 9);
  for (const rule of classicRules) {
    const hits = CLASSIC_REQS.filter(([req]) => req.method === rule.method && rule.re.test(req.path));
    assert.ok(hits.length >= 1, `no sample request for ${rule.name}`);
    for (const [req, cap] of hits) assert.equal(classicCapabilityOf(req.path), cap, req.path);
  }
  for (const [req] of CLASSIC_REQS) assert.equal(checkRequestOk(req), true, `${req.method} ${req.path}`);
  for (const p of ['/api/s/default/rest/portforward', '/api/s/default/stat/sta', '/api/s/default/rest/firewallrules', '/api/s/default/rest/networkconfs', '/api/s/default/rest/usergroup', '/integration/v1/info', '/api/s/default/cmd/devmgr']) {
    assert.equal(classicCapabilityOf(p), null, p);
  }
  assert.equal(classicCapabilityOf('/api/s/default/stat/device?x=1'), 'radio');
});
function checkRequestOk(req) {
  return guard.checkRequest(req).ok;
}

test('tools/list in cloud mode registers exactly the enabled capabilities\' tools; local registers all', async () => {
  const noSend = async () => {
    throw new Error('must not send');
  };
  const list = async (udm) => (await (await mcpClient(udm)).listTools()).tools.map((t) => t.name).sort();
  assert.deepEqual(Object.values(CLASSIC_TOOL_CAPABILITY).sort(), ['firewallrule', 'firewallrule', 'firewallrule', 'firewallrule', 'firewallrule', 'fixed_ip', 'fixed_ip', 'fixed_ip', 'radio', 'radio']);
  for (const caps of SUBSETS) {
    const udm = cloudClient({ allowClassic: caps, transport: noSend });
    assert.deepEqual([...udm.classicCapabilities], caps);
    const expected = TOOL_NAMES.filter((n) => !CLASSIC_TOOL_CAPABILITY[n] || caps.includes(CLASSIC_TOOL_CAPABILITY[n])).sort();
    assert.deepEqual(await list(udm), expected, JSON.stringify(caps));
  }
  const fw = await list(cloudClient({ allowClassic: ['firewallrule'], transport: noSend }));
  for (const n of ['unifi_rw_list_legacy_firewall_rules', 'unifi_rw_list_firewall_groups', 'unifi_rw_list_classic_networks', 'unifi_rw_create_legacy_firewall_rule', 'unifi_rw_update_legacy_firewall_rule']) assert.ok(fw.includes(n), n);
  for (const n of ['unifi_rw_set_fixed_ip', 'unifi_rw_clear_fixed_ip', 'unifi_rw_list_fixed_ips', 'unifi_rw_list_access_points', 'unifi_rw_update_ap_radios']) assert.ok(!fw.includes(n), n);
  assert.deepEqual(await list(cloudClient({ allowClassic: false, transport: noSend })), await list(cloudClient({ transport: noSend })));
  const local = localClient({ allowClassic: false, transport: noSend });
  assert.deepEqual([...local.classicCapabilities], CLASSIC_CAPABILITIES);
  assert.deepEqual(await list(local), [...TOOL_NAMES].sort());
});

test('cloud client: classic paths refused per capability before any socket; enabled capabilities are sent', async () => {
  for (const caps of SUBSETS) {
    const sent = [];
    const udm = cloudClient({ allowClassic: caps, transport: async (req) => (sent.push(req), { status: 200, headers: {}, text: '{"meta":{"rc":"ok"},"data":[]}' }) });
    for (const [req, cap] of CLASSIC_REQS) {
      const before = sent.length;
      if (caps.includes(cap)) {
        await udm.request(req);
        assert.equal(sent.length, before + 1, `${JSON.stringify(caps)} ${req.method} ${req.path}`);
        assert.equal(sent.at(-1).path, `/v1/connector/consoles/${CONSOLE}/proxy/network${req.path}`);
      } else {
        await assert.rejects(udm.request(req), (e) => e instanceof GuardError && e.message.includes(`capability "${cap}" is not enabled`));
        await assert.rejects(udm.request({ ...req, dryRun: true }), GuardError);
        assert.equal(sent.length, before, `${JSON.stringify(caps)} ${req.method} ${req.path} must not be sent`);
      }
    }
  }
});

test('cloud client: a guard-allowed classic path that maps to no capability is refused even with all capabilities (fail closed)', async () => {
  const sent = [];
  const extra = { method: 'GET', re: /^\/api\/s\/default\/stat\/health$/, name: 'test_only_unmapped' };
  guard._ALLOW.push(extra);
  try {
    const udm = cloudClient({ allowClassic: true, transport: async (req) => (sent.push(req), { status: 200, headers: {}, text: '{}' }) });
    await assert.rejects(udm.request({ method: 'GET', path: '/api/s/default/stat/health' }), /maps to no classic capability/);
    // local mode is unchanged (guard decides)
    const local = localClient({ transport: async (req) => (sent.push(req), { status: 200, headers: {}, text: '{}' }) });
    await local.request({ method: 'GET', path: '/api/s/default/stat/health' });
    assert.equal(sent.length, 1);
  } finally {
    guard._ALLOW.splice(guard._ALLOW.indexOf(extra), 1);
  }
});

test('createUdmClient: invalid allowClassic values are refused', () => {
  for (const bad of ['yes', 1, {}, ['radio', 'radio'], ['bogus'], [1]]) {
    assert.throws(() => cloudClient({ allowClassic: bad, transport: async () => ({}) }), /allowClassic/, JSON.stringify(bad));
  }
});

// ---------------------------------------------------------------------------
// Dry run / classic refusal (no network)
// ---------------------------------------------------------------------------
test('cloud dry_run through MCP shows the full api.ui.com URL, redacts the key, sends nothing; log has canonical endpoint + backend', async () => {
  const sent = [];
  const auditLog = createAuditLog({ stateDir: path.join(dir, 'state-dry') });
  const udm = cloudClient({ auditLog, transport: async (req) => sent.push(req) });
  const c = await mcpClient(udm, auditLog);
  const r = await c.callTool({ name: 'unifi_rw_authorize_guest', arguments: { client_id: CLIENT, timeLimitMinutes: 30, dry_run: true } });
  assert.ok(!r.isError, r.content[0].text);
  const out = JSON.parse(r.content[0].text);
  assert.equal(out.dry_run, true);
  assert.equal(out.backend, 'cloud');
  assert.equal(out.request.method, 'POST');
  assert.equal(out.request.url, `${CLOUD_BASE}/integration/v1/sites/${SITE}/clients/${CLIENT}/actions`);
  assert.equal(out.request.headers['X-API-KEY'], '[REDACTED]');
  assert.deepEqual(out.request.body, { action: 'AUTHORIZE_GUEST_ACCESS', timeLimitMinutes: 30 });
  assert.ok(!JSON.stringify(r).includes(API_KEY));
  assert.equal(sent.length, 0);

  const logText = fs.readFileSync(auditLog.file, 'utf8');
  assert.ok(!logText.includes(API_KEY));
  const last = JSON.parse(logText.trim().split('\n').at(-1));
  assert.equal(last.backend, 'cloud');
  assert.equal(last.status, 'dry_run');
  assert.equal(last.endpoint, `/integration/v1/sites/${SITE}/clients/${CLIENT}/actions`);
});

test('cloud client refuses classic paths unless allowClassic (second check, before any send), and is logged as refused', async () => {
  const sent = [];
  const auditLog = createAuditLog({ stateDir: path.join(dir, 'state-classic') });
  const udm = cloudClient({ auditLog, transport: async (req) => (sent.push(req), { status: 200, headers: {}, text: '{"data":[]}' }) });
  assert.equal(udm.classicEnabled, false);
  await assert.rejects(udm.request({ method: 'GET', path: '/api/s/default/rest/user' }), (e) => e instanceof GuardError && /classic/.test(e.message));
  await assert.rejects(
    udm.request({ method: 'PUT', path: '/api/s/default/rest/user/5f1e2d3c4b5a69788796a5b4', body: { use_fixedip: false }, audit: { tool: 't', args: {} } }),
    /classic/
  );
  assert.equal(sent.length, 0);
  const last = JSON.parse(fs.readFileSync(auditLog.file, 'utf8').trim().split('\n').at(-1));
  assert.equal(last.status, 'refused');
  assert.equal(last.backend, 'cloud');
  assert.equal(last.endpoint, '/api/s/default/rest/user/5f1e2d3c4b5a69788796a5b4');

  const withClassic = cloudClient({ allowClassic: true, transport: async (req) => (sent.push(req), { status: 200, headers: {}, text: '{"data":[]}' }) });
  await withClassic.request({ method: 'GET', path: '/api/s/default/rest/user' });
  assert.equal(sent.at(-1).path, `/v1/connector/consoles/${CONSOLE}/proxy/network/api/s/default/rest/user`);
});

test('cloud client: host/TLS options cannot be supplied; prefix and target are fixed', () => {
  const udm = cloudClient({
    transport: async () => ({}),
    target: { host: '127.0.0.1', port: 1, isIp: true, hostHeader: '127.0.0.1:1' },
    tls: { mode: 'pin', pin: 'ab'.repeat(32) },
  });
  assert.equal(udm.target, CLOUD_TARGET);
  assert.deepEqual({ ...CLOUD_TARGET }, { host: 'api.ui.com', port: 443, isIp: false, hostHeader: 'api.ui.com' });
  assert.ok(Object.isFrozen(CLOUD_TARGET));
  assert.equal(udm.origin, 'https://api.ui.com');
  assert.equal(udm.prefix, `/v1/connector/consoles/${CONSOLE}/proxy/network`);
  for (const id of ['abc/defgh123', '../../x/abc', 'abcdefgh?x', 'abcdefgh%2f', undefined]) {
    assert.throws(() => cloudClient({ consoleId: id, transport: async () => ({}) }), /consoleId/);
  }
  assert.throws(() => createUdmClient({ apiKey: API_KEY, consoleId: CONSOLE }), /backend must be/);
});

test('test-only override is unreachable from configuration', () => {
  assert.equal(typeof TEST_OVERRIDES, 'symbol');
  // JSON cannot produce symbol keys, so a config file can never set it.
  const parsed = JSON.parse(`{"${String(TEST_OVERRIDES)}": {"connect": 1}, "connect": 1}`);
  assert.deepEqual(Object.getOwnPropertySymbols(parsed), []);
  // Production code never references the override or the transport sink.
  const main = fs.readFileSync(path.join(__dirname, '..', 'http-server-rw.cjs'), 'utf8');
  assert.doesNotMatch(main, /TEST_OVERRIDES|transport:\s*[a-z]/);
  const config = fs.readFileSync(path.join(__dirname, '..', 'lib', 'config.cjs'), 'utf8');
  assert.doesNotMatch(config, /TEST_OVERRIDES|connect\b/);
});

// ---------------------------------------------------------------------------
// Fake api.ui.com over TLS (self-signed). Reached only through the injected
// connect override, which redirects the socket to 127.0.0.1 and supplies the
// throwaway CA; everything the client itself chose (host, port, servername,
// verification) is recorded and asserted.
// ---------------------------------------------------------------------------
function haveOpenssl() {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}
const skip = haveOpenssl() ? false : 'openssl CLI not available';

function makeCert(name, san) {
  const key = path.join(dir, `${name}-key.pem`);
  const cert = path.join(dir, `${name}-cert.pem`);
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
    '-keyout', key, '-out', cert, '-days', '1', '-subj', `/CN=${name}`, '-addext', `subjectAltName=${san}`,
  ], { stdio: 'ignore' });
  return { key: fs.readFileSync(key), cert: fs.readFileSync(cert, 'utf8') };
}

function startFake(creds) {
  const state = { connections: [], tcp: [], next: { status: 200, headers: {}, body: '{"applicationVersion":"10.6.106"}' } };
  const server = tls.createServer(creds, (sock) => {
    const conn = { data: '' };
    conn.closed = new Promise((resolve) => sock.on('close', resolve));
    state.connections.push(conn);
    sock.on('data', (d) => {
      conn.data += d.toString('latin1');
      const end = conn.data.indexOf('\r\n\r\n');
      if (end === -1) return;
      const m = /\r\ncontent-length: (\d+)/i.exec(conn.data.slice(0, end));
      if (m && conn.data.length < end + 4 + Number(m[1])) return;
      const { status, headers, body } = state.next;
      const extra = Object.entries(headers).map(([k, v]) => `${k}: ${v}\r\n`).join('');
      sock.end(`HTTP/1.1 ${status} X\r\nContent-Type: application/json\r\n${extra}Content-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`);
    });
    sock.on('error', () => {});
  });
  server.on('connection', (raw) => state.tcp.push(new Promise((resolve) => raw.on('close', resolve))));
  server.on('tlsClientError', () => {});
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, state, port: server.address().port })));
}

let good, wrongName, goodCa, wrongCa;

test.before(async () => {
  if (skip) return;
  const g = makeCert('api.ui.com', 'DNS:api.ui.com');
  const w = makeCert('localhost', 'DNS:localhost,IP:127.0.0.1');
  goodCa = g.cert;
  wrongCa = w.cert;
  good = await startFake(g);
  wrongName = await startFake(w);
});

test.after(() => {
  for (const f of [good, wrongName]) if (f) f.server.close();
});

/** Injected tls.connect: records the client's own options, then redirects to the fake server. */
function redirect(fake, ca, seen) {
  return (opts) => {
    seen.push({ ...opts });
    const o = { ...opts, host: '127.0.0.1', port: fake.port };
    if (ca) o.ca = ca;
    return tls.connect(o);
  };
}

async function settle(fake) {
  await Promise.all(fake.state.tcp);
  await Promise.all(fake.state.connections.map((c) => c.closed));
}

function reset(fake) {
  fake.state.connections.length = 0;
  fake.state.tcp.length = 0;
}

test('cloud TLS: connects only to api.ui.com:443 with servername api.ui.com and full verification; key sent after verification', { skip }, async () => {
  reset(good);
  const seen = [];
  const udm = cloudClient({ [TEST_OVERRIDES]: { connect: redirect(good, goodCa, seen) } });
  const res = await udm.request({ method: 'GET', path: INFO });
  assert.deepEqual(res, { applicationVersion: '10.6.106' });
  await settle(good);
  assert.equal(seen.length, 1);
  assert.deepEqual(seen[0], { host: 'api.ui.com', port: 443, servername: 'api.ui.com', rejectUnauthorized: true });
  assert.equal(good.state.connections.length, 1);
  const data = good.state.connections[0].data;
  assert.ok(data.startsWith(`GET /v1/connector/consoles/${CONSOLE}/proxy/network/integration/v1/info HTTP/1.1\r\n`), data.split('\r\n')[0]);
  assert.match(data, /\r\nhost: api\.ui\.com\r\n/i);
  assert.match(data, new RegExp(`\\r\\nx-api-key: ${API_KEY}\\r\\n`, 'i'));
});

test('cloud TLS: writes go to the same fixed host; every connect is api.ui.com:443', { skip }, async () => {
  reset(good);
  const seen = [];
  const udm = cloudClient({ [TEST_OVERRIDES]: { connect: redirect(good, goodCa, seen) } });
  good.state.next = { status: 200, headers: {}, body: '{}' };
  await udm.request({ method: 'POST', path: `/integration/v1/sites/${SITE}/clients/${CLIENT}/actions`, body: { action: 'UNAUTHORIZE_GUEST_ACCESS' } });
  await udm.request({ method: 'GET', path: `/integration/v1/sites/${SITE}/clients?limit=1` });
  await settle(good);
  assert.equal(seen.length, 2);
  for (const o of seen) assert.deepEqual(o, { host: 'api.ui.com', port: 443, servername: 'api.ui.com', rejectUnauthorized: true });
  assert.ok(good.state.connections[0].data.startsWith(`POST /v1/connector/consoles/${CONSOLE}/proxy/network/integration/v1/sites/${SITE}/clients/${CLIENT}/actions HTTP/1.1\r\n`));
  assert.ok(good.state.connections[0].data.endsWith('{"action":"UNAUTHORIZE_GUEST_ACCESS"}'));
});

test('cloud TLS: untrusted certificate (system CA) -> fails before any byte is written', { skip }, async () => {
  reset(good);
  const udm = cloudClient({ [TEST_OVERRIDES]: { connect: redirect(good, null, []) } });
  await assert.rejects(udm.request({ method: 'GET', path: INFO }), /TLS|certificate|self.signed/i);
  await settle(good);
  for (const c of good.state.connections) assert.equal(c.data, '');
});

test('cloud TLS: trusted cert for the wrong name -> refused (hostname checked against api.ui.com), nothing sent', { skip }, async () => {
  reset(wrongName);
  const udm = cloudClient({ [TEST_OVERRIDES]: { connect: redirect(wrongName, wrongCa, []) } });
  await assert.rejects(udm.request({ method: 'GET', path: INFO }), /altnames|api\.ui\.com|Hostname/i);
  await settle(wrongName);
  for (const c of wrongName.state.connections) assert.equal(c.data, '');
});

test('cloud connector error statuses map to fixed tool errors without upstream text', { skip }, async () => {
  const auditLog = createAuditLog({ stateDir: path.join(dir, 'state-errors'), secrets: [API_KEY] });
  const udm = cloudClient({ auditLog, [TEST_OVERRIDES]: { connect: redirect(good, goodCa, []) } });
  const cases = [
    [401, {}, '{"code":"unauthorized","message":"Unauthorized"}', /^Cloud connector: Site Manager API key rejected \(401\).* \[code unauthorized\]$/, 'unauthorized'],
    [403, {}, '{"message":"Forbidden"}', /^Cloud connector: Site Manager API key cannot access this console \(403\)[^[]*$/],
    [404, {}, '{"code":"device_offline","message":"device is offline"}', /^Cloud connector: console is offline \(404 device_offline\) \[code device_offline\]$/, 'device_offline'],
    [404, {}, '{"message":"device_offline"}', /^Cloud connector: not found \(404\): console_id unknown/],
    [408, {}, '{"message":"timeout"}', /25 s limit \(408\)$/],
    [429, { 'Retry-After': '17' }, '{"message":"rate limit"}', /rate limited.*\(429; 100 requests\/min per console\); Retry-After: 17$/],
    [429, { 'Retry-After': '<script>' }, '{}', /per console\)$/],
    [502, {}, 'bad gateway body', /\(502 bad gateway\)$/],
    [500, {}, `{"message":"boom ${API_KEY}"}`, /^Cloud connector: internal server error \(500\)$/],
  ];
  for (const [status, headers, body, re, code] of cases) {
    good.state.next = { status, headers, body };
    await assert.rejects(udm.request({ method: 'GET', path: INFO }), (e) => {
      assert.ok(e instanceof UdmHttpError, String(e));
      assert.equal(e.status, status);
      assert.match(e.message, re);
      assert.equal(e.code, code);
      assert.doesNotMatch(e.message, /Unauthorized|Forbidden|device is offline|timeout"|boom|body/);
      assert.ok(!e.message.includes(API_KEY));
      assert.deepEqual(Object.keys(e.toJSON()), code ? ['status', 'code', 'message'] : ['status', 'message']);
      if (status === 429 && headers['Retry-After'] === '17') assert.equal(e.retryAfter, '17');
      return true;
    });
  }
  // through MCP: isError with the structured error; write attempt logged with status, no key
  good.state.next = { status: 429, headers: { 'Retry-After': '5' }, body: `{"message":"slow down ${API_KEY}"}` };
  const c = await mcpClient(udm, auditLog);
  const r = await c.callTool({ name: 'unifi_rw_unauthorize_guest', arguments: { client_id: CLIENT } });
  assert.equal(r.isError, true);
  const out = JSON.parse(r.content[0].text);
  assert.equal(out.status, 429);
  assert.match(out.message, /rate limited.*Retry-After: 5/);
  assert.ok(!r.content[0].text.includes(API_KEY) && !r.content[0].text.includes('slow down'));
  const logText = fs.readFileSync(auditLog.file, 'utf8');
  assert.ok(!logText.includes(API_KEY));
  const last = JSON.parse(logText.trim().split('\n').at(-1));
  assert.equal(last.status, 429);
  assert.equal(last.backend, 'cloud');
  assert.equal(last.endpoint, `/integration/v1/sites/${SITE}/clients/${CLIENT}/actions`);
  good.state.next = { status: 200, headers: {}, body: '{}' };
});
