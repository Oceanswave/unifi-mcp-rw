'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const net = require('node:net');
const crypto = require('node:crypto');
const { startServer } = require('../http-server-rw.cjs');
const { readSecretFile } = require('../lib/config.cjs');
const { createUdmClient } = require('../lib/udm-client.cjs');
const { createAuditLog } = require('../lib/audit-log.cjs');
const { TOOL_NAMES } = require('../lib/tools.cjs');
const { tmpDir, rawRequest, rpc } = require('./helpers.cjs');

const SITE = '88f7af54-98f8-306a-a1c7-c9349722b1f6';
const CLIENT = '7a2e4c90-1d3b-4f6a-8e25-c4b9d0f13a77';
const EXPECTED_TOOLS = [
  'unifi_rw_authorize_guest',
  'unifi_rw_clear_fixed_ip',
  'unifi_rw_create_firewall_policy',
  'unifi_rw_create_legacy_firewall_rule',
  'unifi_rw_create_wifi_broadcast',
  'unifi_rw_get_client',
  'unifi_rw_get_firewall_policy',
  'unifi_rw_get_info',
  'unifi_rw_get_network',
  'unifi_rw_get_wifi_broadcast',
  'unifi_rw_list_access_points',
  'unifi_rw_list_classic_networks',
  'unifi_rw_list_clients',
  'unifi_rw_list_firewall_groups',
  'unifi_rw_list_firewall_policies',
  'unifi_rw_list_firewall_zones',
  'unifi_rw_list_fixed_ips',
  'unifi_rw_list_legacy_firewall_rules',
  'unifi_rw_list_networks',
  'unifi_rw_list_sites',
  'unifi_rw_list_wifi_broadcasts',
  'unifi_rw_patch_firewall_policy',
  'unifi_rw_set_fixed_ip',
  'unifi_rw_unauthorize_guest',
  'unifi_rw_update_ap_radios',
  'unifi_rw_update_firewall_policy',
  'unifi_rw_update_legacy_firewall_rule',
  'unifi_rw_update_network',
  'unifi_rw_update_wifi_broadcast',
];

let server, port, token, dir, sent, auditLog;

test.before(async () => {
  dir = tmpDir();
  const tokenFile = path.join(dir, 'mcp-rw-token');
  fs.writeFileSync(tokenFile, crypto.randomBytes(32).toString('hex') + '\n', { mode: 0o600 });
  token = readSecretFile(tokenFile, { minLength: 32 });
  sent = [];
  auditLog = createAuditLog({ stateDir: path.join(dir, 'state') });
  const udmClient = createUdmClient({
    backend: 'local',
    target: { host: '127.0.0.1', port: 1, isIp: true, hostHeader: '127.0.0.1:1' },
    apiKey: 'fake-api-key-should-never-leak-0123456789',
    siteId: SITE,
    allowWrites: true,
    auditLog,
    transport: async (req) => {
      sent.push(req);
      throw new Error('transport must not be used in these tests');
    },
  });
  // Ephemeral port: the injected host allowlist array is filled in once the port is known.
  const allowedHosts = [];
  const allowedOrigins = [];
  server = await startServer({ port: 0, token, udmClient, auditLog, allowedHosts, allowedOrigins });
  port = server.address().port;
  allowedHosts.push(`127.0.0.1:${port}`, `localhost:${port}`);
  allowedOrigins.push(`http://127.0.0.1:${port}`);
});

test.after(() => {
  server.close();
  server.closeAllConnections();
  fs.rmSync(dir, { recursive: true, force: true });
});

const H = () => ({ host: `127.0.0.1:${port}`, authorization: `Bearer ${token}`, 'content-type': 'application/json', accept: 'application/json, text/event-stream' });
const INIT = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 't', version: '1' } } });

test('refuses to bind non-loopback', async () => {
  await assert.rejects(() => startServer({ host: '0.0.0.0', port: 0, token: 'x'.repeat(40), udmClient: {} }), /non-loopback/);
});

test('403 on bad or missing Host', async () => {
  for (const host of ['evil.com', `mcp-host.example.ts.net.evil.com`, `127.0.0.1:${port + 1}`]) {
    const r = await rawRequest({ port, headers: { ...H(), host }, body: INIT });
    assert.equal(r.status, 403, host);
    assert.deepEqual(r.json, { error: 'Forbidden' });
  }
  // Missing Host: HTTP/1.0 request over a raw socket (Node's server rejects host-less HTTP/1.1 itself).
  const raw = await new Promise((resolve, reject) => {
    const s = net.connect(port, '127.0.0.1', () => {
      s.end(`POST /mcp HTTP/1.0\r\nAuthorization: Bearer ${token}\r\nContent-Type: application/json\r\nContent-Length: ${INIT.length}\r\n\r\n${INIT}`);
    });
    let buf = '';
    s.on('data', (d) => (buf += d));
    s.on('end', () => resolve(buf));
    s.on('error', reject);
  });
  assert.match(raw, /^HTTP\/1\.[01] 403 /);
});

test('403 on bad Origin', async () => {
  const r = await rawRequest({ port, headers: { ...H(), origin: 'https://evil.example' }, body: INIT });
  assert.equal(r.status, 403);
});

test('401 on missing / wrong token', async () => {
  const h = H();
  delete h.authorization;
  let r = await rawRequest({ port, headers: h, body: INIT });
  assert.equal(r.status, 401);
  assert.deepEqual(r.json, { error: 'Authentication required' });
  r = await rawRequest({ port, headers: { ...H(), authorization: `Bearer ${token.slice(0, -1)}${token.endsWith('0') ? '1' : '0'}` }, body: INIT });
  assert.equal(r.status, 401);
  assert.ok(!r.text.includes(token));
});

test('404 / 405 / 415 / 400', async () => {
  let r = await rawRequest({ port, path: '/other', headers: H(), body: INIT });
  assert.equal(r.status, 404);
  r = await rawRequest({ port, method: 'GET', headers: H() });
  assert.equal(r.status, 405);
  assert.equal(r.headers.allow, 'POST');
  r = await rawRequest({ port, method: 'DELETE', headers: H() });
  assert.equal(r.status, 405);
  r = await rawRequest({ port, headers: { ...H(), 'content-type': 'text/plain' }, body: INIT });
  assert.equal(r.status, 415);
  r = await rawRequest({ port, headers: H(), body: '{not json' });
  assert.equal(r.status, 400);
  assert.deepEqual(r.json, { error: 'Invalid JSON' });
});

test('413 on oversize body (Content-Length and streamed)', async () => {
  const big = JSON.stringify({ x: 'a'.repeat(300 * 1024) });
  let r = await rawRequest({ port, headers: { ...H(), 'content-length': Buffer.byteLength(big) }, body: big });
  assert.equal(r.status, 413);

  // chunked (no Content-Length): cap enforced while streaming
  const status = await new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method: 'POST', path: '/mcp', headers: { ...H(), 'transfer-encoding': 'chunked' }, agent: false }, (res) => {
      res.resume();
      resolve(res.statusCode);
    });
    req.on('error', (e) => (e.code === 'ECONNRESET' || e.code === 'EPIPE' ? null : reject(e)));
    const chunk = 'a'.repeat(64 * 1024);
    let n = 0;
    (function pump() {
      while (n < 8) {
        n++;
        if (!req.write(chunk)) return req.once('drain', pump);
      }
      req.end();
    })();
  });
  assert.equal(status, 413);
});

test('initialize + tools/list with correct token; exact tool set', async () => {
  for (const p of ['/mcp', '/unifi-mcp-rw', '/unifi-mcp-rw/', '/mcp?x=1']) {
    const r = await rawRequest({ port, path: p, headers: H(), body: INIT });
    assert.equal(r.status, 200, p);
    assert.equal(r.json.result.serverInfo.name, 'unifi-mcp-rw');
  }
  const r = await rpc(port, token, 'tools/list');
  assert.equal(r.status, 200);
  const names = r.json.result.tools.map((t) => t.name).sort();
  assert.deepEqual(names, EXPECTED_TOOLS);
  assert.deepEqual(names, [...TOOL_NAMES].sort());
  for (const n of names) assert.doesNotMatch(n, /delete|remove|restart|reboot|upgrade|firmware|adopt|forget|port_?forward|provision|backup|ssh/i);
  for (const t of r.json.result.tools) {
    assert.equal(t.inputSchema.additionalProperties, false, `${t.name} schema is strict`);
    if (!t.annotations.readOnlyHint) assert.ok(t.inputSchema.properties.dry_run, `${t.name} has dry_run`);
  }
  assert.equal(sent.length, 0);
});

test('tools/call dry_run through the full stack sends nothing and is logged', async () => {
  const r = await rpc(port, token, 'tools/call', { name: 'unifi_rw_authorize_guest', arguments: { client_id: CLIENT, timeLimitMinutes: 60, dry_run: true } });
  assert.equal(r.status, 200);
  const res = r.json.result;
  assert.ok(!res.isError, res.content[0].text);
  const out = JSON.parse(res.content[0].text);
  assert.equal(out.dry_run, true);
  assert.equal(out.request.method, 'POST');
  assert.equal(out.request.url, `https://127.0.0.1:1/proxy/network/integration/v1/sites/${SITE}/clients/${CLIENT}/actions`);
  assert.equal(out.request.headers['X-API-KEY'], '[REDACTED]');
  assert.deepEqual(out.request.body, { action: 'AUTHORIZE_GUEST_ACCESS', timeLimitMinutes: 60 });
  assert.ok(!r.text.includes('fake-api-key'));
  assert.equal(sent.length, 0);

  const lines = fs.readFileSync(auditLog.file, 'utf8').trim().split('\n').map(JSON.parse);
  const last = lines.at(-1);
  assert.equal(last.tool, 'unifi_rw_authorize_guest');
  assert.equal(last.status, 'dry_run');
  assert.equal(last.dry_run, true);
});

test('tools/call refused write returns isError and is logged as refused', async () => {
  const r = await rpc(port, token, 'tools/call', {
    name: 'unifi_rw_create_legacy_firewall_rule',
    arguments: { rule: { name: 'ssh', ruleset: 'LAN_IN', action: 'drop', x_ssh_enabled: true }, dry_run: true },
  });
  const res = r.json.result;
  assert.equal(res.isError, true);
  assert.match(res.content[0].text, /Refused by guard: .*x_ssh/);
  const last = fs.readFileSync(auditLog.file, 'utf8').trim().split('\n').map(JSON.parse).at(-1);
  assert.equal(last.status, 'refused');
  assert.equal(last.method, 'POST');
  assert.equal(last.endpoint, '/api/s/default/rest/firewallrule');
  assert.equal(last.backend, 'local');
  assert.equal(sent.length, 0);

  // WAN accept is already refused by the tool's input schema (the guard would refuse it too)
  const z = await rpc(port, token, 'tools/call', {
    name: 'unifi_rw_create_legacy_firewall_rule',
    arguments: { rule: { name: 'ssh in', ruleset: 'WAN_IN', action: 'accept', dst_port: '22' }, dry_run: true },
  });
  assert.ok(z.json.error || z.json.result.isError);
  assert.match(JSON.stringify(z.json), /WAN\* rulesets allow only drop\/reject/);
  assert.equal(sent.length, 0);
});

test('unknown tool is not callable', async () => {
  const r = await rpc(port, token, 'tools/call', { name: 'unifi_rw_delete_network', arguments: {} });
  const ok = r.json.error || r.json.result.isError;
  assert.ok(ok);
});
