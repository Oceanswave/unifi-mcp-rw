'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { InMemoryTransport } = require('@modelcontextprotocol/sdk/inMemory.js');
const { buildMcpServer } = require('../http-server-rw.cjs');
const { createUdmClient } = require('../lib/udm-client.cjs');
const { createAuditLog } = require('../lib/audit-log.cjs');
const { GuardError } = require('../lib/guard.cjs');
const { tmpDir } = require('./helpers.cjs');

const SITE = '88f7af54-98f8-306a-a1c7-c9349722b1f6';
const WIFI = '7a2e4c90-1d3b-4f6a-8e25-c4b9d0f13a77';
const NET = '3f6c2a10-5b7e-4d2a-9c41-7e8d0a6b1c25';
const ZONE = 'aaaaaaaa-0000-4000-8000-000000000001';
const AP_ID = '5f1e2d3c4b5a69788796a5b4';
const USER_ID = '6a1e2d3c4b5a69788796a5b4';
const NETCONF = '7b1e2d3c4b5a69788796a5b4';
const RULE_ID = '8c1e2d3c4b5a69788796a5b4';
const API_KEY = 'super-secret-api-key-0123456789abcdef';
// Canonical paths (what tools and the guard see) and the full local paths the transport receives.
const CI = `/integration/v1/sites/${SITE}`;
const CC = '/api/s/default';
const I = `/proxy/network${CI}`;
const C = `/proxy/network${CC}`;

const wifiSample = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'docs', 'sample-wifi-broadcast.json'), 'utf8'));
wifiSample.securityConfiguration.passphrase = 'real-wifi-passphrase';

const fixtures = {
  [`${I}/wifi/broadcasts/${WIFI}`]: { status: 200, body: wifiSample },
  [`${I}/networks/${NET}`]: {
    status: 200,
    body: { id: NET, management: 'GATEWAY', name: 'Default', enabled: true, vlanId: 1, default: true, metadata: { origin: 'SYSTEM_DEFINED' }, zoneId: ZONE, mdnsForwardingEnabled: false, ipv4Configuration: { hostIpAddress: '192.168.1.1' } },
  },
  [`${I}/firewall/zones?limit=200`]: {
    status: 400,
    body: { statusCode: 400, code: 'api.firewall.zone-based-firewall-not-configured', message: 'Zone Based Firewall is not configured' },
  },
  [`${C}/stat/device/aa:bb:cc:dd:ee:01`]: {
    status: 200,
    body: {
      meta: { rc: 'ok' },
      data: [
        {
          _id: AP_ID,
          mac: 'aa:bb:cc:dd:ee:01',
          type: 'uap',
          radio_table: [
            { radio: 'ng', name: 'wifi0', channel: '6', ht: '20', tx_power_mode: 'auto', min_rssi_enabled: false },
            { radio: 'na', name: 'wifi1', channel: 'auto', ht: 80, tx_power_mode: 'auto', antenna_gain: 3 },
          ],
        },
      ],
    },
  },
  [`${C}/stat/device/aa:bb:cc:dd:ee:02`]: { status: 200, body: { meta: { rc: 'ok' }, data: [{ _id: AP_ID, type: 'usw', radio_table: [] }] } },
  [`${C}/rest/user`]: { status: 200, body: { meta: { rc: 'ok' }, data: [{ _id: USER_ID, mac: '11:22:33:44:55:66', name: 'tv', use_fixedip: false }] } },
  [`${C}/rest/networkconf`]: { status: 200, body: { meta: { rc: 'ok' }, data: [{ _id: NETCONF, name: 'Default', purpose: 'corporate', ip_subnet: '192.168.1.1/24' }] } },
  [`${C}/rest/firewallgroup`]: { status: 200, body: { meta: { rc: 'ok' }, data: [] } },
  [`${C}/rest/firewallrule/${RULE_ID}`]: {
    status: 200,
    body: { meta: { rc: 'ok' }, data: [{ _id: RULE_ID, site_id: 'x', name: 'block in', ruleset: 'WAN_IN', action: 'drop', rule_index: 2000, enabled: true }] },
  },
};

let client, sent, auditLog, dir;

test.before(async () => {
  dir = tmpDir();
  sent = [];
  auditLog = createAuditLog({ stateDir: path.join(dir, 'state') });
  const udm = createUdmClient({
    backend: 'local',
    target: { host: 'udm.test', port: 443, isIp: false, hostHeader: 'udm.test' },
    apiKey: API_KEY,
    siteId: SITE,
    allowWrites: true,
    auditLog,
    transport: async (req) => {
      sent.push(req);
      if (req.method !== 'GET') return { status: 200, text: JSON.stringify({ meta: { rc: 'ok' }, data: [] }) };
      const f = fixtures[req.path];
      if (!f) return { status: 404, text: '{"message":"not found"}' };
      return { status: f.status, text: JSON.stringify(f.body) };
    },
  });
  const server = buildMcpServer({ udmClient: udm, auditLog });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await server.connect(a);
  client = new Client({ name: 'test', version: '1' });
  await client.connect(b);
});

test.after(() => fs.rmSync(dir, { recursive: true, force: true }));

// Input-schema rejections surface as thrown MCP errors or isError results depending on the SDK; normalize both.
const callOn = async (c, name, args) => {
  let r;
  try {
    r = await c.callTool({ name, arguments: args });
  } catch (e) {
    r = { isError: true, content: [{ type: 'text', text: e.message }] };
  }
  return { isError: Boolean(r.isError), text: r.content[0].text, json: (() => { try { return JSON.parse(r.content[0].text); } catch { return undefined; } })() };
};
const call = (name, args) => callOn(client, name, args);
const writes = () => sent.filter((s) => s.method !== 'GET');
const lastLog = () => fs.readFileSync(auditLog.file, 'utf8').trim().split('\n').map(JSON.parse).at(-1);

test('udm-client dry_run returns redacted request and sends nothing', async () => {
  let called = 0;
  const udm = createUdmClient({ backend: 'local', target: { host: 'udm.test', port: 443, isIp: false, hostHeader: 'udm.test' }, apiKey: API_KEY, siteId: SITE, allowWrites: true, transport: async () => called++ });
  const out = await udm.request({ method: 'POST', path: `${CI}/clients/${WIFI}/actions`, body: { action: 'UNAUTHORIZE_GUEST_ACCESS' }, dryRun: true });
  assert.equal(called, 0);
  assert.equal(out.dry_run, true);
  assert.equal(out.request.headers['X-API-KEY'], '[REDACTED]');
  assert.equal(out.request.url, `https://udm.test${I}/clients/${WIFI}/actions`);
  assert.ok(!JSON.stringify(out).includes(API_KEY));
  // guard still runs in dry-run mode
  await assert.rejects(udm.request({ method: 'POST', path: `${CC}/cmd/devmgr`, body: { cmd: 'restart' }, dryRun: true }), GuardError);
  await assert.rejects(udm.request({ method: 'DELETE', path: `${CI}/networks/${NET}`, dryRun: true }), /DELETE/);
  // full (prefixed) paths are not canonical and are refused
  await assert.rejects(udm.request({ method: 'POST', path: `${I}/clients/${WIFI}/actions`, body: { action: 'UNAUTHORIZE_GUEST_ACCESS' }, dryRun: true }), /proxy\/connector prefix/);
  assert.equal(called, 0);
});

test('create_wifi_broadcast dry_run sends nothing', async () => {
  sent.length = 0;
  const r = await call('unifi_rw_create_wifi_broadcast', { broadcast: { type: 'STANDARD', name: 'IoT', enabled: true, network: { type: 'SPECIFIC', networkId: NET }, securityConfiguration: { type: 'WPA2_PERSONAL', passphrase: 'abcdefgh123' } }, dry_run: true });
  assert.equal(r.isError, false, r.text);
  assert.equal(r.json.request.method, 'POST');
  assert.equal(r.json.request.body.securityConfiguration.passphrase, '[REDACTED]');
  assert.equal(sent.length, 0);
  const l = lastLog();
  assert.equal(l.status, 'dry_run');
  assert.equal(l.args.broadcast.securityConfiguration.passphrase, '[REDACTED]');
});

test('update_wifi_broadcast merges, strips read-only fields and preserves passphrase', async () => {
  sent.length = 0;
  let r = await call('unifi_rw_update_wifi_broadcast', { broadcast_id: WIFI, changes: { hideName: true }, dry_run: true });
  assert.equal(r.isError, false, r.text);
  assert.equal(r.json.request.method, 'PUT');
  assert.equal(r.json.request.body.hideName, true);
  assert.equal(r.json.request.body.securityConfiguration.passphrase, '[REDACTED]');
  assert.equal(writes().length, 0);

  r = await call('unifi_rw_update_wifi_broadcast', { broadcast_id: WIFI, changes: { hideName: true } });
  assert.equal(r.isError, false, r.text);
  const w = writes();
  assert.equal(w.length, 1);
  const body = JSON.parse(w[0].body);
  assert.equal(body.securityConfiguration.passphrase, 'real-wifi-passphrase');
  assert.equal(body.id, undefined);
  assert.equal(body.metadata, undefined);
  assert.equal(body.hideName, true);
  assert.equal(w[0].headers['X-API-KEY'], API_KEY);
  assert.equal(lastLog().status, 200);
});

test('update_ap_radios sends only allowlisted per-radio keys, keeps representation', async () => {
  sent.length = 0;
  const r = await call('unifi_rw_update_ap_radios', { mac: 'AA-BB-CC-DD-EE-01', radios: [{ radio: 'ng', channel: 11, tx_power_mode: 'low' }, { radio: 'na', ht: 40 }], dry_run: true });
  assert.equal(r.isError, false, r.text);
  assert.equal(r.json.request.url, `https://udm.test${C}/rest/device/${AP_ID}`);
  assert.deepEqual(r.json.request.body, {
    radio_table: [
      { radio: 'ng', name: 'wifi0', channel: '11', ht: '20', tx_power_mode: 'low', min_rssi_enabled: false },
      // antenna_gain (and any other non-allowlisted key) is never sent
      { radio: 'na', name: 'wifi1', channel: 'auto', ht: 40, tx_power_mode: 'auto' },
    ],
  });
  assert.equal(writes().length, 0);

  const bad = await call('unifi_rw_update_ap_radios', { mac: 'aa:bb:cc:dd:ee:02', radios: [{ radio: 'ng', channel: 1 }], dry_run: true });
  assert.equal(bad.isError, true);
  assert.match(bad.text, /not an access point/);
  assert.equal(lastLog().status, 'error');

  const missing = await call('unifi_rw_update_ap_radios', { mac: 'aa:bb:cc:dd:ee:01', radios: [{ radio: '6e', channel: 37 }], dry_run: true });
  assert.match(missing.text, /no 6e radio/);

  const extra = await call('unifi_rw_update_ap_radios', { mac: 'aa:bb:cc:dd:ee:01', radios: [{ radio: 'ng', name: 'x' }], dry_run: true });
  assert.equal(extra.isError, true);
  for (const radios of [[{ radio: 'wifi6e', channel: 1 }], [{ radio: 'ng', tx_power: 'auto' }], [{ radio: 'ng', min_rssi: -96 }], [{ radio: 'ng', antenna_gain: 1 }]]) {
    assert.equal((await call('unifi_rw_update_ap_radios', { mac: 'aa:bb:cc:dd:ee:01', radios, dry_run: true })).isError, true, JSON.stringify(radios));
  }
  assert.equal(writes().length, 0);
});

test('set_fixed_ip: PUT for existing client, POST for new', async () => {
  let r = await call('unifi_rw_set_fixed_ip', { mac: '11:22:33:44:55:66', fixed_ip: '192.168.1.50', network_id: NETCONF, dry_run: true });
  assert.equal(r.isError, false, r.text);
  assert.equal(r.json.request.method, 'PUT');
  assert.equal(r.json.request.url, `https://udm.test${C}/rest/user/${USER_ID}`);
  assert.deepEqual(r.json.request.body, { use_fixedip: true, fixed_ip: '192.168.1.50', network_id: NETCONF });

  r = await call('unifi_rw_set_fixed_ip', { mac: 'AA:BB:CC:00:00:01', fixed_ip: '192.168.1.51', network_id: NETCONF, name: 'printer', dry_run: true });
  assert.equal(r.json.request.method, 'POST');
  assert.deepEqual(r.json.request.body, { mac: 'aa:bb:cc:00:00:01', use_fixedip: true, fixed_ip: '192.168.1.51', network_id: NETCONF, name: 'printer' });

  r = await call('unifi_rw_clear_fixed_ip', { mac: '11:22:33:44:55:66', dry_run: true });
  assert.deepEqual(r.json.request.body, { use_fixedip: false });

  r = await call('unifi_rw_set_fixed_ip', { mac: 'nope', fixed_ip: '192.168.1.51', network_id: NETCONF, dry_run: true });
  assert.equal(r.isError, true);
  assert.equal(writes().length, 0);
});

test('zone-based policy write fails closed when zones are unavailable', async () => {
  const r = await call('unifi_rw_create_firewall_policy', {
    policy: { name: 'x', enabled: true, loggingEnabled: false, action: { type: 'BLOCK' }, source: { zoneId: ZONE }, destination: { zoneId: ZONE }, ipProtocolScope: { ipVersion: 'IPV4' } },
    dry_run: true,
  });
  assert.equal(r.isError, true);
  assert.match(r.text, /zones could not be determined.*zone lookup failed: UDM: request rejected as invalid \(400\) \[code api\.firewall\.zone-based-firewall-not-configured\]/);
  assert.doesNotMatch(r.text, /Zone Based Firewall is not configured/);
  assert.equal(lastLog().status, 'refused');
});

test('legacy rule update: guard sees merged full rule', async () => {
  let r = await call('unifi_rw_update_legacy_firewall_rule', { rule_id: RULE_ID, changes: { action: 'accept' }, dry_run: true });
  assert.equal(r.isError, true);
  assert.match(r.text, /WAN_IN/);
  r = await call('unifi_rw_update_legacy_firewall_rule', { rule_id: RULE_ID, changes: { name: 'renamed' }, dry_run: true });
  assert.equal(r.isError, false, r.text);
  assert.equal(r.json.request.body._id, undefined);
  assert.equal(r.json.request.body.ruleset, 'WAN_IN');
  for (const changes of [{ enabled: false }, { ruleset: 'LAN_IN' }, { rule_index: 1 }, { src_address: '203.0.113.9' }]) {
    r = await call('unifi_rw_update_legacy_firewall_rule', { rule_id: RULE_ID, changes, dry_run: true });
    assert.equal(r.isError, true, JSON.stringify(changes));
    assert.match(r.text, /only name, logging may change/);
  }
  assert.equal(writes().length, 0);
});

test('legacy rule tools: unknown fields, *_LOCAL accept-from-any, enums refused end to end', async () => {
  sent.length = 0;
  let r = await call('unifi_rw_update_legacy_firewall_rule', { rule_id: RULE_ID, changes: { foo: 1 }, dry_run: true });
  assert.equal(r.isError, true);
  assert.match(r.text, /field "foo" is not allowed/);
  r = await call('unifi_rw_create_legacy_firewall_rule', { rule: { name: 'ssh to gw', ruleset: 'LAN_LOCAL', action: 'accept', dst_port: '22' }, dry_run: true });
  assert.equal(r.isError, true);
  assert.match(r.text, /must constrain the source/);
  r = await call('unifi_rw_create_legacy_firewall_rule', { rule: { name: 'ssh to gw', ruleset: 'LAN_LOCAL', action: 'accept', dst_port: '22', src_networkconf_id: NETCONF, src_networkconf_type: 'NETv4' }, dry_run: true });
  assert.equal(r.isError, false, r.text);
  for (const rule of [{ ruleset: 'wan_in', action: 'drop' }, { ruleset: 'LAN_IN', action: 'DROP' }, { ruleset: 'WAN_OUT', action: 'accept' }, { ruleset: 'LAN_IN', action: 'drop', nat: true }]) {
    r = await call('unifi_rw_create_legacy_firewall_rule', { rule, dry_run: true });
    assert.equal(r.isError, true, JSON.stringify(rule));
  }
  assert.equal(writes().length, 0);
});

test('authorize_guest: limits outside the spec bounds are refused by the schema', async () => {
  sent.length = 0;
  for (const [k, v] of [['timeLimitMinutes', 0], ['timeLimitMinutes', 1000001], ['dataUsageLimitMBytes', 1048577], ['rxRateLimitKbps', 1], ['txRateLimitKbps', 100001], ['txRateLimitKbps', 2.5]]) {
    const r = await call('unifi_rw_authorize_guest', { client_id: WIFI, [k]: v, dry_run: true });
    assert.equal(r.isError, true, `${k}=${v}`);
  }
  const r = await call('unifi_rw_authorize_guest', { client_id: WIFI, timeLimitMinutes: 1000000, rxRateLimitKbps: 2, dry_run: true });
  assert.equal(r.isError, false, r.text);
  assert.equal(writes().length, 0);
});

test('update_network: only mdnsForwardingEnabled, guard sees the existing network', async () => {
  let r = await call('unifi_rw_update_network', { network_id: NET, changes: { mdnsForwardingEnabled: true }, dry_run: true });
  assert.equal(r.isError, false, r.text);
  assert.equal(r.json.request.body.mdnsForwardingEnabled, true);
  assert.equal(r.json.request.body.ipv4Configuration.hostIpAddress, '192.168.1.1');
  for (const k of ['id', 'metadata', 'default']) assert.equal(r.json.request.body[k], undefined);
  r = await call('unifi_rw_update_network', { network_id: NET, changes: { zoneId: 'aaaaaaaa-0000-4000-8000-000000000002' }, dry_run: true });
  assert.equal(r.isError, true);
  assert.match(r.text, /zoneId/);
  for (const changes of [{ isolationEnabled: true }, { internetAccessEnabled: false }, { vlanId: 2 }, { ipv4Configuration: { dhcpConfiguration: { mode: 'NONE' } } }, {}]) {
    r = await call('unifi_rw_update_network', { network_id: NET, changes, dry_run: true });
    assert.equal(r.isError, true, JSON.stringify(changes));
  }
  assert.equal(writes().length, 0);
});

test('strict input schemas reject unknown arguments', async () => {
  const r = await client.callTool({ name: 'unifi_rw_unauthorize_guest', arguments: { client_id: WIFI, dry_run: true, force: true } }).catch((e) => ({ isError: true, content: [{ text: e.message }] }));
  assert.equal(r.isError, true);
});

// ---------------------------------------------------------------------------
// Separate stacks with their own fixtures / transport behaviour
// ---------------------------------------------------------------------------
const BEARER = 'bearer-token-0123456789abcdef0123456789abcdef';

async function stack({ routes, zoneConfig = {}, stateName }) {
  const log = createAuditLog({ stateDir: path.join(dir, stateName), secrets: [BEARER, API_KEY] });
  const seen = [];
  const udm = createUdmClient({
    backend: 'local',
    target: { host: 'udm.test', port: 443, isIp: false, hostHeader: 'udm.test' },
    apiKey: API_KEY,
    siteId: SITE,
    allowWrites: true,
    auditLog: log,
    ...zoneConfig,
    transport: async (req) => {
      seen.push(req);
      const f = routes(req);
      return { status: f.status, headers: f.headers || {}, text: typeof f.body === 'string' ? f.body : JSON.stringify(f.body) };
    },
  });
  const server = buildMcpServer({ udmClient: udm, auditLog: log, secrets: [BEARER] });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await server.connect(a);
  const c = new Client({ name: 'test', version: '1' });
  await c.connect(b);
  return { call: (name, args) => callOn(c, name, args), seen, log };
}

test('upstream error bodies never reach tool output or writes.log (fix 3)', async () => {
  const leaky = JSON.stringify({
    code: 'api.err.InvalidPayload',
    message: `passphrase "hunter2-wifi-passphrase" rejected for key ${API_KEY} / ${BEARER}`,
    details: { passphrase: 'hunter2-wifi-passphrase', apiKey: API_KEY },
  });
  const s = await stack({
    stateName: 'state-leak',
    routes: (req) => (req.method === 'GET' ? { status: 400, body: leaky } : { status: 400, body: leaky }),
  });
  const r = await s.call('unifi_rw_authorize_guest', { client_id: WIFI });
  assert.equal(r.isError, true);
  assert.deepEqual(r.json, { status: 400, code: 'api.err.InvalidPayload', message: 'request rejected as invalid (400)' });
  const rr = await s.call('unifi_rw_get_network', { network_id: NET });
  assert.deepEqual(rr.json, { status: 400, code: 'api.err.InvalidPayload', message: 'request rejected as invalid (400)' });
  const logText = fs.readFileSync(s.log.file, 'utf8');
  for (const out of [r.text, rr.text, logText]) {
    for (const secret of ['hunter2', API_KEY, BEARER, 'rejected for key']) assert.ok(!out.includes(secret), `${secret} leaked: ${out}`);
  }
  assert.equal(JSON.parse(logText.trim().split('\n').at(-1)).status, 400);
});

test('error code is dropped unless token-shaped and secret-free; non-JSON bodies are never echoed (fix 3)', async () => {
  let next;
  const s = await stack({ stateName: 'state-codes', routes: () => next });
  const cases = [
    [{ status: 400, body: { code: API_KEY } }, { status: 400, message: 'request rejected as invalid (400)' }],
    [{ status: 400, body: { code: `x${BEARER}` } }, { status: 400, message: 'request rejected as invalid (400)' }],
    [{ status: 400, body: { code: 'has spaces and "quotes"' } }, { status: 400, message: 'request rejected as invalid (400)' }],
    [{ status: 400, body: { code: 'a'.repeat(101) } }, { status: 400, message: 'request rejected as invalid (400)' }],
    [{ status: 500, body: '<html>stack trace with hunter2</html>' }, { status: 500, message: 'internal server error (500)' }],
    [{ status: 200, body: { meta: { rc: 'error', msg: 'api.err.Invalid' }, data: [{ x_passphrase: 'hunter2' }] } }, { status: 200, code: 'api.err.Invalid', message: 'classic API reported an error' }],
    [{ status: 418, body: { message: 'hunter2' } }, { status: 418, message: 'HTTP error 418' }],
  ];
  for (const [resp, expected] of cases) {
    next = resp;
    const r = await s.call('unifi_rw_unauthorize_guest', { client_id: WIFI });
    assert.equal(r.isError, true);
    assert.deepEqual(r.json, expected, JSON.stringify(resp));
  }
  // non-JSON successful responses: status + note only
  next = { status: 200, body: `plain text with hunter2 and ${API_KEY}` };
  for (const [name, args] of [['unifi_rw_get_info', {}], ['unifi_rw_unauthorize_guest', { client_id: WIFI }]]) {
    const r = await s.call(name, args);
    assert.equal(r.isError, false, r.text);
    assert.deepEqual(r.json, { status: 200, note: 'non-JSON response omitted' });
  }
  const logText = fs.readFileSync(s.log.file, 'utf8');
  for (const secret of ['hunter2', API_KEY, BEARER, 'stack trace']) assert.ok(!logText.includes(secret), secret);
});

test('tool output and writes.log scrub the API key and bearer token even from caller input (fix 3)', async () => {
  const s = await stack({ stateName: 'state-scrub', routes: () => ({ status: 200, body: {} }) });
  // a guard refusal echoes caller-supplied text; the scrubber still removes the secrets
  const r = await s.call('unifi_rw_create_legacy_firewall_rule', { rule: { name: 'r', ruleset: 'LAN_IN', action: 'accept', [`x_ssh_${BEARER}`]: API_KEY }, dry_run: true });
  assert.equal(r.isError, true);
  assert.match(r.text, /Refused by guard/);
  assert.ok(!r.text.includes(BEARER) && !r.text.includes(API_KEY), r.text);
  const logText = fs.readFileSync(s.log.file, 'utf8');
  assert.ok(!logText.includes(BEARER) && !logText.includes(API_KEY), logText);
  assert.match(logText, /\[REDACTED\]/);
});

const Z_INTERNAL = 'aaaaaaaa-0000-4000-8000-000000000001';
const Z_EXTERNAL = 'aaaaaaaa-0000-4000-8000-000000000002';
const Z_IOT = 'aaaaaaaa-0000-4000-8000-000000000004';
const POLICY = 'c0ffee00-0000-4000-8000-000000000001';

test('firewall policy tools pass the existing policy; WAN-side deny stays intact (fixes 1, 5)', async () => {
  const wanBlock = {
    id: POLICY,
    index: 10000,
    metadata: { origin: 'USER_DEFINED' },
    name: 'block wan',
    enabled: true,
    loggingEnabled: false,
    action: { type: 'BLOCK' },
    source: { zoneId: Z_EXTERNAL },
    destination: { zoneId: Z_INTERNAL },
    ipProtocolScope: { ipVersion: 'IPV4_AND_IPV6' },
  };
  const s = await stack({
    stateName: 'state-policy',
    zoneConfig: { firewallInternalZoneIds: [Z_INTERNAL, Z_IOT], firewallWanZoneIds: [Z_EXTERNAL] },
    routes: (req) => {
      if (req.method !== 'GET') return { status: 200, body: {} };
      if (req.path === `${I}/firewall/zones?limit=200`) {
        return { status: 200, body: { data: [{ id: Z_INTERNAL, name: 'Internal' }, { id: Z_EXTERNAL, name: 'Uplink' }, { id: Z_IOT, name: 'IoT' }] } };
      }
      if (req.path === `${I}/firewall/policies/${POLICY}`) return { status: 200, body: wanBlock };
      return { status: 404, body: {} };
    },
  });
  const upd = (changes) => s.call('unifi_rw_update_firewall_policy', { policy_id: POLICY, changes, dry_run: true });
  for (const changes of [{ enabled: false }, { action: { type: 'ALLOW' } }, { source: { zoneId: Z_IOT } }, { destination: { zoneId: Z_IOT } }]) {
    const r = await upd(changes);
    assert.equal(r.isError, true, JSON.stringify(changes));
    assert.match(r.text, /WAN-side deny/);
  }
  let r = await upd({ description: 'documented', loggingEnabled: true });
  assert.equal(r.isError, false, r.text);
  assert.equal(r.json.request.body.enabled, true);
  // PATCH reads the policy first, then patches
  s.seen.length = 0;
  r = await s.call('unifi_rw_patch_firewall_policy', { policy_id: POLICY, loggingEnabled: true, dry_run: true });
  assert.equal(r.isError, false, r.text);
  assert.deepEqual(s.seen.map((q) => q.method), ['GET']);
  // ALLOW create: internal <-> internal only
  const create = (src, dst) =>
    s.call('unifi_rw_create_firewall_policy', { policy: { name: 'p', enabled: true, loggingEnabled: false, action: { type: 'ALLOW' }, source: { zoneId: src }, destination: { zoneId: dst }, ipProtocolScope: { ipVersion: 'IPV4' } }, dry_run: true });
  assert.equal((await create(Z_INTERNAL, Z_IOT)).isError, false);
  assert.match((await create(Z_EXTERNAL, Z_INTERNAL)).text, /WAN-in/);
  assert.match((await create(Z_INTERNAL, Z_EXTERNAL)).text, /ALLOW to WAN/);
  // input schema: action type enum, read-only fields
  assert.equal((await upd({ index: 1 })).isError, true);
  assert.equal((await create('not-a-uuid', Z_IOT)).isError, true);
  assert.equal(s.seen.filter((q) => q.method !== 'GET').length, 0);
});

test('WiFi tools: open/OWE, network/isolation/portal changes refused (fix 2)', async () => {
  const s = await stack({ stateName: 'state-wifi', routes: (req) => (req.path === `${I}/wifi/broadcasts/${WIFI}` ? { status: 200, body: wifiSample } : { status: 200, body: {} }) });
  const base = { type: 'STANDARD', name: 'IoT', enabled: true, network: { type: 'SPECIFIC', networkId: NET }, securityConfiguration: { type: 'WPA3_PERSONAL', passphrase: 'abcdefgh123' } };
  const create = (b) => s.call('unifi_rw_create_wifi_broadcast', { broadcast: b, dry_run: true });
  assert.equal((await create(base)).isError, false);
  for (const b of [
    { ...base, securityConfiguration: { type: 'OPEN' } },
    { ...base, securityConfiguration: { type: 'OPEN', encryption: 'ENHANCED_OPEN' } },
    { ...base, network: { type: 'NATIVE' } },
    { ...base, hotspotConfiguration: { type: 'CAPTIVE_PORTAL' } },
    { ...base, network: undefined },
  ]) {
    assert.equal((await create(b)).isError, true, JSON.stringify(b));
  }
  const upd = (changes) => s.call('unifi_rw_update_wifi_broadcast', { broadcast_id: WIFI, changes, dry_run: true });
  assert.equal((await upd({ hideName: true })).isError, false);
  for (const changes of [{ securityConfiguration: { type: 'OPEN' } }, { network: { type: 'NATIVE' } }, { clientIsolationEnabled: true }, { hotspotConfiguration: { type: 'CAPTIVE_PORTAL' } }, { type: 'IOT_OPTIMIZED' }]) {
    assert.equal((await upd(changes)).isError, true, JSON.stringify(changes));
  }
  assert.equal(s.seen.filter((q) => q.method !== 'GET').length, 0);
});
