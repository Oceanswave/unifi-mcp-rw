'use strict';

// WAN-exposure refusals (lib/wan-exposure.cjs), through the tools, and UNIFI_ALLOW_WAN_EXPOSURE / UNIFI_WAN_ZONE_IDS.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { InMemoryTransport } = require('@modelcontextprotocol/sdk/inMemory.js');
const { buildMcpServer } = require('../http-server-rw.cjs');
const { createUdmClient } = require('../lib/udm-client.cjs');
const { createWriteLog } = require('../lib/write-log.cjs');
const { createWanExposure, WanExposureError, WAN_RULESETS } = require('../lib/wan-exposure.cjs');
const { validateConfig, resolveWanExposure, ConfigError } = require('../lib/config.cjs');
const { GuardError } = require('../lib/guard.cjs');
const { tmpDir, rpc, spawnServer } = require('./helpers.cjs');

const SITE = '00000000-0000-4000-8000-000000000001';
const NET = '00000000-0000-4000-8000-000000000002';
const NET_WAN = '00000000-0000-4000-8000-000000000003';
const POLICY = '00000000-0000-4000-8000-000000000004';
const CONSOLE = 'FAKECONSOLE00000000:0000';
const API_KEY = 'fake-key-0000-0000-0000-0000';
const Z_INTERNAL = '00000000-0000-4000-8000-0000000000a1';
const Z_IOT = '00000000-0000-4000-8000-0000000000a2';
const Z_EXTERNAL = '00000000-0000-4000-8000-0000000000e1'; // system-defined "External"
const Z_UPLINK = '00000000-0000-4000-8000-0000000000e2'; // renamed WAN zone, known only by id
const Z_NAMED_WAN = '00000000-0000-4000-8000-0000000000e3'; // user zone named "WAN"
const RULE_ID = 'fa0e00000000000000000003';
const NETCONF = 'fa0e00000000000000000001';
const CI = `/integration/v1/sites/${SITE}`;
const CC = '/api/s/default';
const I = `/proxy/network${CI}`;
const C = `/proxy/network${CC}`;

const ZONES = [
  { id: Z_INTERNAL, name: 'Internal', networkIds: [NET], metadata: { origin: 'SYSTEM_DEFINED' } },
  { id: Z_IOT, name: 'IoT', networkIds: [], metadata: { origin: 'USER_DEFINED' } },
  { id: Z_EXTERNAL, name: 'External', networkIds: [NET_WAN], metadata: { origin: 'SYSTEM_DEFINED' } },
  { id: Z_UPLINK, name: 'Uplink', networkIds: [], metadata: { origin: 'USER_DEFINED' } },
  { id: Z_NAMED_WAN, name: 'wan', networkIds: [], metadata: { origin: 'USER_DEFINED' } },
];

const wan = (o = {}) => createWanExposure({ zoneIds: [Z_UPLINK], ...o });
const policyReq = (method, body, context = { zones: ZONES }) => ({ method, path: `${CI}/firewall/policies${method === 'POST' ? '' : `/${POLICY}`}`, body, context });
const policy = (type, src, extra = {}) => ({ name: 'p', enabled: true, action: { type }, source: { zoneId: src }, destination: { zoneId: Z_INTERNAL }, ...extra });

const refused = async (p, re) => {
  await assert.rejects(p, (e) => {
    assert.ok(e instanceof WanExposureError, e && e.stack);
    assert.match(e.message, /^Refused: /);
    assert.match(e.message, /dry_run does not change that/);
    if (re) assert.match(e.reason, re);
    return true;
  });
};
const passes = async (p) => assert.equal(await p, undefined);

// --- unit: which zone is the WAN -------------------------------------------------

test('isWanZone: configured id, system-defined External, or a WAN-looking name', () => {
  const w = wan();
  const byId = Object.fromEntries(ZONES.map((z) => [z.id, w.isWanZone(z)]));
  assert.deepEqual(byId, { [Z_INTERNAL]: false, [Z_IOT]: false, [Z_EXTERNAL]: true, [Z_UPLINK]: true, [Z_NAMED_WAN]: true });
  // ids compare without case
  assert.equal(createWanExposure({ zoneIds: [Z_UPLINK.toUpperCase()] }).isWanZone({ id: Z_UPLINK, name: 'Uplink' }), true);
  assert.equal(createWanExposure().isWanZone({ id: Z_UPLINK, name: 'Uplink' }), false);
  assert.equal(createWanExposure().isWanZone({ id: Z_IOT, name: ' Internet ' }), true);
  assert.throws(() => createWanExposure({ zoneIds: ['not-a-uuid'] }), /zone UUIDs/);
});

// --- unit: zone-based firewall policies ------------------------------------------

test('policy: ALLOW from the WAN zone is refused (create, update), whichever way the zone is known', async () => {
  for (const src of [Z_EXTERNAL, Z_UPLINK, Z_NAMED_WAN, Z_EXTERNAL.toUpperCase()]) {
    await refused(wan().check(policyReq('POST', policy('ALLOW', src))), /would ALLOW traffic from the ".*" zone, which is the WAN/);
    await refused(wan().check(policyReq('PUT', policy('ALLOW', src))));
  }
  // missing or unknown action types count as ALLOW
  await refused(wan().check(policyReq('POST', { ...policy('ALLOW', Z_EXTERNAL), action: {} })));
  await refused(wan().check(policyReq('POST', { ...policy('ALLOW', Z_EXTERNAL), action: { type: 'ACCEPT' } })));
});

test('policy: BLOCK/REJECT from the WAN and ALLOW between internal zones pass', async () => {
  await passes(wan().check(policyReq('POST', policy('BLOCK', Z_EXTERNAL))));
  await passes(wan().check(policyReq('PUT', policy('reject', Z_UPLINK))));
  await passes(wan().check(policyReq('POST', policy('ALLOW', Z_INTERNAL))));
  await passes(wan().check(policyReq('POST', policy('ALLOW', Z_IOT))));
});

test('policy: an ALLOW whose source cannot be checked is refused (no zone, unknown zone, zones unreadable)', async () => {
  await refused(wan().check(policyReq('POST', { ...policy('ALLOW', Z_IOT), source: {} })), /has no source\.zoneId/);
  await refused(wan().check(policyReq('POST', policy('ALLOW', '00000000-0000-4000-8000-0000000000ff'))), /not one of this site's firewall zones/);
  await refused(wan().check(policyReq('POST', policy('ALLOW', Z_IOT), {})), /firewall zones could not be read/);
  await refused(wan().check(policyReq('POST', policy('ALLOW', Z_IOT), { zones: [] })), /firewall zones could not be read/);
  await refused(
    wan().check(policyReq('POST', policy('ALLOW', Z_IOT), {}), {
      loadZones: async () => {
        throw new Error('HTTP 400 zone-based firewall not configured');
      },
    }),
    /could not be read to find the WAN zone \(HTTP 400/
  );
  // loadZones is used when the context has none
  await passes(wan().check(policyReq('POST', policy('ALLOW', Z_IOT), {}), { loadZones: async () => ZONES }));
  await refused(wan().check(policyReq('POST', policy('ALLOW', Z_EXTERNAL), {}), { loadZones: async () => ZONES }));
});

test('policy PATCH: logging-only patches pass unread; anything else is checked on the merged policy', async () => {
  const existing = policy('ALLOW', Z_EXTERNAL, { enabled: false });
  await passes(wan().check(policyReq('PATCH', { loggingEnabled: true }, { zones: ZONES })));
  await refused(wan().check(policyReq('PATCH', { enabled: true }, { zones: ZONES, existing })));
  await refused(wan().check(policyReq('PATCH', { enabled: true }, { zones: ZONES })), /could not be read/);
  await passes(wan().check(policyReq('PATCH', { action: { type: 'BLOCK' } }, { zones: ZONES, existing })));
});

// --- unit: zones, networks ----------------------------------------------------------

test('zones: editing the WAN zone, or taking networks from it, is refused', async () => {
  const zoneReq = (method, id, body) => ({ method, path: `${CI}/firewall/zones${id ? `/${id}` : ''}`, body, context: { zones: ZONES } });
  await refused(wan().check(zoneReq('PUT', Z_EXTERNAL, { name: 'Outside', networkIds: [NET_WAN] })), /modify the "External" zone, which is the WAN/);
  await refused(wan().check(zoneReq('PUT', Z_UPLINK, { name: 'Uplink' })), /modify the "Uplink" zone/);
  await refused(wan().check(zoneReq('POST', undefined, { name: 'Lab', networkIds: [NET_WAN.toUpperCase()] })), /move networks out of the WAN zone/);
  await refused(wan().check(zoneReq('PUT', Z_IOT, { name: 'IoT', networkIds: [NET_WAN] })), /move networks out of the WAN zone/);
  await refused(wan().check(zoneReq('DELETE', Z_EXTERNAL)), /modify the "External" zone/);
  await passes(wan().check(zoneReq('PUT', Z_IOT, { name: 'IoT', networkIds: [NET] })));
});

test('networks: moving a network into (or out of) the WAN zone, or making it a WAN, is refused', async () => {
  const netReq = (body, existing, context = { zones: ZONES }) => ({ method: 'PUT', path: `${CI}/networks/${NET}`, body, context: { ...context, existing } });
  const current = { id: NET, name: 'Lab', zoneId: Z_INTERNAL, mdnsForwardingEnabled: false };
  await refused(wan().check(netReq({ ...current, zoneId: Z_EXTERNAL }, current)), /put the network in the "External" zone, which is the WAN/);
  await refused(wan().check(netReq({ ...current, zoneId: Z_UPLINK }, current)), /put the network in the "Uplink" zone/);
  await refused(wan().check(netReq({ ...current, zoneId: Z_IOT }, { ...current, zoneId: Z_EXTERNAL })), /move the network out of the "External" zone/);
  await refused(wan().check(netReq({ ...current, zoneId: Z_IOT }, current, {})), /firewall zones could not be read/);
  await refused(wan().check(netReq({ ...current, zoneId: 7 }, current)), /zoneId is not a string/);
  await refused(wan().check(netReq({ ...current, purpose: 'WAN' }, current)), /turn the network into a WAN/);
  await refused(wan().check({ method: 'PUT', path: `${CC}/rest/networkconf/${NETCONF}`, body: { purpose: 'wan' }, context: { existing: { purpose: 'corporate' } } }), /turn the network into a WAN/);
  // what update_network actually sends: same zone, mDNS flipped; zones are not even needed
  await passes(wan().check(netReq({ ...current, mdnsForwardingEnabled: true }, current, {})));
  await passes(wan().check(netReq({ ...current, zoneId: Z_IOT }, current)));
});

// --- unit: legacy firewall rules ------------------------------------------------------

test('legacy rules: accept on WAN_IN, WAN_LOCAL, WANv6_IN, WANv6_LOCAL is refused; drop/reject pass', async () => {
  assert.deepEqual(WAN_RULESETS, ['WAN_IN', 'WAN_LOCAL', 'WANv6_IN', 'WANv6_LOCAL']);
  const create = (body) => ({ method: 'POST', path: `${CC}/rest/firewallrule`, body });
  const update = (body) => ({ method: 'PUT', path: `${CC}/rest/firewallrule/${RULE_ID}`, body });
  for (const ruleset of WAN_RULESETS) {
    for (const req of [create, update]) {
      await refused(wan().check(req({ ruleset, action: 'accept', dst_address: '192.0.2.10' })), new RegExp(`legacy rule on ${ruleset} with action "accept" would let traffic in from the WAN`));
      await passes(wan().check(req({ ruleset, action: 'drop' })));
      await passes(wan().check(req({ ruleset, action: 'reject' })));
    }
    // case variants and a missing action fail closed
    await refused(wan().check(create({ ruleset: ruleset.toLowerCase(), action: 'ACCEPT' })));
    await refused(wan().check(create({ ruleset })));
  }
  // not this layer's business (the guard refuses WAN_OUT accept; LAN accept has its own rules)
  await passes(wan().check(create({ ruleset: 'WAN_OUT', action: 'accept' })));
  await passes(wan().check(create({ ruleset: 'LAN_IN', action: 'accept' })));
  await passes(wan().check(create({ ruleset: 'GUESTv6_LOCAL', action: 'accept' })));
});

test('other requests are not this layer\'s business; non-object bodies on checked paths are refused', async () => {
  await passes(wan().check({ method: 'GET', path: `${CI}/firewall/policies`, body: undefined }));
  await passes(wan().check({ method: 'PUT', path: `${CC}/rest/user/${NETCONF}`, body: { use_fixedip: false } }));
  await passes(wan().check({ method: 'POST', path: `${CI}/clients/${NET}/actions`, body: { action: 'AUTHORIZE_GUEST_ACCESS' } }));
  await refused(wan().check({ method: 'POST', path: `${CC}/rest/firewallrule`, body: [] }));
  await refused(wan().check({ method: 'POST', path: `${CI}/firewall/policies`, body: 'x' }));
});

test('allowExposure turns every check off', async () => {
  const off = createWanExposure({ allowExposure: true, zoneIds: [Z_UPLINK] });
  assert.equal(off.allowExposure, true);
  await passes(off.check(policyReq('POST', policy('ALLOW', Z_EXTERNAL), {})));
  await passes(off.check({ method: 'POST', path: `${CC}/rest/firewallrule`, body: { ruleset: 'WAN_IN', action: 'accept' } }));
});

// --- through the tools ---------------------------------------------------------------

let dir;
test.before(() => {
  dir = tmpDir();
});
test.after(() => fs.rmSync(dir, { recursive: true, force: true }));

const fixtures = {
  [`${I}/firewall/zones?limit=200`]: { status: 200, body: { data: ZONES } },
  [`${I}/firewall/policies/${POLICY}`]: { status: 200, body: { id: POLICY, index: 10000, metadata: { origin: 'USER_DEFINED' }, ...policy('BLOCK', Z_EXTERNAL), loggingEnabled: false } },
  [`${I}/networks/${NET}`]: { status: 200, body: { id: NET, management: 'GATEWAY', name: 'Lab', enabled: true, vlanId: 10, metadata: { origin: 'USER_DEFINED' }, zoneId: Z_INTERNAL, mdnsForwardingEnabled: false } },
  [`${C}/rest/firewallrule/${RULE_ID}`]: {
    status: 200,
    body: { meta: { rc: 'ok' }, data: [{ _id: RULE_ID, site_id: 'x', name: 'block in', ruleset: 'WAN_LOCAL', action: 'drop', rule_index: 2000, enabled: true }] },
  },
};

async function stack({ wanExposure, internal = [Z_INTERNAL, Z_IOT, Z_EXTERNAL] } = {}) {
  const sent = [];
  const lines = [];
  const udm = createUdmClient({
    backend: 'local',
    target: { host: 'udm.test', port: 443, isIp: false, hostHeader: 'udm.test' },
    apiKey: API_KEY,
    siteId: SITE,
    allowWrites: true,
    // Guard zone config; tests (mis)configure WAN zones as internal to show the WAN layer stands on its own.
    firewallInternalZoneIds: internal,
    transport: async (req) => {
      sent.push(req);
      if (req.method !== 'GET') return { status: 200, text: '{"meta":{"rc":"ok"},"data":[]}' };
      const f = fixtures[req.path];
      return f ? { status: f.status, text: JSON.stringify(f.body) } : { status: 404, text: '{}' };
    },
  });
  const writeLog = createWriteLog({ sink: (l) => lines.push(JSON.parse(l)) });
  const server = buildMcpServer({ udmClient: udm, writeLog, ...(wanExposure ? { wanExposure } : {}) });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await server.connect(a);
  const client = new Client({ name: 'test', version: '1' });
  await client.connect(b);
  const call = async (tool, args) => {
    const r = await client.callTool({ name: tool, arguments: args });
    return { isError: Boolean(r.isError), text: r.content[0].text };
  };
  return { call, sent, writes: () => sent.filter((q) => q.method !== 'GET'), lines };
}

test('tools: ALLOW policy from the WAN is refused by default, before the guard, dry_run or not; logged as wan_exposure', async () => {
  const s = await stack();
  for (const dry_run of [true, false]) {
    const r = await s.call('unifi_rw_create_firewall_policy', { policy: policy('ALLOW', Z_EXTERNAL), dry_run });
    assert.equal(r.isError, true);
    assert.match(r.text, /^Refused: the policy would ALLOW traffic from the "External" zone, which is the WAN\./);
    assert.match(r.text, /make it in the UniFi console/);
    const l = s.lines.at(-1);
    assert.deepEqual([l.outcome, l.reason, l.method, l.endpoint, l.dry_run], ['refused', 'wan_exposure', 'POST', `${CI}/firewall/policies`, dry_run]);
  }
  // update to ALLOW of an existing WAN BLOCK policy
  const r = await s.call('unifi_rw_update_firewall_policy', { policy_id: POLICY, changes: { action: { type: 'ALLOW' } } });
  assert.match(r.text, /^Refused: the policy would ALLOW traffic from the "External" zone/);
  assert.equal(s.lines.at(-1).reason, 'wan_exposure');
  // patching only logging stays possible
  assert.equal((await s.call('unifi_rw_patch_firewall_policy', { policy_id: POLICY, loggingEnabled: true })).isError, false);
  // ALLOW between internal zones still works
  assert.equal((await s.call('unifi_rw_create_firewall_policy', { policy: { ...policy('ALLOW', Z_IOT), destination: { zoneId: Z_INTERNAL } } })).isError, false);
  assert.deepEqual(s.writes().map((q) => q.method), ['PATCH', 'POST']);
});

test('tools: a renamed WAN zone known only by id is refused even when the guard config wrongly calls it internal', async () => {
  // With this guard config and no WAN layer, the policy would be allowed: show that first.
  const unguarded = await stack({ wanExposure: createWanExposure({ allowExposure: true }), internal: [Z_INTERNAL, Z_UPLINK] });
  assert.equal((await unguarded.call('unifi_rw_create_firewall_policy', { policy: policy('ALLOW', Z_UPLINK), dry_run: true })).isError, false);
  const s = await stack({ wanExposure: createWanExposure({ zoneIds: [Z_UPLINK] }), internal: [Z_INTERNAL, Z_UPLINK] });
  const r = await s.call('unifi_rw_create_firewall_policy', { policy: policy('ALLOW', Z_UPLINK), dry_run: true });
  assert.equal(r.isError, true);
  assert.match(r.text, /^Refused: the policy would ALLOW traffic from the "Uplink" zone, which is the WAN/);
  assert.equal(s.writes().length, 0);
});

test('tools: no extra parameter gets past the refusal (strict schemas; no confirm flag exists)', async () => {
  const s = await stack();
  for (const extra of [{ confirm: true }, { force: true }, { allow_wan_exposure: true }]) {
    const r = await s
      .call('unifi_rw_create_firewall_policy', { policy: policy('ALLOW', Z_EXTERNAL), ...extra })
      .catch((e) => ({ isError: true, text: e.message }));
    assert.equal(r.isError, true, JSON.stringify(extra));
  }
  assert.equal(s.writes().length, 0);
});

test('tools: legacy WAN accept refused on create and on update (merged rule); WAN drop/reject still allowed', async () => {
  const s = await stack();
  for (const ruleset of WAN_RULESETS) {
    const r = await s.call('unifi_rw_create_legacy_firewall_rule', { rule: { name: 'in', ruleset, action: 'accept', dst_port: '443' } });
    assert.equal(r.isError, true, ruleset);
    assert.match(r.text, new RegExp(`^Refused: legacy rule on ${ruleset} with action "accept" would let traffic in from the WAN`));
    assert.equal(s.lines.at(-1).reason, 'wan_exposure');
  }
  // existing WAN_LOCAL drop rule: flipping it to accept is refused by the merged-rule check
  let r = await s.call('unifi_rw_update_legacy_firewall_rule', { rule_id: RULE_ID, changes: { action: 'accept' } });
  assert.match(r.text, /^Refused: legacy rule on WAN_LOCAL with action "accept"/);
  assert.deepEqual([s.lines.at(-1).method, s.lines.at(-1).endpoint], ['PUT', `${CC}/rest/firewallrule/${RULE_ID}`]);
  assert.equal(s.writes().length, 0);
  // drop/reject on WAN rulesets: allowed (the Sonos-era LAN rules are unaffected too)
  r = await s.call('unifi_rw_create_legacy_firewall_rule', { rule: { name: 'block telnet', ruleset: 'WAN_IN', action: 'drop', dst_port: '23' } });
  assert.equal(r.isError, false, r.text);
  r = await s.call('unifi_rw_create_legacy_firewall_rule', { rule: { name: 'reject v6', ruleset: 'WANv6_LOCAL', action: 'reject', dst_port: '23' } });
  assert.equal(r.isError, false, r.text);
  r = await s.call('unifi_rw_update_legacy_firewall_rule', { rule_id: RULE_ID, changes: { name: 'renamed' } });
  assert.equal(r.isError, false, r.text);
  assert.equal(s.writes().length, 3);
  assert.deepEqual(s.lines.slice(-3).map((l) => l.outcome), ['ok', 'ok', 'ok']);
});

test('tools: update_network keeps working; its zone never changes, so no zone lookup is needed', async () => {
  const s = await stack();
  const r = await s.call('unifi_rw_update_network', { network_id: NET, changes: { mdnsForwardingEnabled: true } });
  assert.equal(r.isError, false, r.text);
  assert.ok(!s.sent.some((q) => q.path.includes('/firewall/zones')));
});

test('tools: with UNIFI_ALLOW_WAN_EXPOSURE the layer is off, and the guard still refuses on its own', async () => {
  const s = await stack({ wanExposure: createWanExposure({ allowExposure: true }), internal: [Z_INTERNAL, Z_IOT] });
  let r = await s.call('unifi_rw_create_firewall_policy', { policy: policy('ALLOW', Z_EXTERNAL), dry_run: true });
  assert.equal(r.isError, true);
  assert.match(r.text, /Refused by guard: policy would allow WAN-in/);
  assert.equal(s.lines.at(-1).reason, 'guard');
  r = await s.call('unifi_rw_create_legacy_firewall_rule', { rule: { name: 'in', ruleset: 'WAN_IN', action: 'accept', dst_port: '443' }, dry_run: true });
  assert.match(r.text, /Refused by guard: legacy rule on WAN_IN with action "accept" would allow WAN traffic/);
  assert.equal(s.lines.at(-1).reason, 'guard');
  assert.equal(s.writes().length, 0);
});

test('tools: the refusal error class is distinct from the guard\'s', () => {
  assert.ok(!(new WanExposureError('x') instanceof GuardError));
});

// --- config and process ----------------------------------------------------------------

test('config: refusals on by default; only "true" (any case) turns them off; odd values warn', () => {
  const fw = { internalZoneIds: [Z_INTERNAL], wanZoneIds: [] };
  for (const [v, allow] of [[undefined, false], ['', false], ['false', false], ['true', true], [' TRUE ', true]]) {
    const warnings = [];
    assert.equal(resolveWanExposure(v === undefined ? {} : { UNIFI_ALLOW_WAN_EXPOSURE: v }, fw, warnings).allowExposure, allow, String(v));
    assert.deepEqual(warnings, []);
  }
  for (const v of ['1', 'yes', 'on']) {
    const warnings = [];
    assert.equal(resolveWanExposure({ UNIFI_ALLOW_WAN_EXPOSURE: v }, fw, warnings).allowExposure, false, v);
    assert.match(warnings[0], /UNIFI_ALLOW_WAN_EXPOSURE has an unrecognised value .*refusals stay on/);
  }
});

test('config: UNIFI_WAN_ZONE_IDS adds to firewall_wan_zone_ids; bad ids and internal overlaps are errors', () => {
  const cfg = validateConfig(
    { console_id: CONSOLE, allow_writes: true, firewall_internal_zone_ids: [Z_INTERNAL], firewall_wan_zone_ids: [Z_EXTERNAL] },
    { env: { UNIFI_WAN_ZONE_IDS: ` ${Z_UPLINK.toUpperCase()} , ${Z_EXTERNAL},` } }
  );
  assert.deepEqual(cfg.wanExposure, { allowExposure: false, zoneIds: [Z_EXTERNAL, Z_UPLINK] });
  assert.deepEqual(validateConfig({ console_id: CONSOLE }, { env: {} }).wanExposure, { allowExposure: false, zoneIds: [] });
  assert.throws(() => validateConfig({ console_id: CONSOLE }, { env: { UNIFI_WAN_ZONE_IDS: 'External' } }), (e) => e instanceof ConfigError && /UNIFI_WAN_ZONE_IDS must be a comma-separated list of firewall zone UUIDs/.test(e.message));
  assert.throws(() => validateConfig({ console_id: CONSOLE, firewall_internal_zone_ids: [Z_INTERNAL] }, { env: { UNIFI_WAN_ZONE_IDS: Z_INTERNAL } }), /in both UNIFI_WAN_ZONE_IDS and firewall_internal_zone_ids/);
});

test('server process: UNIFI_ALLOW_WAN_EXPOSURE=true is reported at startup', async () => {
  const s = await spawnServer(dir, 'proc-wan-off', { config: { console_id: CONSOLE, site_id: SITE, allow_writes: true }, env: { UNIFI_ALLOW_WAN_EXPOSURE: 'true' } });
  try {
    assert.equal(await s.started, true, s.stderr());
    await rpc(s.port, s.token, 'tools/list');
    assert.match(s.stderr(), /write safeguards: write_tools=all write_log=off wan_exposure=allowed/);
    assert.match(s.stderr(), /warning: WAN-exposure refusals are off \(UNIFI_ALLOW_WAN_EXPOSURE=true\)/);
  } finally {
    s.child.kill('SIGTERM');
    await s.exited;
  }
  const bad = await spawnServer(dir, 'proc-wan-bad-ids', { config: { console_id: CONSOLE, site_id: SITE, allow_writes: true }, env: { UNIFI_WAN_ZONE_IDS: 'wan' } });
  assert.equal(await bad.started, false);
  assert.deepEqual(await bad.exited, { code: 2, signal: null });
  assert.match(bad.stderr(), /refusing to start: UNIFI_WAN_ZONE_IDS must be/);
});

test('package: the new modules are shipped (covered by "files")', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
  for (const f of ['lib/wan-exposure.cjs', 'lib/write-log.cjs', 'lib/tool-names.cjs']) assert.ok(pkg.files.some((e) => f.startsWith(e)), f);
});
