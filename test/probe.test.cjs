'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { validateConfig } = require('../lib/config.cjs');
const { createUdmClient, PROBE_READ_ONLY } = require('../lib/udm-client.cjs');
const { GuardError } = require('../lib/guard.cjs');
const { registerTools } = require('../lib/tools.cjs');
const { runProbe, buildProbeClient, parseArgs } = require('../scripts/probe-classic.cjs');
const { tmpDir } = require('./helpers.cjs');

const CONSOLE = '942A6FF664C0000000000964970E0000000009E710560000000068A9873F:9999999999';
const SITE = '88f7af54-98f8-306a-a1c7-c9349722b1f6';
// Alphanumeric on purpose: it is a printable key name, so only the scrubber stops it.
const API_KEY = 'probeSiteManagerKey0123456789abcdefXYZ';
const TOKEN = 'probe-bearer-token-0123456789abcdef0123456789';
const PREFIX = `/v1/connector/consoles/${CONSOLE}/proxy/network`;
const SCRIPT = path.join(__dirname, '..', 'scripts', 'probe-classic.cjs');
const HEX = (n) => String(n).padStart(24, 'a');

// Values that must never appear in probe output.
const SECRET_VALUES = ['Alex-iPhone', 'Living Room AP', 'Office Switch', 'hunter2-wifi-pass', 'radius-secret-xyz', 'Block Telnet', 'kids tablet', 'Trusted Hosts', 'garage-cam'];
const ok = (data) => ({ status: 200, body: { meta: { rc: 'ok' }, data } });

const ROUTES = {
  '/integration/v1/sites?limit=200': { status: 200, body: { offset: 0, limit: 200, count: 1, totalCount: 1, data: [{ id: SITE, internalReference: 'default', name: 'Default' }] } },
  '/api/s/default/rest/firewallrule': ok([
    { _id: HEX(1), name: 'Block Telnet', ruleset: 'WAN_IN', action: 'drop', src_address: '203.0.113.7', dst_port: '23', enabled: true },
    { _id: HEX(2), name: 'x', ruleset: 'WAN_IN', action: 'drop', src_mac_address: 'aa:bb:cc:dd:ee:01' },
    { _id: HEX(3), name: 'y', ruleset: 'WAN_IN', action: 'drop', dst_address: '192.168.1.10' },
    { _id: HEX(4), name: 'z', ruleset: 'LAN_IN', action: 'accept', src_networkconf_id: HEX(9) },
    { _id: HEX(5), name: 'garage-cam', ruleset: 'Alex-iPhone', action: '10.0.0.1' },
    { _id: HEX(6), [API_KEY]: 1, ruleset: 'GUEST_LOCAL', action: 'reject', 'weird key with spaces': 1, '10.1.2.3': 1 },
  ]),
  '/api/s/default/rest/firewallgroup': ok([{ _id: HEX(7), name: 'Trusted Hosts', group_type: 'address-group', group_members: ['192.168.1.2', '192.168.1.3'] }]),
  '/api/s/default/rest/networkconf': ok([
    { _id: HEX(9), name: 'Trusted Hosts', purpose: 'corporate', ip_subnet: '192.168.1.1/24', vlan: 42 },
    { _id: HEX(8), name: 'garage-cam', purpose: 'wan', wan_ip: '203.0.113.9' },
    { _id: HEX(13), name: 'x', purpose: 'Alex-iPhone' },
  ]),
  '/api/s/default/rest/user': ok([
    { _id: HEX(10), mac: '11:22:33:44:55:66', name: 'Alex-iPhone', hostname: 'Alex-iPhone', use_fixedip: true, fixed_ip: '192.168.1.50', network_id: HEX(9) },
    { _id: HEX(11), mac: '11:22:33:44:55:67', name: 'kids tablet', note: 'hunter2-wifi-pass' },
    { _id: HEX(12), mac: '11:22:33:44:55:68', use_fixedip: false, x_passphrase: 'hunter2-wifi-pass' },
  ]),
  '/api/s/default/stat/device': ok([
    {
      _id: HEX(20), mac: 'f0:9f:c2:00:00:01', ip: '192.168.1.20', name: 'Living Room AP', type: 'uap', model: 'U6LR',
      radio_table: [{ radio: 'ng', name: 'wifi0', channel: 6, ht: 20 }, { radio: 'na', name: 'wifi1', channel: 36, ht: 80, antenna_gain: 3 }],
      x_authkey: 'radius-secret-xyz',
    },
    { _id: HEX(21), mac: 'f0:9f:c2:00:00:02', name: 'garage-cam', type: 'uap', radio_table: [{ radio: 'ng' }, { radio: 'na' }, { radio: '6e', min_rssi: -80 }] },
    { _id: HEX(22), mac: 'f0:9f:c2:00:00:03', ip: '192.168.1.2', name: 'Office Switch', type: 'usw', port_table: [{ name: 'Port 1' }] },
  ]),
  [`/integration/v1/sites/${SITE}/firewall/policies?limit=200`]: { status: 400, body: { statusCode: 400, code: 'api.firewall.zone-based-firewall-not-configured', message: 'Zone Based Firewall is not configured' } },
  [`/integration/v1/sites/${SITE}/firewall/zones?limit=200`]: { status: 400, body: { statusCode: 400, code: 'api.firewall.zone-based-firewall-not-configured', message: 'Zone Based Firewall is not configured' } },
  [`/integration/v1/sites/${SITE}/acl-rules?limit=200`]: { status: 200, body: { offset: 0, limit: 200, count: 0, totalCount: 0, data: [] } },
  [`/integration/v1/sites/${SITE}/devices?limit=200`]: {
    status: 200,
    body: { offset: 0, limit: 200, count: 1, totalCount: 3, data: [{ id: SITE, macAddress: 'f0:9f:c2:00:00:01', ipAddress: '192.168.1.20', name: 'Living Room AP', model: 'U6LR', state: 'ONLINE' }] },
  },
  [`/integration/v1/sites/${SITE}/clients?limit=5`]: {
    status: 200,
    body: { offset: 0, limit: 5, count: 1, totalCount: 42, data: [{ id: SITE, name: 'Alex-iPhone', macAddress: '11:22:33:44:55:66', ipAddress: '192.168.1.50', type: 'WIRELESS' }] },
  },
};

const EXPECTED_PATHS = [
  '/integration/v1/sites?limit=200',
  '/api/s/default/rest/firewallrule',
  '/api/s/default/rest/firewallgroup',
  '/api/s/default/rest/networkconf',
  '/api/s/default/rest/user',
  '/api/s/default/stat/device',
  `/integration/v1/sites/${SITE}/firewall/policies?limit=200`,
  `/integration/v1/sites/${SITE}/firewall/zones?limit=200`,
  `/integration/v1/sites/${SITE}/acl-rules?limit=200`,
  `/integration/v1/sites/${SITE}/devices?limit=200`,
  `/integration/v1/sites/${SITE}/clients?limit=5`,
];

const cloudCfg = (extra = {}) => validateConfig({ console_id: CONSOLE, ...extra });

function fakeTransport(sent, { prefix = PREFIX, routes = ROUTES } = {}) {
  return async (req) => {
    sent.push(req);
    assert.ok(req.path.startsWith(prefix), req.path);
    const r = routes[req.path.slice(prefix.length)];
    if (!r) return { status: 404, headers: {}, text: '{"message":"not found"}' };
    return { status: r.status, headers: {}, text: JSON.stringify(r.body) };
  };
}

async function probeLines(cfg, transport) {
  const lines = [];
  const client = buildProbeClient(cfg, { apiKey: API_KEY }, { transport });
  const res = await runProbe(client, { siteId: cfg.siteId, secrets: [TOKEN, API_KEY], write: (l) => lines.push(l) });
  return { lines, ...res };
}

function assertClean(text) {
  assert.ok(!text.includes(API_KEY), 'API key leaked');
  assert.ok(!text.includes(TOKEN), 'token leaked');
  assert.doesNotMatch(text, /([0-9a-f]{2}:){5}/i, 'MAC-like value leaked');
  assert.doesNotMatch(text, /\b\d{1,3}(\.\d{1,3}){3}\b/, 'IPv4 leaked');
  for (const v of SECRET_VALUES) assert.ok(!text.includes(v), `${v} leaked`);
}

test('probe (cloud, cloud_allow_classic off): only GETs, exact paths, through the connector prefix', async () => {
  const sent = [];
  const cfg = cloudCfg();
  assert.deepEqual([...cfg.cloud.classicCapabilities], []);
  const { lines, complete } = await probeLines(cfg, fakeTransport(sent));
  assert.equal(complete, true);
  assert.deepEqual(sent.map((r) => r.method), EXPECTED_PATHS.map(() => 'GET'));
  assert.deepEqual(sent.map((r) => r.path), EXPECTED_PATHS.map((p) => PREFIX + p));
  for (const r of sent) {
    assert.equal(r.body, undefined);
    assert.equal(r.headers['X-API-KEY'], API_KEY);
  }
  assert.equal(lines.length, EXPECTED_PATHS.length + 2);
  for (const [i, p] of EXPECTED_PATHS.entries()) assert.ok(lines[i + 1].startsWith(`GET ${p} `), lines[i + 1]);
});

test('probe output: shapes only; no key, token, MACs, IPs, names, passphrases', async () => {
  const { lines } = await probeLines(cloudCfg(), fakeTransport([]));
  const text = lines.join('\n');
  assertClean(text);
  const line = (p) => lines.find((l) => l.startsWith(`GET ${p} `));
  const fw = line('/api/s/default/rest/firewallrule');
  assert.match(fw, / 200 meta\.rc=ok count=6 keys=\[/);
  assert.match(fw, /rules=\{GUEST_LOCAL:reject=1,LAN_IN:accept=1,WAN_IN:drop=3,other:other=1\}/);
  assert.match(fw, /keys=\[_id,action,dst_address,dst_port,enabled,name,\[REDACTED\],ruleset,src_address,src_mac_address,src_networkconf_id,\+2 unprintable\]/);
  assert.match(line('/api/s/default/rest/firewallgroup'), / 200 meta\.rc=ok count=1 keys=\[_id,group_members,group_type,name\] group_types=\{address-group=1\}$/);
  assert.match(line('/api/s/default/rest/networkconf'), / 200 meta\.rc=ok count=3 keys=\[_id,ip_subnet,name,purpose,vlan,wan_ip\] purposes=\{corporate=1,other=1,wan=1\}$/);
  const user = line('/api/s/default/rest/user');
  assert.match(user, /count=3 keys=\[_id,fixed_ip,hostname,mac,name,network_id,note,use_fixedip,x_passphrase\] use_fixedip=1$/);
  const dev = line('/api/s/default/stat/device');
  assert.match(dev, /count=3 /);
  assert.match(dev, /types=\{uap=2,usw=1\}/);
  assert.match(dev, /uap_radio_table_keys=\[antenna_gain,channel,ht,min_rssi,name,radio\]/);
  assert.match(dev, /uap_radios=\{6e=1,na=2,ng=2\}/);
  assert.match(dev, /uap_without_radio_table=0/);
  assert.match(line(`/integration/v1/sites/${SITE}/firewall/policies?limit=200`), / 400 code=api\.firewall\.zone-based-firewall-not-configured$/);
  assert.match(line(`/integration/v1/sites/${SITE}/clients?limit=5`), / 200 count=1 totalCount=42 keys=\[id,ipAddress,macAddress,name,type\]$/);
  assert.match(line(`/integration/v1/sites/${SITE}/acl-rules?limit=200`), / 200 count=0 totalCount=0 keys=\[\]$/);
  assert.match(line('/integration/v1/sites?limit=200'), / 200 count=1 totalCount=1 keys=\[id,internalReference,name\]$/);
  assert.doesNotMatch(text, /Zone Based Firewall is not configured|not found/);
});

test('probe: non-2xx is still "completed"; transport errors are masked and make it incomplete', async () => {
  const sent = [];
  const four04 = await probeLines(cloudCfg(), fakeTransport(sent, { routes: { '/integration/v1/sites?limit=200': ROUTES['/integration/v1/sites?limit=200'] } }));
  assert.equal(four04.complete, true);
  assert.equal(four04.lines.filter((l) => / 404( |$)/.test(l)).length, EXPECTED_PATHS.length - 1);
  const failing = async () => {
    throw new Error(`connect ECONNREFUSED 192.168.1.1:443 aa:bb:cc:dd:ee:ff ${API_KEY} ${TOKEN}`);
  };
  const { lines, complete } = await probeLines(cloudCfg({ site_id: SITE }), failing);
  assert.equal(complete, false);
  assertClean(lines.join('\n'));
  assert.match(lines[1], /^GET \/integration\/v1\/sites\?limit=200 ERROR connect ECONNREFUSED \[REDACTED\]:443 \[REDACTED\] \[REDACTED\] \[REDACTED\]$/);
  assert.match(lines.at(-1), /some requests did not complete/);
  // no site resolvable: site-scoped requests are skipped, not guessed
  const none = await probeLines(cloudCfg(), fakeTransport([], { routes: { '/integration/v1/sites?limit=200': { status: 200, body: { data: [] } } } }));
  assert.equal(none.complete, false);
  assert.equal(none.lines.filter((l) => /SKIPPED site id unresolved/.test(l)).length, 5);
});

test('probe: local backend uses /proxy/network and the same output rules', async () => {
  const sent = [];
  const cfg = validateConfig({ backend: 'local', local_host: 'udm.lan', site_id: SITE });
  const { lines, complete } = await probeLines(cfg, fakeTransport(sent, { prefix: '/proxy/network' }));
  assert.equal(complete, true);
  assert.deepEqual(sent.map((r) => r.path), EXPECTED_PATHS.map((p) => `/proxy/network${p}`));
  assertClean(lines.join('\n'));
});

test('probe client refuses POST/PUT/PATCH/DELETE (also dry runs) before anything is sent; GETs stay guarded', async () => {
  const HX = '5f1e2d3c4b5a69788796a5b4';
  const writes = [
    { method: 'POST', path: `/integration/v1/sites/${SITE}/clients/${SITE}/actions`, body: { action: 'UNAUTHORIZE_GUEST_ACCESS' } },
    { method: 'PUT', path: `/api/s/default/rest/user/${HX}`, body: { use_fixedip: false } },
    { method: 'POST', path: '/api/s/default/rest/firewallrule', body: { name: 'r', ruleset: 'LAN_IN', action: 'drop' } },
    { method: 'PATCH', path: `/integration/v1/sites/${SITE}/firewall/policies/${SITE}`, body: { loggingEnabled: true }, context: { existing: { id: SITE } } },
    { method: 'DELETE', path: `/api/s/default/rest/firewallrule/${HX}` },
    { method: 'get', path: '/integration/v1/info' },
  ];
  for (const cfg of [cloudCfg(), cloudCfg({ cloud_allow_classic: true }), validateConfig({ backend: 'local', local_host: 'udm.lan' })]) {
    const sent = [];
    const client = buildProbeClient(cfg, { apiKey: API_KEY }, { transport: fakeTransport(sent, { prefix: cfg.backend === 'cloud' ? PREFIX : '/proxy/network' }) });
    assert.equal(client.probeReadOnly, true);
    for (const req of writes) {
      for (const dryRun of [false, true]) {
        await assert.rejects(client.request({ ...req, dryRun }), (e) => e instanceof GuardError && /probe client is read-only/.test(e.message), `${req.method} ${req.path}`);
      }
    }
    // still the guard allowlist / deny list for GETs
    for (const p of ['/api/s/default/stat/sta', '/api/s/default/cmd/devmgr', '/api/s/default/rest/setting', '/api/s/default/rest/portforward', '/integration/v1/sites/x/devices']) {
      await assert.rejects(client.request({ method: 'GET', path: p }), GuardError, p);
    }
    assert.equal(sent.length, 0);
    // and probe clients cannot back MCP tools
    assert.throws(() => registerTools(new McpServer({ name: 't', version: '1' }), { client }), /probe client/);
  }
});

test('probe-only option: only GET on classic paths is unlocked; a normal cloud client still refuses them', async () => {
  const sent = [];
  const normal = createUdmClient({ backend: 'cloud', consoleId: CONSOLE, apiKey: API_KEY, transport: fakeTransport(sent) });
  await assert.rejects(normal.request({ method: 'GET', path: '/api/s/default/rest/firewallgroup' }), /capability "firewallrule" is not enabled/);
  // the option is keyed by a Symbol only; a string key with the same description does nothing
  const fake = createUdmClient({ backend: 'cloud', consoleId: CONSOLE, apiKey: API_KEY, transport: fakeTransport(sent), [String(PROBE_READ_ONLY)]: true, probeReadOnly: true });
  assert.equal(fake.probeReadOnly, false);
  await assert.rejects(fake.request({ method: 'GET', path: '/api/s/default/rest/user' }), /capability "fixed_ip" is not enabled/);
  assert.equal(sent.length, 0);
  const probe = createUdmClient({ backend: 'cloud', consoleId: CONSOLE, apiKey: API_KEY, transport: fakeTransport(sent), [PROBE_READ_ONLY]: true });
  await probe.request({ method: 'GET', path: '/api/s/default/rest/user' });
  assert.equal(sent.length, 1);
  // not reachable from config or the server's main()
  assert.equal(typeof PROBE_READ_ONLY, 'symbol');
  const main = fs.readFileSync(path.join(__dirname, '..', 'http-server-rw.cjs'), 'utf8');
  assert.doesNotMatch(main, /PROBE_READ_ONLY|probe/i);
  assert.doesNotMatch(fs.readFileSync(path.join(__dirname, '..', 'lib', 'config.cjs'), 'utf8'), /PROBE_READ_ONLY/);
});

test('probe CLI: argument parsing and config / secret-file errors exit 2 without contacting anything', () => {
  assert.equal(parseArgs(['--config', '/x/c.json']).configPath, '/x/c.json');
  for (const bad of [['--config'], ['--bogus'], ['x'], ['--config', '']]) assert.throws(() => parseArgs(bad), /usage/);

  const dir = tmpDir();
  try {
    const run = (args) => spawnSync(process.execPath, [SCRIPT, ...args], { encoding: 'utf8', env: { ...process.env, UNIFI_MCP_RW_CONFIG: path.join(dir, 'none.json') }, timeout: 20_000 });
    let r = run(['--config', path.join(dir, 'missing.json')]);
    assert.equal(r.status, 2, r.stderr);
    assert.match(r.stderr, /cannot read config/);
    assert.equal(r.stdout, '');
    r = run(['--nope']);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /usage/);
    r = run([]);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /none\.json/);

    const key = path.join(dir, 'cloud-rw-key');
    const token = path.join(dir, 'mcp-rw-token');
    fs.writeFileSync(key, API_KEY, { mode: 0o644 });
    fs.chmodSync(key, 0o644);
    fs.writeFileSync(token, TOKEN, { mode: 0o600 });
    const cfgPath = path.join(dir, 'config.json');
    fs.writeFileSync(cfgPath, JSON.stringify({ console_id: CONSOLE, cloud_rw_key_file: key, rw_token_file: token }));
    r = run(['--config', cfgPath]);
    assert.equal(r.status, 2, r.stderr);
    assert.match(r.stderr, /mode 0600/);
    assert.ok(!r.stderr.includes(API_KEY) && !r.stdout.includes(API_KEY));
    fs.writeFileSync(cfgPath, JSON.stringify({ console_id: CONSOLE, cloud_allow_classic: ['bogus'] }));
    r = run(['--config', cfgPath]);
    assert.equal(r.status, 2);
    assert.match(r.stderr, /cloud_allow_classic has unknown capability "bogus"/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('npm scripts: test runs only *.test.cjs files; probe runs the probe script', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
  assert.equal(pkg.scripts.test, 'node --test test/*.test.cjs');
  assert.equal(pkg.scripts.probe, 'node scripts/probe-classic.cjs');
  assert.ok(!/\.test\.cjs$/.test('helpers.cjs'));
  const out = execFileSync(process.execPath, ['--check', SCRIPT], { encoding: 'utf8' });
  assert.equal(out, '');
});
