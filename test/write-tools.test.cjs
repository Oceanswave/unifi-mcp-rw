'use strict';

// UNIFI_WRITE_TOOLS: the write-tool allowlist (lib/tool-names.cjs, config, registration, server process).

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { InMemoryTransport } = require('@modelcontextprotocol/sdk/inMemory.js');
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { buildMcpServer } = require('../http-server-rw.cjs');
const { createUdmClient } = require('../lib/udm-client.cjs');
const { validateConfig, resolveWriteTools, ConfigError } = require('../lib/config.cjs');
const { READ_TOOLS, WRITE_TOOLS, parseWriteTools } = require('../lib/tool-names.cjs');
const tools = require('../lib/tools.cjs');
const { tmpDir, rpc, spawnServer } = require('./helpers.cjs');

const SITE = '00000000-0000-4000-8000-000000000001';
const CONSOLE = 'FAKECONSOLE00000000:0000';
const API_KEY = 'fake-key-0000-0000-0000-0000';

// The minimum allowlist ("Minimum allowlist" in README.md).
const MINIMAL_ALLOWLIST =
  'unifi_rw_create_wifi_broadcast,unifi_rw_update_wifi_broadcast,unifi_rw_update_network,unifi_rw_create_legacy_firewall_rule,unifi_rw_update_legacy_firewall_rule,unifi_rw_set_fixed_ip,unifi_rw_clear_fixed_ip';
const MINIMAL_TOOLS = MINIMAL_ALLOWLIST.split(',');
const NOT_IN_MINIMAL = [
  'unifi_rw_authorize_guest',
  'unifi_rw_unauthorize_guest',
  'unifi_rw_create_firewall_policy',
  'unifi_rw_update_firewall_policy',
  'unifi_rw_patch_firewall_policy',
  'unifi_rw_update_ap_radios',
];

let dir;
test.before(() => {
  dir = tmpDir();
});
test.after(() => fs.rmSync(dir, { recursive: true, force: true }));

const noSend = async () => {
  throw new Error('must not send');
};
const localClient = (extra = {}) =>
  createUdmClient({ backend: 'local', target: { host: 'udm.test', port: 443, isIp: false, hostHeader: 'udm.test' }, apiKey: API_KEY, siteId: SITE, allowWrites: true, transport: noSend, ...extra });

async function listed(opts) {
  const server = buildMcpServer(opts);
  const [a, b] = InMemoryTransport.createLinkedPair();
  await server.connect(a);
  const c = new Client({ name: 'test', version: '1' });
  await c.connect(b);
  return { names: (await c.listTools()).tools.map((t) => t.name).sort(), client: c };
}

test('tool-names: one canonical list, disjoint from the read tools, matching what tools.cjs exports', () => {
  assert.equal(new Set(WRITE_TOOLS).size, WRITE_TOOLS.length);
  assert.ok(WRITE_TOOLS.every((n) => !READ_TOOLS.includes(n)));
  assert.equal(tools.WRITE_TOOLS, WRITE_TOOLS);
  assert.equal(tools.READ_TOOLS, READ_TOOLS);
  assert.ok(READ_TOOLS.every((n) => /^unifi_rw_(list|get)_/.test(n)));
  assert.ok(READ_TOOLS.includes('unifi_rw_list_fixed_ips'));
  assert.ok(Object.isFrozen(WRITE_TOOLS) && Object.isFrozen(READ_TOOLS));
});

test('tool-names: every tool tools.cjs registers is in exactly one list (registration throws otherwise)', async () => {
  const registered = [];
  const fake = { registerTool: (name, cfg) => registered.push({ name, readOnly: cfg.annotations.readOnlyHint }) };
  tools.registerTools(fake, { client: localClient() });
  assert.deepEqual(registered.map((r) => r.name).sort(), [...READ_TOOLS, ...WRITE_TOOLS].sort());
  for (const r of registered) assert.equal(r.readOnly, READ_TOOLS.includes(r.name), r.name);
});

test('parseWriteTools: comma-separated, whitespace-trimmed, de-duplicated, in canonical order', () => {
  assert.deepEqual(parseWriteTools(' unifi_rw_update_network ,\tunifi_rw_set_fixed_ip,,unifi_rw_update_network '), {
    tools: ['unifi_rw_set_fixed_ip', 'unifi_rw_update_network'],
    readTools: [],
    unknown: [],
  });
  assert.deepEqual(parseWriteTools(''), { tools: [], readTools: [], unknown: [] });
  assert.deepEqual(parseWriteTools(' , '), { tools: [], readTools: [], unknown: [] });
  assert.deepEqual(parseWriteTools(' None '), { tools: [], readTools: [], unknown: [] });
  const r = parseWriteTools('unifi_rw_list_fixed_ips,unifi_rw_delete_network,unifi_rw_set_fixed_ip,UNIFI_RW_SET_FIXED_IP');
  assert.deepEqual(r.tools, ['unifi_rw_set_fixed_ip']);
  assert.deepEqual(r.readTools, ['unifi_rw_list_fixed_ips']);
  // names are case-sensitive, like MCP tool names
  assert.deepEqual(r.unknown, ['unifi_rw_delete_network', 'UNIFI_RW_SET_FIXED_IP']);
  // "none" only means none on its own
  assert.deepEqual(parseWriteTools('none,unifi_rw_set_fixed_ip').unknown, ['none']);
});

test('config: unset UNIFI_WRITE_TOOLS registers every write tool (upstream behaviour)', () => {
  assert.equal(resolveWriteTools({}), null);
  assert.equal(validateConfig({ console_id: CONSOLE, allow_writes: true }, { env: {} }).writeTools, null);
});

test('config: the minimum allowlist is accepted as-is, with or without spaces', () => {
  const cfg = validateConfig({ console_id: CONSOLE, allow_writes: true }, { env: { UNIFI_WRITE_TOOLS: MINIMAL_ALLOWLIST } });
  assert.deepEqual([...cfg.writeTools].sort(), [...MINIMAL_TOOLS].sort());
  assert.deepEqual(cfg.warnings.filter((w) => /WRITE_TOOLS/.test(w)), []);
  const spaced = validateConfig({ console_id: CONSOLE, allow_writes: true }, { env: { UNIFI_WRITE_TOOLS: MINIMAL_TOOLS.join(' ,  ') } });
  assert.deepEqual(spaced.writeTools, cfg.writeTools);
});

test('config: "" and "none" enable no write tools', () => {
  for (const v of ['', 'none', 'NONE']) assert.deepEqual(validateConfig({ console_id: CONSOLE, allow_writes: true }, { env: { UNIFI_WRITE_TOOLS: v } }).writeTools, [], v);
});

test('config: an unknown name or a read tool name is a startup error listing the valid write tool names', () => {
  const check = (value, re) =>
    assert.throws(
      () => validateConfig({ console_id: CONSOLE, allow_writes: true }, { env: { UNIFI_WRITE_TOOLS: value } }),
      (e) => {
        assert.ok(e instanceof ConfigError);
        assert.match(e.message, re);
        assert.match(e.message, /Valid write tool names: /);
        for (const n of WRITE_TOOLS) assert.ok(e.message.includes(n), n);
        return true;
      }
    );
  check('unifi_rw_delete_network', /UNIFI_WRITE_TOOLS: unknown name unifi_rw_delete_network\./);
  check('unifi_rw_set_fixed_ip,unifi_rw_list_fixed_ips', /unifi_rw_list_fixed_ips is a read tool \(read tools are always registered/);
  check('unifi_rw_get_info,unifi_rw_list_sites,bogus', /unifi_rw_get_info, unifi_rw_list_sites are read tools.*; unknown name bogus/);
});

test('config: in read-only mode UNIFI_WRITE_TOOLS is still validated, then ignored with a warning', () => {
  assert.throws(() => validateConfig({ console_id: CONSOLE }, { env: { UNIFI_WRITE_TOOLS: 'typo' } }), ConfigError);
  const cfg = validateConfig({ console_id: CONSOLE }, { env: { UNIFI_WRITE_TOOLS: MINIMAL_ALLOWLIST } });
  assert.equal(cfg.allowWrites, false);
  assert.equal(cfg.writeTools, null);
  assert.ok(cfg.warnings.some((w) => /UNIFI_WRITE_TOOLS ignored: the server is read-only/.test(w)));
});

test('toolNamesFor: write tools narrowed by writeTools; read tools never are', () => {
  const all = ['firewallrule', 'fixed_ip', 'radio'];
  assert.deepEqual(tools.toolNamesFor({ classicCapabilities: all, writesEnabled: true, writeTools: [] }), [...READ_TOOLS]);
  assert.deepEqual(tools.toolNamesFor({ classicCapabilities: all, writesEnabled: true, writeTools: null }), [...READ_TOOLS, ...WRITE_TOOLS]);
  assert.deepEqual(tools.toolNamesFor({ classicCapabilities: all, writesEnabled: false, writeTools: MINIMAL_TOOLS }), [...READ_TOOLS]);
  // classic capability gating still applies to listed tools
  const got = tools.toolNamesFor({ classicCapabilities: [], writesEnabled: true, writeTools: MINIMAL_TOOLS });
  assert.ok(!got.includes('unifi_rw_set_fixed_ip') && !got.includes('unifi_rw_list_fixed_ips') && got.includes('unifi_rw_update_network'));
});

test('registerTools refuses a writeTools list containing anything but write tools', () => {
  const server = new McpServer({ name: 't', version: '1' }, { capabilities: { tools: {} } });
  assert.throws(() => tools.registerTools(server, { client: localClient(), writeTools: ['unifi_rw_list_fixed_ips'] }), /writeTools must list write tools only/);
  assert.throws(() => tools.registerTools(server, { client: localClient(), writeTools: 'unifi_rw_set_fixed_ip' }), /writeTools must list write tools only/);
});

test('minimum allowlist: exactly those 7 writes plus every read tool are registered (local backend)', async () => {
  const cfg = validateConfig({ backend: 'local', local_host: '192.0.2.1', allow_writes: true }, { env: { UNIFI_WRITE_TOOLS: MINIMAL_ALLOWLIST } });
  const { names, client } = await listed({ udmClient: localClient(), writeTools: cfg.writeTools });
  assert.deepEqual(names, [...READ_TOOLS, ...MINIMAL_TOOLS].sort());
  for (const n of NOT_IN_MINIMAL) assert.ok(!names.includes(n), n);
  assert.ok(names.includes('unifi_rw_list_fixed_ips'));
  // an unregistered write tool cannot be called, dry_run or not
  for (const name of NOT_IN_MINIMAL) {
    const r = await client.callTool({ name, arguments: { dry_run: true } }).catch((e) => ({ isError: true, content: [{ text: e.message }] }));
    assert.equal(r.isError, true, name);
    assert.match(r.content[0].text, /not found/i, name);
  }
});

test('"none": only read tools; unset: every tool', async () => {
  assert.deepEqual((await listed({ udmClient: localClient(), writeTools: [] })).names, [...READ_TOOLS].sort());
  assert.deepEqual((await listed({ udmClient: localClient() })).names, [...READ_TOOLS, ...WRITE_TOOLS].sort());
});

test('server process: the minimum allowlist starts cleanly and tools/list is exactly the 7 writes plus all read tools', async () => {
  const s = await spawnServer(dir, 'proc-minimal', {
    config: { console_id: CONSOLE, site_id: SITE, cloud_allow_classic: true, allow_writes: true },
    env: { UNIFI_WRITE_TOOLS: MINIMAL_ALLOWLIST },
  });
  try {
    assert.equal(await s.started, true, s.stderr());
    const r = await rpc(s.port, s.token, 'tools/list');
    assert.equal(r.status, 200);
    const names = r.json.result.tools.map((t) => t.name).sort();
    assert.deepEqual(names, [...READ_TOOLS, ...MINIMAL_TOOLS].sort());
    for (const n of NOT_IN_MINIMAL) assert.ok(!names.includes(n), n);
    assert.match(s.stderr(), new RegExp(`write safeguards: write_tools=${MINIMAL_TOOLS.slice().sort((a, b) => WRITE_TOOLS.indexOf(a) - WRITE_TOOLS.indexOf(b)).join(',')} write_log=off wan_exposure=refused`));
    assert.doesNotMatch(s.stderr(), /refusing|UNIFI_WRITE_TOOLS/);
  } finally {
    s.child.kill('SIGTERM');
    assert.equal((await s.exited).code, 0);
  }
});

test('server process: an unknown write tool name exits 2 with one line listing the valid names', async () => {
  const s = await spawnServer(dir, 'proc-bad-tools', {
    config: { console_id: CONSOLE, site_id: SITE, allow_writes: true },
    env: { UNIFI_WRITE_TOOLS: 'unifi_rw_set_fixed_ip, unifi_rw_delete_everything' },
  });
  assert.equal(await s.started, false);
  assert.deepEqual(await s.exited, { code: 2, signal: null });
  const lines = s.stderr().trim().split('\n');
  assert.equal(lines.length, 1, s.stderr());
  assert.match(lines[0], /^unifi-mcp-rw: refusing to start: UNIFI_WRITE_TOOLS: unknown name unifi_rw_delete_everything\. Valid write tool names: unifi_rw_create_wifi_broadcast, /);
});

test('server process: a read tool name in UNIFI_WRITE_TOOLS exits 2', async () => {
  const s = await spawnServer(dir, 'proc-read-in-tools', {
    config: { console_id: CONSOLE, site_id: SITE, allow_writes: true },
    env: { UNIFI_WRITE_TOOLS: 'unifi_rw_list_fixed_ips' },
  });
  assert.equal(await s.started, false);
  assert.deepEqual(await s.exited, { code: 2, signal: null });
  assert.match(s.stderr(), /unifi_rw_list_fixed_ips is a read tool/);
});
