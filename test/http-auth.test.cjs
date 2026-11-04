'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const a = require('../lib/http-auth.cjs');

const P = 'mcp-host.example.ts.net';

test('without MCP_PUBLIC_HOST only loopback is allowed', () => {
  assert.deepEqual(a.defaultAllowedHosts(), ['localhost:18778', '127.0.0.1:18778']);
  assert.deepEqual(a.defaultAllowedOrigins(), ['http://localhost:18778', 'http://127.0.0.1:18778']);
});

test('MCP_PUBLIC_HOST must be a bare DNS name', () => {
  assert.equal(a.parsePublicHost(undefined), null);
  assert.equal(a.parsePublicHost(''), null);
  assert.equal(a.parsePublicHost('MCP-Host.Example.ts.net'), P);
  for (const bad of ['https://mcp-host.example.ts.net', 'mcp-host.example.ts.net:443', 'mcp-host.example.ts.net/x', 'localhost', 'a b.example', '-x.example.com']) {
    assert.throws(() => a.parsePublicHost(bad), /MCP_PUBLIC_HOST/, bad);
  }
});

test('host allowlist with a public host is exactly the spec list', () => {
  assert.deepEqual(a.defaultAllowedHosts(18778, P), [
    'localhost:18778',
    '127.0.0.1:18778',
    'mcp-host.example.ts.net',
    'mcp-host.example.ts.net:443',
  ]);
  assert.deepEqual(a.defaultAllowedOrigins(18778, P), ['https://mcp-host.example.ts.net', 'http://localhost:18778', 'http://127.0.0.1:18778']);
  assert.deepEqual([...a.DEFAULT_PATHS], ['/mcp', '/unifi-mcp-rw']);
});

test('host allowlist', () => {
  const H = a.defaultAllowedHosts(18778, P);
  for (const ok of ['localhost:18778', '127.0.0.1:18778', 'mcp-host.example.ts.net', 'MCP-HOST.example.TS.NET:443', 'LocalHost:18778']) {
    assert.equal(a.isAllowedHost(ok, H), true, ok);
  }
  for (const bad of [
    undefined,
    '',
    'mcp-host.example.ts.net.evil.com',
    'evil.com',
    'mcp-host.example.ts.net:8443',
    'localhost',
    '127.0.0.1',
    'localhost:18779',
    '127.0.0.1:18778 ',
    'mcp-host.example.ts.net.',
    ['localhost:18778'],
  ]) {
    assert.equal(a.isAllowedHost(bad, H), false, String(bad));
  }
});

test('origin allowlist', () => {
  const O = a.defaultAllowedOrigins(18778, P);
  assert.equal(a.isAllowedOrigin(undefined, O), true);
  assert.equal(a.isAllowedOrigin('https://mcp-host.example.ts.net', O), true);
  assert.equal(a.isAllowedOrigin('http://localhost:18778', O), true);
  assert.equal(a.isAllowedOrigin('http://127.0.0.1:18778', O), true);
  assert.equal(a.isAllowedOrigin('http://mcp-host.example.ts.net', O), false);
  assert.equal(a.isAllowedOrigin('https://evil.com', O), false);
  assert.equal(a.isAllowedOrigin('null', O), false);
  assert.equal(a.isAllowedOrigin('', O), false);
});

test('paths', () => {
  for (const ok of ['/mcp', '/mcp/', '/unifi-mcp-rw', '/unifi-mcp-rw/', '/mcp?x=1', '/unifi-mcp-rw/?a=b']) assert.equal(a.isAllowedPath(ok), true, ok);
  for (const bad of ['/', '/mcp//', '/mcpx', '/MCP', '/unifi-mcp-rw/mcp', '/mcp/../mcp', 'mcp', '', undefined, '/unifi-mcp']) {
    assert.equal(a.isAllowedPath(bad), false, String(bad));
  }
});

test('method and content-type', () => {
  assert.equal(a.isAllowedMethod('POST'), true);
  for (const m of ['GET', 'DELETE', 'PUT', 'OPTIONS', 'post']) assert.equal(a.isAllowedMethod(m), false, m);
  assert.equal(a.isJsonContentType('application/json'), true);
  assert.equal(a.isJsonContentType('application/json; charset=utf-8'), true);
  assert.equal(a.isJsonContentType('Application/JSON'), true);
  for (const bad of ['text/plain', 'application/jsonx', 'application/x-www-form-urlencoded', undefined, '']) {
    assert.equal(a.isJsonContentType(bad), false, String(bad));
  }
});

test('content-length', () => {
  assert.equal(a.checkContentLength(undefined), 'ok');
  assert.equal(a.checkContentLength('100'), 'ok');
  assert.equal(a.checkContentLength(String(256 * 1024)), 'ok');
  assert.equal(a.checkContentLength(String(256 * 1024 + 1)), 'too_large');
  assert.equal(a.checkContentLength('-1'), 'invalid');
  assert.equal(a.checkContentLength('abc'), 'invalid');
});

test('bearer token', () => {
  const token = 'a'.repeat(64);
  const d = a.sha256(token);
  assert.equal(a.checkBearer(`Bearer ${token}`, d), true);
  assert.equal(a.checkBearer(`bearer ${token}`, d), true);
  assert.equal(a.checkBearer(`BEARER ${token}`, d), true);
  assert.equal(a.checkBearer(`Bearer ${'a'.repeat(63)}b`, d), false);
  assert.equal(a.checkBearer(`Bearer ${token}x`, d), false);
  assert.equal(a.checkBearer(`Bearer short`, d), false);
  assert.equal(a.checkBearer(`Bearer `, d), false);
  assert.equal(a.checkBearer('Bearer', d), false);
  assert.equal(a.checkBearer(token, d), false);
  assert.equal(a.checkBearer(`Basic ${token}`, d), false);
  assert.equal(a.checkBearer(undefined, d), false);
  assert.equal(a.checkBearer(`Bearer ${token}`, Buffer.alloc(3)), false);
});

test('evaluateHeaders check order', () => {
  const token = 't'.repeat(40);
  const opts = { allowedHosts: a.defaultAllowedHosts(18778, P), allowedOrigins: a.defaultAllowedOrigins(18778, P), tokenDigest: a.sha256(token) };
  const good = { host: 'localhost:18778', authorization: `Bearer ${token}`, 'content-type': 'application/json' };
  const ev = (method, url, headers) => a.evaluateHeaders({ method, url, headers }, opts);
  assert.equal(ev('POST', '/mcp', good), null);
  // host checked before everything else
  assert.equal(ev('GET', '/nope', { ...good, host: 'evil' }).status, 403);
  assert.equal(ev('GET', '/nope', { ...good, origin: 'https://evil' }).status, 403);
  assert.equal(ev('GET', '/nope', good).status, 404);
  assert.equal(ev('GET', '/mcp', { ...good, authorization: undefined }).status, 405);
  assert.equal(ev('POST', '/mcp', { ...good, authorization: undefined, 'content-type': 'text/plain' }).status, 401);
  assert.equal(ev('POST', '/mcp', { ...good, 'content-type': 'text/plain' }).status, 415);
  assert.equal(ev('POST', '/mcp', { ...good, 'content-length': '999999' }).status, 413);
  assert.deepEqual(ev('GET', '/mcp', good).headers, { Allow: 'POST' });
});
