'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const tls = require('node:tls');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const { createUdmClient, PinMismatchError } = require('../lib/udm-client.cjs');
const { tmpDir } = require('./helpers.cjs');

const API_KEY = 'FAKE-API-KEY-DO-NOT-USE';
const INFO = '/integration/v1/info';

function haveOpenssl() {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

const skip = haveOpenssl() ? false : 'openssl CLI not available';
let dir, server, port, certPem, connections, tcp;

test.before(async () => {
  if (skip) return;
  dir = tmpDir();
  const key = path.join(dir, 'key.pem');
  const cert = path.join(dir, 'cert.pem');
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
    '-keyout', key, '-out', cert, '-days', '1', '-subj', '/CN=localhost',
    '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost',
  ], { stdio: 'ignore' });
  certPem = fs.readFileSync(cert, 'utf8');
  connections = [];
  server = tls.createServer({ key: fs.readFileSync(key), cert: certPem }, (sock) => {
    const conn = { data: '', closed: null };
    conn.closed = new Promise((resolve) => sock.on('close', resolve));
    connections.push(conn);
    sock.on('data', (d) => {
      conn.data += d.toString('latin1');
      if (conn.data.includes('\r\n\r\n')) {
        sock.end('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\nConnection: close\r\n\r\n{"version":"x"}');
      }
    });
    sock.on('error', () => {});
  });
  // Raw TCP connections (fires even if the client aborts before the server finishes the handshake).
  tcp = [];
  server.on('connection', (raw) => tcp.push(new Promise((resolve) => raw.on('close', resolve))));
  // Server may see client-side aborts after the pin check.
  server.on('tlsClientError', () => {});
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  port = server.address().port;
});

test.after(() => {
  if (server) server.close();
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
});

const target = () => ({ host: '127.0.0.1', port, isIp: true, hostHeader: `127.0.0.1:${port}` });
const rightPin = () => new crypto.X509Certificate(certPem).fingerprint256.replace(/:/g, '').toLowerCase();

async function settle() {
  await Promise.all(tcp);
  await Promise.all(connections.map((c) => c.closed));
}

test('wrong pin: request refused, server never receives any request bytes or the API key', { skip }, async () => {
  connections.length = 0;
  tcp.length = 0;
  const wrong = crypto.createHash('sha256').update('other').digest('hex');
  const udm = createUdmClient({ backend: 'local', target: target(), tls: { mode: 'pin', pin: wrong }, apiKey: API_KEY, siteId: '88f7af54-98f8-306a-a1c7-c9349722b1f6' });
  await assert.rejects(udm.request({ method: 'GET', path: INFO }), PinMismatchError);
  await settle();
  assert.equal(tcp.length, 1, 'the client did connect and handshake');
  // If the client had written anything, the server would have completed the
  // handshake and recorded the decrypted bytes.
  for (const c of connections) assert.equal(c.data, '', 'no application bytes were sent');
});

test('right pin: request (with X-API-KEY) is delivered over the verified socket', { skip }, async () => {
  connections.length = 0;
  const pinWithColons = new crypto.X509Certificate(certPem).fingerprint256; // upper-case with colons
  const udm = createUdmClient({ backend: 'local', target: target(), tls: { mode: 'pin', pin: rightPin() }, apiKey: API_KEY });
  const res = await udm.request({ method: 'GET', path: INFO });
  assert.deepEqual(res, { version: 'x' });
  await settle();
  assert.equal(connections.length, 1);
  assert.match(connections[0].data, /^GET \/proxy\/network\/integration\/v1\/info HTTP\/1\.1\r\n/);
  assert.match(connections[0].data, new RegExp(`x-api-key: ${API_KEY}`, 'i'));
  assert.ok(pinWithColons.includes(':'));
});

test('system-CA mode against a self-signed cert fails before sending', { skip }, async () => {
  connections.length = 0;
  tcp.length = 0;
  const udm = createUdmClient({ backend: 'local', target: target(), tls: { mode: 'system' }, apiKey: API_KEY });
  await assert.rejects(udm.request({ method: 'GET', path: INFO }));
  await settle();
  for (const c of connections) assert.equal(c.data, '');
});

test('CA-file mode verifies with the provided CA', { skip }, async () => {
  connections.length = 0;
  const caFile = path.join(dir, 'cert.pem');
  const udm = createUdmClient({ backend: 'local', target: target(), tls: { mode: 'ca', caFile }, apiKey: API_KEY });
  assert.deepEqual(await udm.request({ method: 'GET', path: INFO }), { version: 'x' });
});

test('guard runs before any socket is opened', { skip }, async () => {
  connections.length = 0;
  const udm = createUdmClient({ backend: 'local', target: target(), tls: { mode: 'pin', pin: rightPin() }, apiKey: API_KEY });
  tcp.length = 0;
  await assert.rejects(udm.request({ method: 'GET', path: '/api/s/default/rest/setting' }), /Refused by guard/);
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(tcp.length, 0);
  assert.equal(connections.length, 0);
});
