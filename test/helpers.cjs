'use strict';

const http = require('node:http');
const net = require('node:net');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');

const SERVER = path.join(__dirname, '..', 'http-server-rw.cjs');

function tmpDir(prefix = 'unifi-mcp-rw-test-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

/** Raw HTTP request (fetch cannot set Host). Resolves {status, headers, text, json}. */
function rawRequest({ port, method = 'POST', path: p = '/mcp', headers = {}, body }) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path: p, headers, agent: false }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json;
        try {
          json = JSON.parse(text);
        } catch {
          json = undefined;
        }
        resolve({ status: res.statusCode, headers: res.headers, text, json });
      });
    });
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

function rpc(port, token, method, params = {}, { host = `127.0.0.1:${port}`, id = 1 } = {}) {
  const body = JSON.stringify({ jsonrpc: '2.0', id, method, params });
  return rawRequest({
    port,
    headers: {
      host,
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      'content-length': Buffer.byteLength(body),
    },
    body,
  });
}

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

/**
 * Start the real server process (main()) in its own directory under `dir`.
 * Only the UNIFI_* variables given in `env` reach it. Nothing upstream is
 * contacted: the server opens no upstream connection at startup.
 * Resolves { child, port, token, started, exited, stderr(), dir }.
 */
async function spawnServer(dir, name, { config = {}, env = {}, apiKey = 'fake-key-0000-0000-0000-0000' } = {}) {
  const d = path.join(dir, name);
  fs.mkdirSync(d, { mode: 0o700 });
  const token = crypto.randomBytes(32).toString('hex');
  writeSecret(path.join(d, 'token'), token);
  writeSecret(path.join(d, 'key'), apiKey);
  const port = await freePort();
  const keyFileKey = config.backend === 'local' ? 'local_rw_key_file' : 'cloud_rw_key_file';
  const cfg = { rw_token_file: path.join(d, 'token'), [keyFileKey]: path.join(d, 'key'), rw_listen_port: port, ...config };
  fs.writeFileSync(path.join(d, 'config.json'), JSON.stringify(cfg));
  const childEnv = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('UNIFI_')));
  Object.assign(childEnv, { UNIFI_MCP_RW_CONFIG: path.join(d, 'config.json'), UNIFI_MCP_RW_STATE_DIR: path.join(d, 'state') }, env);
  const child = spawn(process.execPath, [SERVER], { env: childEnv, stdio: ['ignore', 'ignore', 'pipe'] });
  let stderr = '';
  child.stderr.on('data', (c) => (stderr += c));
  const exited = new Promise((resolve) => child.on('exit', (code, signal) => resolve({ code, signal })));
  const started = new Promise((resolve) => {
    const check = () => (/started /.test(stderr) ? resolve(true) : null);
    child.stderr.on('data', check);
    exited.then(() => resolve(false));
  });
  return { child, port, token, started, exited, stderr: () => stderr, dir: d };
}

module.exports = { tmpDir, rawRequest, rpc, freePort, writeSecret, spawnServer };
