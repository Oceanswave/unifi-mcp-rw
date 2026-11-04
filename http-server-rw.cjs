#!/usr/bin/env node
'use strict';

/**
 * unifi-mcp-rw: write-enabled UniFi Network MCP server (Streamable HTTP, stateless).
 * Loopback only; meant to sit behind `tailscale serve`.
 */

const http = require('node:http');
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StreamableHTTPServerTransport } = require('@modelcontextprotocol/sdk/server/streamableHttp.js');

const auth = require('./lib/http-auth.cjs');
const { loadConfig, loadSecrets, isLoopbackAddress, ConfigError } = require('./lib/config.cjs');
const { createUdmClient } = require('./lib/udm-client.cjs');
const { registerTools } = require('./lib/tools.cjs');
const { createAuditLog } = require('./lib/audit-log.cjs');
const { openWriteLog } = require('./lib/write-log.cjs');
const { createWanExposure } = require('./lib/wan-exposure.cjs');
const { makeScrubber } = require('./lib/redact.cjs');

// SIGTERM drain: just above the cloud backend's 30 s upstream timeout, so a
// write that is already in flight can finish (and be logged). The systemd
// unit's TimeoutStopSec must be larger.
const DRAIN_MS = 35_000;

const SERVER_INFO = { name: 'unifi-mcp-rw', version: require('./package.json').version };
let scrubSecrets = (m) => m;

function sendJson(res, status, body, headers = {}) {
  if (res.headersSent) return;
  const text = JSON.stringify(body);
  res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(text), 'Cache-Control': 'no-store', ...headers });
  res.end(text);
}

/** Read the body with a hard cap enforced while streaming. Resolves Buffer, or null if the cap was hit. */
function readBody(req, cap) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let over = false;
    req.on('data', (c) => {
      if (over) return;
      size += c.length;
      if (size > cap) {
        over = true;
        chunks.length = 0;
        req.pause();
        resolve(null);
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!over) resolve(Buffer.concat(chunks));
    });
    req.on('error', reject);
  });
}

/**
 * `secrets`: extra values (bearer token) scrubbed from tool output; the client scrubs its own API key.
 * `writeTools` / `writeLog` / `wanExposure`: UNIFI_WRITE_TOOLS, UNIFI_WRITE_LOG and the WAN-exposure
 * refusals (see lib/tools.cjs registerTools; omitted wanExposure means refusals on).
 */
function buildMcpServer({ udmClient, auditLog, writeLog, writeTools, wanExposure, secrets = [] }) {
  const server = new McpServer(SERVER_INFO, { capabilities: { tools: {} } });
  registerTools(server, { client: udmClient, auditLog, writeLog: writeLog ?? null, writeTools: writeTools ?? null, ...(wanExposure ? { wanExposure } : {}), secrets });
  return server;
}

/**
 * @param {object} opts
 * @param {string} opts.token              bearer token (plaintext; only its digest is kept)
 * @param {object} opts.udmClient
 * @param {object} [opts.auditLog]
 * @param {object} [opts.writeLog]       UNIFI_WRITE_LOG
 * @param {string[]|null} [opts.writeTools] UNIFI_WRITE_TOOLS (null = all)
 * @param {object} [opts.wanExposure]    WAN-exposure refusals (default: on)
 * @param {number} [opts.port]             used to derive default host/origin allowlists
 * @param {string|null} [opts.publicHost] MCP_PUBLIC_HOST: the reverse proxy's name, added to both allowlists
 * @param {string[]} [opts.allowedHosts]
 * @param {string[]} [opts.allowedOrigins]
 * @param {string[]} [opts.paths]
 * @param {number} [opts.bodyCap]
 */
function createServer(opts) {
  if (!opts || typeof opts.token !== 'string' || opts.token.length < 32) throw new Error('createServer: token (>= 32 chars) required');
  const port = opts.port ?? auth.DEFAULT_PORT;
  const gate = {
    allowedHosts: opts.allowedHosts || auth.defaultAllowedHosts(port, opts.publicHost),
    allowedOrigins: opts.allowedOrigins || auth.defaultAllowedOrigins(port, opts.publicHost),
    paths: opts.paths || auth.DEFAULT_PATHS,
    bodyCap: opts.bodyCap || auth.BODY_CAP_BYTES,
    tokenDigest: auth.sha256(opts.token),
  };
  const scrub = makeScrubber([opts.token]);
  const log = opts.logger || ((m) => process.stderr.write(`unifi-mcp-rw: ${m}\n`));

  async function handle(req, res) {
    const rejected = auth.evaluateHeaders(req, gate);
    if (rejected) {
      if (rejected === auth.ERR.tooLarge) res.setHeader('Connection', 'close');
      return sendJson(res, rejected.status, rejected.body, rejected.headers);
    }

    const raw = await readBody(req, gate.bodyCap);
    if (raw === null) {
      res.on('finish', () => req.socket.destroy());
      return sendJson(res, auth.ERR.tooLarge.status, auth.ERR.tooLarge.body, { Connection: 'close' });
    }
    let parsed;
    try {
      parsed = JSON.parse(raw.toString('utf8'));
    } catch {
      return sendJson(res, auth.ERR.badJson.status, auth.ERR.badJson.body);
    }

    const server = buildMcpServer({
      udmClient: opts.udmClient,
      auditLog: opts.auditLog,
      writeLog: opts.writeLog,
      writeTools: opts.writeTools,
      wanExposure: opts.wanExposure,
      secrets: [opts.token],
    });
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.on('close', () => {
      transport.close().catch(() => {});
      server.close().catch(() => {});
    });
    await server.connect(transport);
    await transport.handleRequest(req, res, parsed);
  }

  const httpServer = http.createServer({ maxHeaderSize: 16 * 1024 }, (req, res) => {
    handle(req, res).catch((e) => {
      // Details stay in the journal; the client only gets a fixed text.
      log(`request failed: ${scrub(String((e && e.message) || e))}`);
      sendJson(res, 500, { error: 'Internal error' });
    });
  });
  // Malformed HTTP / aborted sockets: answer 400 if still possible, never crash.
  httpServer.on('clientError', (err, socket) => {
    if (socket.writable && !socket.destroyed) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    else socket.destroy();
  });
  httpServer.requestTimeout = 60_000;
  httpServer.headersTimeout = 15_000;
  return httpServer;
}

/** Listen on a loopback address only. Resolves the http.Server once listening. */
async function startServer(opts) {
  const host = opts.host || '127.0.0.1';
  if (!isLoopbackAddress(host)) throw new Error(`refusing to bind non-loopback address ${host}`);
  const server = createServer(opts);
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(opts.port ?? auth.DEFAULT_PORT, host, () => {
      server.removeListener('error', reject);
      resolve(server);
    });
  });
}

const keyValues = (fields) =>
  Object.entries(fields)
    .map(([k, v]) => `${k}=${/[\s"]/.test(String(v)) ? JSON.stringify(String(v)) : v}`)
    .join(' ');

/** The write safeguards in effect (write mode only): UNIFI_WRITE_TOOLS, UNIFI_WRITE_LOG, WAN-exposure refusals. */
function safeguardSummary(cfg) {
  return keyValues({
    write_tools: cfg.writeTools ? (cfg.writeTools.length ? cfg.writeTools.join(',') : 'none') : 'all',
    write_log: cfg.writeLog || 'off',
    wan_exposure: cfg.wanExposure && cfg.wanExposure.allowExposure ? 'allowed' : 'refused',
  });
}

/** One-line startup summary: key=value pairs, no secrets (no key, token or file contents). */
function startupSummary(cfg, udmClient) {
  const fields = {
    version: SERVER_INFO.version,
    node: process.version,
    listen: `http://${cfg.listenHost}:${cfg.listenPort}`,
    public_host: cfg.publicHost || 'none',
    backend: cfg.backend,
    mode: udmClient.writesEnabled ? 'read-write' : 'read-only',
    allow_writes_source: cfg.allowWritesSource,
    classic: udmClient.classicCapabilities.length ? udmClient.classicCapabilities.join(',') : 'off',
    config: cfg.configPath,
  };
  if (cfg.backend === 'cloud') fields.console_id = cfg.cloud.consoleId;
  else Object.assign(fields, { local_host: cfg.target.hostHeader, tls: cfg.tls.mode });
  return keyValues(fields);
}

async function main() {
  const stderr = (m) => process.stderr.write(`unifi-mcp-rw: ${m}\n`);
  // Last-resort handlers: log one scrubbed line (no stack, which could carry
  // request data) and exit non-zero so systemd restarts the service.
  process.on('uncaughtException', (e) => {
    stderr(`fatal: uncaught exception: ${scrubSecrets(String((e && e.message) || e))}`);
    process.exit(1);
  });
  process.on('unhandledRejection', (e) => {
    stderr(`fatal: unhandled rejection: ${scrubSecrets(String((e && e.message) || e))}`);
    process.exit(1);
  });

  let cfg, token, apiKey;
  try {
    cfg = loadConfig();
    ({ token, apiKey } = loadSecrets(cfg));
  } catch (e) {
    if (e instanceof ConfigError) {
      stderr(`refusing to start: ${e.message}`);
      process.exit(2);
    }
    throw e;
  }
  scrubSecrets = makeScrubber([token, apiKey]);
  for (const w of cfg.warnings) stderr(`warning: ${w}`);
  const auditLog = createAuditLog({ secrets: [token, apiKey] });
  let writeLog = null;
  if (cfg.writeLog) {
    try {
      writeLog = openWriteLog(cfg.writeLog, { secrets: [token, apiKey], onError: stderr });
    } catch (e) {
      stderr(`refusing to start: cannot use UNIFI_WRITE_LOG (${cfg.writeLog}): ${scrubSecrets(e.message)}`);
      process.exit(2);
    }
  }
  const wanExposure = createWanExposure(cfg.wanExposure);
  // Options are passed field by field: nothing from config.json can reach
  // the test-only client options (injected sink / connect override).
  const common = {
    apiKey,
    allowWrites: cfg.allowWrites,
    siteName: cfg.siteName,
    siteId: cfg.siteId,
    auditLog,
    firewallInternalZoneIds: cfg.firewall.internalZoneIds,
    firewallWanZoneIds: cfg.firewall.wanZoneIds,
  };
  const udmClient =
    cfg.backend === 'cloud'
      ? createUdmClient({ backend: 'cloud', consoleId: cfg.cloud.consoleId, allowClassic: cfg.cloud.classicCapabilities, ...common })
      : createUdmClient({ backend: 'local', target: cfg.target, tls: cfg.tls, ...common });
  const server = await startServer({ host: cfg.listenHost, port: cfg.listenPort, token, udmClient, auditLog, writeLog, writeTools: cfg.writeTools, wanExposure, publicHost: cfg.publicHost });

  let stopping = false;
  const shutdown = (sig) => {
    if (stopping) return;
    stopping = true;
    stderr(`${sig} received: refusing new writes, draining in-flight requests (up to ${DRAIN_MS / 1000} s)`);
    const writesDrained = udmClient.beginShutdown();
    server.close(async () => {
      await writesDrained;
      stderr('drained, exiting');
      process.exit(0);
    });
    server.closeIdleConnections();
    setTimeout(() => {
      stderr('drain timeout, closing remaining connections');
      server.closeAllConnections();
      process.exit(0);
    }, DRAIN_MS).unref();
  };
  // Before "started", so anything that signals on that line finds the handler in place.
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
  // "started" is the last startup line: by then the signal handlers are installed.
  if (!udmClient.writesEnabled) stderr('read-only mode: no write tools are registered and every non-GET request is refused; set "allow_writes": true to enable writes');
  else {
    stderr(`write safeguards: ${safeguardSummary(cfg)}`);
    if (wanExposure.allowExposure) stderr('warning: WAN-exposure refusals are off (UNIFI_ALLOW_WAN_EXPOSURE=true); only the guard stands between a write and the WAN');
  }
  stderr(`started ${startupSummary(cfg, udmClient)}`);
}

module.exports = { createServer, startServer, buildMcpServer, startupSummary, safeguardSummary, DRAIN_MS };

if (require.main === module) {
  main().catch((e) => {
    process.stderr.write(`unifi-mcp-rw: fatal: ${scrubSecrets(String((e && e.message) || e))}\n`);
    process.exit(1);
  });
}
