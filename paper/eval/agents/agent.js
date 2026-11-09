// Synthetic AI agent for the evaluation bench, Node.js variant (no dependency).
//
// Same footprint as agent.py: a keep-alive HTTPS connection polled with an
// INVALID key (the server answers 401, nothing is sent or billed) and a
// persistent shell child fed one harmless command per poll.
//
// Usage: node agent.js --endpoint https://api.anthropic.com/v1/models --shell powershell
'use strict';

const https = require('https');
const tls = require('tls');
const { spawn } = require('child_process');

function arg(name, def) {
  const i = process.argv.indexOf('--' + name);
  return i > 0 && i + 1 < process.argv.length ? process.argv[i + 1] : def;
}

const endpoint = new URL(arg('endpoint', 'https://api.anthropic.com/v1/models'));
const intervalMs = Number(arg('interval', '5')) * 1000;
const durationMs = Number(arg('duration', '0')) * 1000;
const shellKind = arg('shell', 'powershell');

const agent = new https.Agent({ keepAlive: true, maxSockets: 1 });

function poll() {
  const req = https.request({
    hostname: endpoint.hostname,
    port: endpoint.port || 443,
    path: endpoint.pathname + endpoint.search,
    method: 'GET',
    agent,
    timeout: 15000,
    headers: {
      Authorization: 'Bearer sk-invalid-key-for-detection-research',
      'x-api-key': 'invalid-key-for-detection-research',
      'User-Agent': 'agent-detector-eval/1.0',
    },
  }, (res) => res.resume());
  req.on('error', () => {});
  req.on('timeout', () => req.destroy());
  req.end();
}

// A warm TLS connection kept open between polls, as connection pools do, so
// that one connection is always established even when the server closes the
// request connection (for example after a 401).
let warm = null;
function keepWarm() {
  if (warm && !warm.destroyed) return;
  warm = tls.connect({ host: endpoint.hostname, port: Number(endpoint.port) || 443, servername: endpoint.hostname });
  warm.on('error', () => {});
  warm.on('close', () => { warm = null; });
}

let shell = null;
if (shellKind !== 'none') {
  const cmd = shellKind === 'cmd'
    ? ['cmd.exe', ['/Q', '/K']]
    : ['powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', '-']];
  shell = spawn(cmd[0], cmd[1], { stdio: ['pipe', 'ignore', 'ignore'], windowsHide: true });
}

function tick() {
  poll();
  keepWarm();
  if (shell && shell.exitCode === null) {
    shell.stdin.write('echo tool-call\r\n');
  }
}

console.log(`agent pid ${process.pid} running`);
tick();
const timer = setInterval(tick, intervalMs);

function stop() {
  clearInterval(timer);
  agent.destroy();
  if (warm) warm.destroy();
  if (shell && shell.exitCode === null) shell.kill();
  process.exit(0);
}
process.on('SIGTERM', stop);
process.on('SIGINT', stop);
if (durationMs > 0) setTimeout(stop, durationMs);
