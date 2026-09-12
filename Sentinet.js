#!/usr/bin/env node
"use strict";

/*
 * SentinelGuard - Defensive Security Monitor
 *
 * Single-file Node.js monitor.
 *
 * Features:
 *   - Syslog UDP ingestion
 *   - Authentication failure/success detection
 *   - Brute-force correlation
 *   - Port-scan indicators from observed connection telemetry
 *   - Promiscuous-interface detection
 *   - Wireless deauth/disassociation telemetry ingestion
 *   - File-integrity monitoring
 *   - Hardware/firmware inventory baseline
 *   - JSONL security event logging
 *   - HTTP dashboard/API
 *
 * This is a defensive monitor. It does NOT:
 *   - capture credentials
 *   - perform packet interception
 *   - transmit deauthentication frames
 *   - actively scan remote hosts
 *   - exploit systems
 *
 * Node.js: 18+
 *
 * Run:
 *   node sentinel.js
 *
 * Optional:
 *   SYSLOG_PORT=5514 HTTP_PORT=8080 node sentinel.js
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const dgram = require("dgram");
const http = require("http");
const { execFile, spawn } = require("child_process");

const CONFIG = {
  syslogPort: Number(process.env.SYSLOG_PORT || 5514),
  httpPort: Number(process.env.HTTP_PORT || 8080),

  // Correlation windows.
  bruteForceWindowMs: 60_000,
  bruteForceThreshold: 10,

  authCompromiseWindowMs: 5 * 60_000,

  portScanWindowMs: 10_000,
  portScanThreshold: 20,

  deauthWindowMs: 10_000,
  deauthThreshold: 50,

  // Keep memory bounded.
  maxEvents: 5000,

  // File-integrity paths.
  monitoredPaths:
    process.platform === "win32"
      ? [
          process.env.WINDIR
            ? path.join(process.env.WINDIR, "System32", "drivers")
            : "C:\\Windows\\System32\\drivers"
        ]
      : [
          "/etc/passwd",
          "/etc/group",
          "/etc/hosts",
          "/etc/ssh"
        ],

  hashAlgorithm: "sha256",

  logFile: path.join(process.cwd(), "sentinel-events.jsonl"),
  baselineFile: path.join(process.cwd(), "sentinel-baseline.json")
};

const state = {
  startedAt: new Date().toISOString(),

  events: [],

  authFailures: new Map(),
  authSuccesses: new Map(),

  observedPorts: new Map(),

  deauthEvents: [],

  fileHashes: new Map(),

  baseline: null,

  stats: {
    syslogMessages: 0,
    authFailures: 0,
    authSuccesses: 0,
    bruteForceAlerts: 0,
    portScanAlerts: 0,
    deauthAlerts: 0,
    integrityAlerts: 0,
    hardwareAlerts: 0
  }
};

/* -------------------------------------------------------------------------- */
/* Utilities                                                                  */
/* -------------------------------------------------------------------------- */

function now() {
  return Date.now();
}

function iso(ts = now()) {
  return new Date(ts).toISOString();
}

function safeString(value, max = 500) {
  return String(value ?? "").slice(0, max);
}

function sha256(data) {
  return crypto
    .createHash(CONFIG.hashAlgorithm)
    .update(data)
    .digest("hex");
}

function addEvent(event) {
  const normalized = {
    timestamp: iso(),
    ...event
  };

  state.events.push(normalized);

  if (state.events.length > CONFIG.maxEvents) {
    state.events.splice(0, state.events.length - CONFIG.maxEvents);
  }

  try {
    fs.appendFileSync(
      CONFIG.logFile,
      JSON.stringify(normalized) + "\n",
      "utf8"
    );
  } catch (err) {
    console.error("[LOG ERROR]", err.message);
  }

  const level = normalized.severity || "info";

  if (level === "critical" || level === "high") {
    console.warn(
      `[${level.toUpperCase()}] ${normalized.type}:`,
      normalized.message || ""
    );
  }
}

function alert(type, severity, message, details = {}) {
  addEvent({
    type,
    severity,
    message,
    details
  });
}

/* -------------------------------------------------------------------------- */
/* Authentication monitoring                                                  */
/* -------------------------------------------------------------------------- */

function pruneMap(map, windowMs) {
  const cutoff = now() - windowMs;

  for (const [key, entries] of map) {
    const filtered = entries.filter((x) => x.timestamp >= cutoff);

    if (filtered.length === 0) {
      map.delete(key);
    } else {
      map.set(key, filtered);
    }
  }
}

function recordAuthFailure(srcIp, username, service) {
  srcIp = srcIp || "unknown";
  username = username || "unknown";
  service = service || "unknown";

  const key = `${srcIp}|${username}`;

  if (!state.authFailures.has(key)) {
    state.authFailures.set(key, []);
  }

  const entries = state.authFailures.get(key);

  entries.push({
    timestamp: now(),
    srcIp,
    username,
    service
  });

  state.stats.authFailures++;

  const recent = entries.filter(
    (x) => x.timestamp >= now() - CONFIG.bruteForceWindowMs
  );

  if (recent.length >= CONFIG.bruteForceThreshold) {
    state.stats.bruteForceAlerts++;

    alert(
      "brute_force",
      "high",
      `Possible brute-force authentication attack from ${srcIp}`,
      {
        sourceIp: srcIp,
        username,
        service,
        attempts: recent.length,
        windowSeconds: CONFIG.bruteForceWindowMs / 1000
      }
    );

    // Prevent one continuous stream from generating an alert every event.
    state.authFailures.set(
      key,
      recent.slice(-Math.floor(CONFIG.bruteForceThreshold / 2))
    );
  }
}

function recordAuthSuccess(srcIp, username, service) {
  srcIp = srcIp || "unknown";
  username = username || "unknown";
  service = service || "unknown";

  const key = `${srcIp}|${username}`;

  if (!state.authSuccesses.has(key)) {
    state.authSuccesses.set(key, []);
  }

  state.authSuccesses.get(key).push({
    timestamp: now(),
    srcIp,
    username,
    service
  });

  state.stats.authSuccesses++;

  const failures = state.authFailures.get(key) || [];

  const recentFailures = failures.filter(
    (x) => x.timestamp >= now() - CONFIG.authCompromiseWindowMs
  );

  if (recentFailures.length >= 5) {
    alert(
      "possible_account_compromise",
      "critical",
      `Successful authentication followed repeated failures from ${srcIp}`,
      {
        sourceIp: srcIp,
        username,
        service,
        previousFailures: recentFailures.length
      }
    );
  }
}

/*
 * Parse common SSH/Linux authentication messages.
 */
function parseAuthenticationMessage(message) {
  let match;

  // SSH failed password.
  match = message.match(
    /Failed password for (?:invalid user )?([A-Za-z0-9._@-]+) from ([0-9a-fA-F:.]+) port \d+/i
  );

  if (match) {
    recordAuthFailure(match[2], match[1], "ssh");
    return true;
  }

  // SSH accepted password/public key.
  match = message.match(
    /Accepted (?:password|publickey|keyboard-interactive\/pam) for ([A-Za-z0-9._@-]+) from ([0-9a-fA-F:.]+) port \d+/i
  );

  if (match) {
    recordAuthSuccess(match[2], match[1], "ssh");
    return true;
  }

  // Generic authentication failure.
  if (
    /authentication failure|authentication failed|login failed|invalid password|invalid credentials/i.test(
      message
    )
  ) {
    const ip =
      message.match(
        /\b(?:from|src|source)[ =:]([0-9a-fA-F:.]+)\b/i
      )?.[1] || "unknown";

    const user =
      message.match(
        /\b(?:user|username)[ =:]([A-Za-z0-9._@-]+)\b/i
      )?.[1] || "unknown";

    recordAuthFailure(ip, user, "unknown");
    return true;
  }

  return false;
}

/* -------------------------------------------------------------------------- */
/* Port scan indicators                                                        */
/* -------------------------------------------------------------------------- */

/*
 * This function only analyzes connection telemetry that the host already
 * observed. It does not initiate scans.
 *
 * Example:
 *   recordConnection("192.0.2.10", 22)
 */
function recordConnection(srcIp, dstPort) {
  if (!srcIp || !dstPort) return;

  if (!state.observedPorts.has(srcIp)) {
    state.observedPorts.set(srcIp, []);
  }

  const entries = state.observedPorts.get(srcIp);

  entries.push({
    timestamp: now(),
    port: Number(dstPort)
  });

  const cutoff = now() - CONFIG.portScanWindowMs;

  const recent = entries.filter((x) => x.timestamp >= cutoff);

  const uniquePorts = new Set(recent.map((x) => x.port));

  state.observedPorts.set(srcIp, recent);

  if (uniquePorts.size >= CONFIG.portScanThreshold) {
    state.stats.portScanAlerts++;

    alert(
      "possible_port_scan",
      "high",
      `Possible port scan observed from ${srcIp}`,
      {
        sourceIp: srcIp,
        distinctPorts: uniquePorts.size,
        windowSeconds: CONFIG.portScanWindowMs / 1000,
        ports: [...uniquePorts].slice(0, 100)
      }
    );

    state.observedPorts.set(srcIp, recent.slice(-5));
  }
}

/* -------------------------------------------------------------------------- */
/* Wireless deauthentication telemetry                                        */
/* -------------------------------------------------------------------------- */

/*
 * Feed this from an authorized wireless IDS/AP log.
 *
 * Example input:
 *   {
 *      srcMac: "...",
 *      dstMac: "...",
 *      bssid: "...",
 *      type: "deauth"
 *   }
 */
function recordWirelessEvent(event) {
  const type = String(event.type || "").toLowerCase();

  if (!["deauth", "deauthentication", "disassoc", "disassociation"].includes(type)) {
    return;
  }

  state.deauthEvents.push({
    timestamp: now(),
    srcMac: event.srcMac || "unknown",
    dstMac: event.dstMac || "unknown",
    bssid: event.bssid || "unknown",
    type
  });

  const cutoff = now() - CONFIG.deauthWindowMs;

  state.deauthEvents = state.deauthEvents.filter(
    (x) => x.timestamp >= cutoff
  );

  if (state.deauthEvents.length >= CONFIG.deauthThreshold) {
    state.stats.deauthAlerts++;

    alert(
      "possible_wifi_deauth_attack",
      "high",
      "Abnormally high wireless deauthentication/disassociation activity",
      {
        events: state.deauthEvents.length,
        windowSeconds: CONFIG.deauthWindowMs / 1000,
        bssids: [
          ...new Set(state.deauthEvents.map((x) => x.bssid))
        ].slice(0, 20)
      }
    );

    state.deauthEvents = state.deauthEvents.slice(-10);
  }
}

/* -------------------------------------------------------------------------- */
/* Syslog                                                                      */
/* -------------------------------------------------------------------------- */

function parseSyslog(message, remoteAddress) {
  state.stats.syslogMessages++;

  const text = safeString(message, 5000);

  addEvent({
    type: "syslog",
    severity: "info",
    sourceIp: remoteAddress,
    message: text
  });

  parseAuthenticationMessage(text);

  /*
   * Extract simple network telemetry when it appears in firewall logs.
   * This is passive log parsing rather than packet inspection.
   */
  let match = text.match(
    /\bSRC=([0-9a-fA-F:.]+).*?\bDPT=(\d+)/i
  );

  if (match) {
    recordConnection(match[1], Number(match[2]));
  }

  /*
   * Optional wireless IDS log format.
   */
  if (/deauth|disassoc/i.test(text)) {
    const srcMac =
      text.match(/\bSRC(?:MAC)?=([0-9a-fA-F:.-]+)/i)?.[1];

    const dstMac =
      text.match(/\bDST(?:MAC)?=([0-9a-fA-F:.-]+)/i)?.[1];

    const bssid =
      text.match(/\bBSSID=([0-9a-fA-F:.-]+)/i)?.[1];

    recordWirelessEvent({
      type: /deauth/i.test(text) ? "deauth" : "disassoc",
      srcMac,
      dstMac,
      bssid
    });
  }
}

function startSyslogServer() {
  const socket = dgram.createSocket("udp4");

  socket.on("message", (msg, rinfo) => {
    parseSyslog(msg.toString("utf8"), rinfo.address);
  });

  socket.on("error", (err) => {
    console.error("[SYSLOG]", err.message);
  });

  socket.bind(CONFIG.syslogPort, "0.0.0.0", () => {
    console.log(
      `[+] Syslog UDP listener: 0.0.0.0:${CONFIG.syslogPort}`
    );
  });
}

/* -------------------------------------------------------------------------- */
/* File integrity monitoring                                                   */
/* -------------------------------------------------------------------------- */

function collectFiles(target) {
  const result = [];

  try {
    const stat = fs.statSync(target);

    if (stat.isFile()) {
      result.push(target);
      return result;
    }

    if (!stat.isDirectory()) {
      return result;
    }

    for (const entry of fs.readdirSync(target, { withFileTypes: true })) {
      const full = path.join(target, entry.name);

      if (entry.isSymbolicLink()) continue;

      if (entry.isDirectory()) {
        result.push(...collectFiles(full));
      } else if (entry.isFile()) {
        result.push(full);
      }
    }
  } catch {
    // Permission errors are expected for some system locations.
  }

  return result;
}

function hashFile(file) {
  try {
    const data = fs.readFileSync(file);
    return sha256(data);
  } catch {
    return null;
  }
}

function initializeIntegrityBaseline() {
  const files = [];

  for (const target of CONFIG.monitoredPaths) {
    files.push(...collectFiles(target));
  }

  for (const file of files.slice(0, 5000)) {
    const hash = hashFile(file);

    if (hash) {
      state.fileHashes.set(file, hash);
    }
  }

  console.log(
    `[+] File-integrity baseline initialized: ${state.fileHashes.size} files`
  );
}

function checkFileIntegrity() {
  for (const [file, previousHash] of state.fileHashes) {
    const currentHash = hashFile(file);

    if (!currentHash) {
      continue;
    }

    if (currentHash !== previousHash) {
      state.stats.integrityAlerts++;

      alert(
        "file_integrity_change",
        "high",
        `Monitored file changed: ${file}`,
        {
          file,
          previousHash,
          currentHash
        }
      );

      state.fileHashes.set(file, currentHash);
    }
  }
}

/* -------------------------------------------------------------------------- */
/* Hardware / firmware inventory                                               */
/* -------------------------------------------------------------------------- */

function runCommand(command, args = [], timeout = 5000) {
  return new Promise((resolve) => {
    execFile(
      command,
      args,
      {
        timeout,
        windowsHide: true,
        maxBuffer: 2 * 1024 * 1024
      },
      (error, stdout, stderr) => {
        if (error) {
          resolve(null);
          return;
        }

        resolve({
          stdout: String(stdout || ""),
          stderr: String(stderr || "")
        });
      }
    );
  });
}

async function collectHardwareInventory() {
  const inventory = {
    platform: process.platform,
    arch: process.arch,
    hostname: os.hostname(),
    kernel: os.release(),
    cpus: os.cpus().length,
    memoryBytes: os.totalmem()
  };

  if (process.platform === "linux") {
    const dmi = await runCommand("cat", [
      "/sys/class/dmi/id/product_name"
    ]);

    const bios = await runCommand("cat", [
      "/sys/class/dmi/id/bios_version"
    ]);

    const machineId = await runCommand("cat", [
      "/etc/machine-id"
    ]);

    inventory.productName = dmi?.stdout.trim() || null;
    inventory.biosVersion = bios?.stdout.trim() || null;
    inventory.machineIdHash = machineId
      ? sha256(machineId.stdout.trim())
      : null;

    const secureBoot = await runCommand("sh", [
      "-c",
      "command -v mokutil >/dev/null 2>&1 && mokutil --sb-state"
    ]);

    inventory.secureBoot = secureBoot?.stdout.trim() || "unknown";

    const tpm = await runCommand("sh", [
      "-c",
      "test -e /dev/tpmrm0 && echo present || echo absent"
    ]);

    inventory.tpm = tpm?.stdout.trim() || "unknown";
  }

  if (process.platform === "win32") {
    const bios = await runCommand("powershell.exe", [
      "-NoProfile",
      "-Command",
      "(Get-CimInstance Win32_BIOS).SMBIOSBIOSVersion"
    ]);

    inventory.biosVersion = bios?.stdout.trim() || null;

    const secureBoot = await runCommand("powershell.exe", [
      "-NoProfile",
      "-Command",
      "try { Confirm-SecureBootUEFI } catch { 'unknown' }"
    ]);

    inventory.secureBoot = secureBoot?.stdout.trim() || "unknown";
  }

  if (process.platform === "darwin") {
    const hardware = await runCommand("system_profiler", [
      "SPHardwareDataType"
    ]);

    inventory.hardwareSummary = hardware?.stdout || null;
  }

  return inventory;
}

async function initializeHardwareBaseline() {
  const current = await collectHardwareInventory();

  state.baseline = current;

  try {
    fs.writeFileSync(
      CONFIG.baselineFile,
      JSON.stringify(current, null, 2),
      "utf8"
    );
  } catch (err) {
    console.error("[BASELINE]", err.message);
  }

  console.log("[+] Hardware/firmware baseline initialized");
}

async function checkHardwareBaseline() {
  if (!state.baseline) return;

  const current = await collectHardwareInventory();

  const fields = [
    "platform",
    "arch",
    "hostname",
    "kernel",
    "productName",
    "biosVersion",
    "secureBoot",
    "tpm"
  ];

  for (const field of fields) {
    if (
      state.baseline[field] !== undefined &&
      current[field] !== undefined &&
      state.baseline[field] !== current[field]
    ) {
      state.stats.hardwareAlerts++;

      alert(
        "hardware_firmware_baseline_change",
        "high",
        `Hardware/firmware baseline changed: ${field}`,
        {
          field,
          previous: state.baseline[field],
          current: current[field]
        }
      );
    }
  }
}

/* -------------------------------------------------------------------------- */
/* Promiscuous interface detection                                            */
/* -------------------------------------------------------------------------- */

async function checkPromiscuousInterfaces() {
  if (process.platform === "linux") {
    const result = await runCommand("ip", ["-details", "link", "show"]);

    if (!result) return;

    const lines = result.stdout.split("\n");
    let currentInterface = null;

    for (const line of lines) {
      const nameMatch = line.match(
        /^\d+:\s+([^:@]+)/
      );

      if (nameMatch) {
        currentInterface = nameMatch[1];
      }

      if (
        currentInterface &&
        /\bPROMISC\b/i.test(line)
      ) {
        alert(
          "promiscuous_interface",
          "medium",
          `Interface ${currentInterface} appears to be in promiscuous mode`,
          {
            interface: currentInterface
          }
        );
      }
    }
  }

  if (process.platform === "darwin") {
    const result = await runCommand("ifconfig", []);

    if (!result) return;

    for (const block of result.stdout.split(/\n(?=\S)/)) {
      const firstLine = block.split("\n")[0];

      if (/PROMISC/i.test(block)) {
        const iface = firstLine.split(":")[0];

        alert(
          "promiscuous_interface",
          "medium",
          `Interface ${iface} appears to be in promiscuous mode`,
          {
            interface: iface
          }
        );
      }
    }
  }
}

/* -------------------------------------------------------------------------- */
/* Process monitoring                                                          */
/* -------------------------------------------------------------------------- */

async function processSnapshot() {
  let result;

  if (process.platform === "win32") {
    result = await runCommand("powershell.exe", [
      "-NoProfile",
      "-Command",
      "Get-Process | Select-Object Id,ProcessName,Path | ConvertTo-Json"
    ]);
  } else {
    result = await runCommand("ps", [
      "-eo",
      "pid,ppid,user,comm,args"
    ]);
  }

  if (!result) return;

  /*
   * We deliberately log metadata rather than process memory/content.
   */
  addEvent({
    type: "process_snapshot",
    severity: "info",
    message: "Periodic process inventory collected",
    details: {
      platform: process.platform,
      bytes: result.stdout.length
    }
  });
}

/* -------------------------------------------------------------------------- */
/* HTTP dashboard/API                                                         */
/* -------------------------------------------------------------------------- */

function jsonResponse(res, status, data) {
  const body = JSON.stringify(data, null, 2);

  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "X-Content-Type-Options": "nosniff"
  });

  res.end(body);
}

function htmlDashboard() {
  const recent = state.events.slice(-30).reverse();

  const rows = recent
    .map(
      (e) => `
<tr>
  <td>${safeString(e.timestamp, 40)}</td>
  <td>${safeString(e.severity, 20)}</td>
  <td>${safeString(e.type, 60)}</td>
  <td>${safeString(e.message, 160)}</td>
</tr>`
    )
    .join("");

  return `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>SentinelGuard</title>
<style>
body {
  font-family: system-ui, sans-serif;
  background: #0b1020;
  color: #e8edf7;
  margin: 30px;
}
.card {
  background: #151c31;
  padding: 18px;
  border-radius: 12px;
  margin-bottom: 20px;
}
table {
  width: 100%;
  border-collapse: collapse;
}
td, th {
  padding: 8px;
  border-bottom: 1px solid #29324b;
  text-align: left;
}
.high, .critical {
  color: #ff7070;
}
</style>
</head>
<body>
<h1>SentinelGuard</h1>

<div class="card">
  <b>Started:</b> ${state.startedAt}<br>
  <b>Syslog messages:</b> ${state.stats.syslogMessages}<br>
  <b>Auth failures:</b> ${state.stats.authFailures}<br>
  <b>Auth successes:</b> ${state.stats.authSuccesses}<br>
  <b>Brute-force alerts:</b> ${state.stats.bruteForceAlerts}<br>
  <b>Port-scan alerts:</b> ${state.stats.portScanAlerts}<br>
  <b>Wi-Fi deauth alerts:</b> ${state.stats.deauthAlerts}<br>
  <b>Integrity alerts:</b> ${state.stats.integrityAlerts}<br>
  <b>Hardware alerts:</b> ${state.stats.hardwareAlerts}
</div>

<div class="card">
<h2>Recent events</h2>
<table>
<thead>
<tr>
<th>Time</th>
<th>Severity</th>
<th>Type</th>
<th>Message</th>
</tr>
</thead>
<tbody>
${rows}
</tbody>
</table>
</div>
</body>
</html>`;
}

function startHttpServer() {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);

    if (url.pathname === "/") {
      res.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8"
      });

      res.end(htmlDashboard());
      return;
    }

    if (url.pathname === "/api/status") {
      jsonResponse(res, 200, {
        startedAt: state.startedAt,
        hostname: os.hostname(),
        platform: process.platform,
        stats: state.stats,
        recentEvents: state.events.slice(-50)
      });
      return;
    }

    if (url.pathname === "/api/events") {
      jsonResponse(res, 200, state.events.slice(-500));
      return;
    }

    if (url.pathname === "/api/health") {
      jsonResponse(res, 200, {
        status: "ok",
        timestamp: iso()
      });
      return;
    }

    res.writeHead(404);
    res.end("Not found");
  });

  server.listen(CONFIG.httpPort, "127.0.0.1", () => {
    console.log(
      `[+] Dashboard: http://127.0.0.1:${CONFIG.httpPort}`
    );
  });
}

/* -------------------------------------------------------------------------- */
/* Maintenance                                                                */
/* -------------------------------------------------------------------------- */

function maintenance() {
  pruneMap(state.authFailures, CONFIG.authCompromiseWindowMs);
  pruneMap(state.authSuccesses, CONFIG.authCompromiseWindowMs);
  pruneMap(state.observedPorts, CONFIG.portScanWindowMs);

  const cutoff = now() - CONFIG.deauthWindowMs;

  state.deauthEvents = state.deauthEvents.filter(
    (x) => x.timestamp >= cutoff
  );
}

/* -------------------------------------------------------------------------- */
/* Startup                                                                     */
/* -------------------------------------------------------------------------- */

async function main() {
  console.log("==============================================");
  console.log(" SentinelGuard Defensive Security Monitor");
  console.log("==============================================");
  console.log(`Host: ${os.hostname()}`);
  console.log(`Platform: ${process.platform}`);
  console.log(`Node: ${process.version}`);

  startSyslogServer();
  startHttpServer();

  initializeIntegrityBaseline();
  await initializeHardwareBaseline();

  setInterval(checkFileIntegrity, 30_000);
  setInterval(checkHardwareBaseline, 60_000);
  setInterval(checkPromiscuousInterfaces, 60_000);
  setInterval(processSnapshot, 120_000);
  setInterval(maintenance, 10_000);

  addEvent({
    type: "monitor_started",
    severity: "info",
    message: "SentinelGuard monitoring started",
    details: {
      hostname: os.hostname(),
      platform: process.platform
    }
  });

  console.log("[+] Monitoring active");
}

process.on("SIGINT", () => {
  console.log("\n[+] Shutting down");
  process.exit(0);
});

process.on("SIGTERM", () => {
  console.log("\n[+] Shutting down");
  process.exit(0);
});

main().catch((err) => {
  console.error("[FATAL]", err);
  process.exit(1);
});

