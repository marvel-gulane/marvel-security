#!/usr/bin/env node
/**
 * Sentinel AV — Single-file Node.js antivirus powered by ClamAV
 * Usage: node antivirus.js [options]
 *
 * Options:
 *   --watch <dir>       Watch a directory for new/changed files
 *   --scan <dir>        One-shot recursive scan of a directory
 *   --port <n>          Start HTTP API on port (default: 3000)
 *   --quarantine <dir>  Quarantine infected files (default: ./quarantine)
 *   --auto-update       Run freshclam every 12 hours
 */

const { spawn, execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const http = require('http');

// ─── Config ───────────────────────────────────────────────────────────────────
const CONFIG = {
  clamscanPath: '/usr/bin/clamscan',
  freshclamPath: '/usr/bin/freshclam',
  clamavDb: '/var/lib/clamav',       // ClamAV database location
  tempDir: '/tmp/clamav-sentinel',
  maxFileSizeMB: 200,
  scanArchives: true,
  port: 3000,
  quarantineDir: './quarantine',
  watchDirs: [],
  logFile: './av-alerts.log',
  autoUpdate: false,
  updateIntervalMs: 12 * 60 * 60 * 1000, // 12 hours
};

// ─── Parse CLI args ───────────────────────────────────────────────────────────
const args = process.argv.slice(2);
for (let i = 0; i < args.length; i++) {
  switch (args[i]) {
    case '--watch':      CONFIG.watchDirs.push(args[++i]); break;
    case '--scan':       CONFIG.scanDirs = [args[++i]]; break;
    case '--port':       CONFIG.port = parseInt(args[++i]); break;
    case '--quarantine': CONFIG.quarantineDir = args[++i]; break;
    case '--auto-update': CONFIG.autoUpdate = true; break;
  }
}

// ─── Logger ───────────────────────────────────────────────────────────────────
function log(level, message, data = {}) {
  const entry = { ts: new Date().toISOString(), level, message, ...data };
  const line = JSON.stringify(entry);
  const colors = { INFO: '\x1b[36m', WARN: '\x1b[33m', CRIT: '\x1b[31m', ALERT: '\x1b[41m\x1b[97m' };
  console.log(`${colors[level] || ''} [${level}] ${message}\x1b[0m`);
  fs.appendFileSync(CONFIG.logFile, line + '\n');
}

// ─── Core: Scan a file using clamscan ─────────────────────────────────────────
function scanFile(filePath) {
  return new Promise((resolve) => {
    // Ensure file exists and isn't too large
    try {
      const stat = fs.statSync(filePath);
      if (stat.size > CONFIG.maxFileSizeMB * 1024 * 1024) {
        return resolve({ status: 'skipped', reason: `File too large (${(stat.size/1024/1024).toFixed(1)}MB)` });
      }
    } catch (e) {
      return resolve({ status: 'error', reason: 'File not found' });
    }

    const cmd = [
      '--no-summary',
      '--database=' + CONFIG.clamavDb,
      '--tempdir=' + CONFIG.tempDir,
      CONFIG.scanArchives ? '--allmatch' : '',
      filePath,
    ].filter(Boolean);

    const proc = spawn(CONFIG.clamscanPath, cmd, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', d => stdout += d);
    proc.stderr.on('data', d => stderr += d);

    proc.on('error', (err) => {
      resolve({ status: 'error', reason: err.message });
    });

    proc.on('close', (code) => {
      // Exit codes: 0=clean, 1=infected, 2=error
      if (code === 0) {
        resolve({ status: 'clean', file: filePath });
      } else if (code === 1) {
        // Parse virus name from output: "file: Eicar-Signature FOUND"
        const match = stdout.match(/: (.+) FOUND/);
        const virus = match ? match[1] : 'Unknown';
        resolve({ status: 'infected', file: filePath, virus });
      } else {
        resolve({ status: 'error', file: filePath, reason: stderr.slice(0, 200) || `exit code ${code}` });
      }
    });
  });
}

// ─── Recursive directory scan ─────────────────────────────────────────────────
async function scanDirectory(dir, results = { clean: 0, infected: 0, errors: 0, skipped: 0, findings: [] }) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      // Skip node_modules, .git, quarantine
      if (['node_modules', '.git', CONFIG.quarantineDir].includes(entry.name)) continue;
      await scanDirectory(fullPath, results);
    } else if (entry.isFile()) {
      const result = await scanFile(fullPath);
      results[result.status] = (results[result.status] || 0) + 1;

      if (result.status === 'infected') {
        results.findings.push(result);
        log('ALERT', `MALWARE DETECTED`, { file: fullPath, virus: result.virus });
        quarantineFile(fullPath, result.virus);
      } else if (result.status === 'error') {
        log('WARN', 'Scan error', { file: fullPath, reason: result.reason });
      }
    }
  }
  return results;
}

// ─── Quarantine ───────────────────────────────────────────────────────────────
function quarantineFile(filePath, virus) {
  try {
    if (!fs.existsSync(CONFIG.quarantineDir)) {
      fs.mkdirSync(CONFIG.quarantineDir, { recursive: true });
    }
    const safeName = path.basename(filePath) + '.' + Date.now() + '.quarantined';
    fs.renameSync(filePath, path.join(CONFIG.quarantineDir, safeName));
    log('INFO', 'File quarantined', { from: filePath, virus });
  } catch (e) {
    log('WARN', 'Quarantine failed', { file: filePath, error: e.message });
  }
}

// ─── File watcher (inotify via fs.watch) ─────────────────────────────────────
function watchDirectory(dir) {
  log('INFO', `Watching directory`, { dir });

  fs.watch(dir, { recursive: true }, (eventType, filename) => {
    if (!filename) return;
    const fullPath = path.join(dir, filename);

    // Ignore quarantine dir and hidden files
    if (fullPath.includes(CONFIG.quarantineDir)) return;
    if (path.basename(filename).startsWith('.')) return;

    // Small delay to let the file finish writing
    setTimeout(async () => {
      try {
        if (!fs.existsSync(fullPath)) return; // deleted before we checked
        const result = await scanFile(fullPath);

        if (result.status === 'infected') {
          log('ALERT', 'WATCH: MALWARE DETECTED', { file: fullPath, virus: result.virus, event: eventType });
          quarantineFile(fullPath, result.virus);
        } else if (result.status === 'clean') {
          // log('INFO', 'WATCH: clean', { file: fullPath });
        }
      } catch (e) {
        // Ignore transient errors (file in use, etc.)
      }
    }, 500);
  });
}

// ─── HTTP API ─────────────────────────────────────────────────────────────────
function startHttpServer() {
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://localhost:${CONFIG.port}`);

    // CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

    // GET /status — engine health
    if (req.method === 'GET' && url.pathname === '/status') {
      try {
        const ver = execSync(`${CONFIG.clamscanPath} --version 2>/dev/null | head -1`, { encoding: 'utf-8' });
        const dbInfo = execSync(`${CONFIG.clamscanPath} --version 2>/dev/null | grep -oP 'Database version: \\K.*' || echo "unknown"`, { encoding: 'utf-8' }).trim();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          status: 'ok',
          engine: ver.trim(),
          database: dbInfo,
          pid: process.pid,
          uptime: process.uptime(),
        }));
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ status: 'error', message: e.message }));
      }
    }

    // POST /scan — scan a file path (JSON body: { "path": "/tmp/file" })
    if (req.method === 'POST' && url.pathname === '/scan') {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', async () => {
        try {
          const { path: filePath } = JSON.parse(body);
          if (!filePath) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: 'Missing "path" field' }));
          }
          const result = await scanFile(filePath);
          const status = result.status === 'infected' ? 200 : result.status === 'error' ? 500 : 200;
          res.writeHead(status, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(result));
        } catch (e) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: e.message }));
        }
      });
      return;
    }

    // POST /scan/upload — scan an uploaded file (multipart not supported, use raw body)
    if (req.method === 'POST' && url.pathname === '/scan/upload') {
      const chunks = [];
      req.on('data', chunk => chunks.push(chunk));
      req.on('end', async () => {
        try {
          const buffer = Buffer.concat(chunks);
          // Write to temp file for clamscan
          const tmpFile = path.join(CONFIG.tempDir, `upload_${Date.now()}`);
          if (!fs.existsSync(CONFIG.tempDir)) fs.mkdirSync(CONFIG.tempDir, { recursive: true });
          fs.writeFileSync(tmpFile, buffer);

          const result = await scanFile(tmpFile);
          fs.unlinkSync(tmpFile); // cleanup

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(result));
        } catch (e) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: e.message }));
        }
      });
      return;
    }

    // GET /alerts — last 50 alerts from log
    if (req.method === 'GET' && url.pathname === '/alerts') {
      try {
        const lines = fs.readFileSync(CONFIG.logFile, 'utf-8').trim().split('\n').slice(-50);
        const alerts = lines.map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(alerts));
      } catch {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify([]));
      }
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found' }));
  });

  server.listen(CONFIG.port, () => {
    log('INFO', `HTTP API listening`, { port: CONFIG.port });
  });
}

// ─── Auto-update ClamAV database ─────────────────────────────────────────────
function scheduleDbUpdate() {
  if (!CONFIG.autoUpdate) return;

  const update = () => {
    log('INFO', 'Running freshclam (DB update)...');
    try {
      const output = execSync(CONFIG.freshclamPath, { encoding: 'utf-8', timeout: 300000 });
      log('INFO', 'DB updated', { output: output.split('\n').slice(-3).join(' | ') });
    } catch (e) {
      log('WARN', 'DB update failed', { error: e.message });
    }
  };

  update(); // Run once at startup
  setInterval(update, CONFIG.updateIntervalMs);
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  log('INFO', '=== Sentinel AV Starting ===');
  log('INFO', 'Engine', { clamscan: CONFIG.clamscanPath, db: CONFIG.clamavDb });

  // Ensure temp dir exists
  if (!fs.existsSync(CONFIG.tempDir)) fs.mkdirSync(CONFIG.tempDir, { recursive: true });

  // Verify clamscan is available
  try {
    const ver = execSync(`${CONFIG.clamscanPath} --version 2>&1 | head -1`, { encoding: 'utf-8' });
    log('INFO', 'ClamAV version', { version: ver.trim() });
  } catch (e) {
    log('CRIT', 'clamscan not found. Install ClamAV: sudo apt install clamav');
    process.exit(1);
  }

  // Schedule DB updates
  scheduleDbUpdate();

  // One-shot scan
  if (CONFIG.scanDirs) {
    for (const dir of CONFIG.scanDirs) {
      log('INFO', `Scanning directory: ${dir}`);
      const results = await scanDirectory(dir);
      log('INFO', 'Scan complete', {
        clean: results.clean,
        infected: results.infected,
        errors: results.errors,
        skipped: results.skipped,
      });
      if (results.findings.length > 0) {
        log('ALERT', 'Infected files found', { count: results.findings.length, files: results.findings.map(f => f.file) });
      }
    }
  }

  // Watch directories
  for (const dir of CONFIG.watchDirs) {
    if (fs.existsSync(dir)) {
      watchDirectory(dir);
    } else {
      log('WARN', 'Watch directory not found', { dir });
    }
  }

  // HTTP API (always start unless only --scan was used)
  if (!CONFIG.scanDirs || CONFIG.watchDirs.length > 0) {
    startHttpServer();
  }

  log('INFO', 'Sentinel AV ready');

  // Graceful shutdown
  process.on('SIGINT', () => { log('INFO', 'Shutting down'); process.exit(0); });
  process.on('SIGTERM', () => { log('INFO', 'Shutting down'); process.exit(0); });
}

main().catch(err => {
  log('CRIT', 'Fatal', { error: err.message, stack: err.stack });
  process.exit(1);
});   
