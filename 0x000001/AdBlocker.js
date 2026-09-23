#!/usr/bin/env node
/**
 * Sentinel AdBlock — Zero-dependency Node.js ad-blocking proxy
 *
 * Usage:
 *   node adblock.js --port 8080
 *   node adblock.js --port 8080 --blocklist ./easylist.txt
 *   node adblock.js --port 8080 --stats
 *
 * Set your system/browser proxy to http://localhost:8080
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ─── Config ───────────────────────────────────────────────────────────────────
const CONFIG = {
  port: 8080,
  blocklistFile: './blocklist.txt',
  logFile: './adblock.log',
  stats: false,
  // Built-in default blocklist (top ad/tracker domains)
  defaultBlocklist: [
    'doubleclick.net', 'googlesyndication.com', 'google-analytics.com',
    'googleadservices.com', 'googletagservices.com', 'adservice.google.com',
    'adservice.google.com', 'admob.com', 'adnxs.com', 'amazon-adsystem.com',
    'applovin.com', 'criteo.com', 'criteo.net', 'pubmatic.com',
    'rubiconproject.com', 'taboola.com', 'outbrain.com', 'taboola.com',
    'scorecardresearch.com', 'quantserve.com', 'quantcount.com',
    'moatads.com', 'moatpixel.com', 'adcolony.com', 'unityads.unity3d.com',
    'facebook.net', 'facebook.com/tr', 'fbcdn.net',
    'twitter.com/i/ad', 'ads-twitter.com',
    'taboola.com', 'outbrain.com', 'viglink.com', 'impactradius.com',
    'media.net', 'adform.net', 'adform.com', 'adtech.us',
    'adtech.de', 'adtech.co.uk', 'adtech.com', 'adtechjp.com',
    'adtechus.com', 'advertising.com', 'advertising.com',
    'adroll.com', 'adstir.com', 'adswizz.com', 'adtden.com',
    'adthrive.com', 'adtigergarage.com', 'adtoll.com',
    'advertising.com', 'advertising.aol.com', 'advertising.com',
    'advertising.microsoft.com', 'advertising.com',
    'adsrvr.org', 'adswizz.com', 'adtech.com',
    'anymind.com', 'appnext.com', 'bidswitch.net',
    'casalemedia.com', 'comscore.com', 'demdex.net',
    'emxdigital.com', 'exoclick.com', 'indexww.com',
    'inmobi.com', 'kargo.com', 'liftoff.io',
    'mopub.com', 'openx.net', 'openx.com',
    'optimizely.com', 'pubmatic.com', 'pubwise.com',
    'revcontent.com', 'serving-sys.com', 'sharethrough.com',
    'smartadserver.com', 'smrtconnect.com', 'spotxchange.com',
    'tapad.com', 'tapjoy.com', 'teads.tv',
    'theadex.com', 'thebroadcaster.com', 'thirtyfive.com',
    'tremorhub.com', 'turn.com', 'undertone.com',
    'unruly.com', 'viant.com', 'yieldmo.com',
    'yieldselect.com', 'yieldlab.net', 'zedo.com',
    'zedo.com', 'zeta.net', 'zedo.com',
    // Analytics / fingerprinting
    'hotjar.com', 'mixpanel.com', 'segment.io', 'amplitude.com',
    'heap.io', 'luckyorange.com', 'crazyegg.com',
    'fullstory.com', 'mouseflow.com', 'clarity.ms',
    // Crypto miners
    'coin-hive.com', 'cryptoloot.pro', 'jsecoin.com',
    'minero-proxy.org', 'webminerpool.com',
  ],
};

// Parse CLI args
const args = process.argv.slice(2);
for (let i = 0; i < args.length; i++) {
  switch (args[i]) {
    case '--port':       CONFIG.port = parseInt(args[++i]); break;
    case '--blocklist':  CONFIG.blocklistFile = args[++i]; break;
    case '--stats':      CONFIG.stats = true; break;
  }
}

// ─── Stats ────────────────────────────────────────────────────────────────────
const stats = {
  total: 0, blocked: 0, passed: 0, errors: 0,
  blockedDomains: new Map(),
  startTime: Date.now(),
};

// ─── Logger ───────────────────────────────────────────────────────────────────
function log(level, msg, data = {}) {
  const entry = { ts: new Date().toISOString(), level, msg, ...data };
  const colors = { INFO: '\x1b[36m', BLOCK: '\x1b[31m', PASS: '\x1b[32m', WARN: '\x1b[33m' };
  console.log(`${colors[level] || ''} [${level}] ${msg}\x1b[0m`);
  if (level === 'BLOCK') fs.appendFileSync(CONFIG.logFile, JSON.stringify(entry) + '\n');
}

// ─── Blocklist Engine ─────────────────────────────────────────────────────────
class BlocklistEngine {
  constructor() {
    this.domains = new Set();
    this.patterns = []; // regex patterns for URL-based blocking
  }

  load(file) {
    if (!fs.existsSync(file)) {
      console.log(`Blocklist file not found: ${file}. Using built-in defaults.`);
      this.loadDefaults();
      return;
    }

    const lines = fs.readFileSync(file, 'utf-8').split('\n');
    let count = 0;

    for (const raw of lines) {
      const line = raw.trim();
      if (!line || line.startsWith('!') || line.startsWith('[')) continue;

      // Remove [email protected] and similar
      const clean = line.replace(/\[.*?\]/g, '');

      if (clean.startsWith('||') && clean.endsWith('/')) {
        // ||domain.com/^ → domain block
        const domain = clean.slice(2, -1);
        this.domains.add(domain.toLowerCase());
        count++;
      } else if (clean.startsWith('||') && !clean.endsWith('/')) {
        // ||domain.com/path → pattern
        const domain = clean.slice(2).split('/')[0];
        this.domains.add(domain.toLowerCase());
        count++;
      } else if (clean.startsWith('$')) {
        // Skip rule-type-only lines
        continue;
      } else if (clean.includes('.')) {
        // Bare domain
        const domain = clean.split('/')[0].split(':')[0].toLowerCase();
        this.domains.add(domain);
        count++;
      }
    }

    console.log(`Loaded ${count} domains from ${file}`);
  }

  loadDefaults() {
    for (const d of CONFIG.defaultBlocklist) {
      this.domains.add(d.toLowerCase());
    }
    console.log(`Using built-in blocklist: ${this.domains.size} domains`);
  }

  isBlocked(hostname, url = '') {
    const host = hostname.toLowerCase();

    // Exact match
    if (this.domains.has(host)) return true;

    // Subdomain match (ads.doubleclick.net matches doubleclick.net)
    const parts = host.split('.');
    for (let i = 1; i < parts.length; i++) {
      const parent = parts.slice(i).join('.');
      if (this.domains.has(parent)) return true;
    }

    // Wildcard: *.domain.com
    for (const d of this.domains) {
      if (d.startsWith('*.')) {
        const base = d.slice(2);
        if (host === base || host.endsWith('.' + base)) return true;
      }
    }

    return false;
  }

  get size() { return this.domains.size; }
}

// ─── Proxy Server ─────────────────────────────────────────────────────────────
function createProxyServer(engine) {
  return http.createServer((req, res) => {
    stats.total++;
    const url = new URL(req.url, `http://${req.headers.host}`);
    const hostname = url.hostname;

    // ── Check blocklist ──
    if (engine.isBlocked(hostname, url.pathname)) {
      stats.blocked++;
      stats.blockedDomains.set(hostname, (stats.blockedDomains.get(hostname) || 0) + 1);
      log('BLOCK', hostname, { url: url.pathname, method: req.method });

      // Return a 204 No Content (invisible block)
      res.writeHead(204, {
        'Content-Type': 'text/plain',
        'X-AdBlock': 'blocked',
        'X-Blocked-Domain': hostname,
      });
      res.end();
      return;
    }

    // ── Allow: proxy the request ──
    stats.passed++;

    const isHttps = url.protocol === 'https:';
    const lib = isHttps ? https : http;

    const options = {
      hostname: url.hostname,
      port: isHttps ? 443 : 80,
      path: url.pathname + url.search,
      method: req.method,
      headers: { ...req.headers },
    };

    // Fix host header
    options.headers.host = url.hostname;

    const proxyReq = lib.request(options, (proxyRes) => {
      res.writeHead(proxyRes.statusCode, proxyRes.headers);

      // Modify response: strip ad-related headers
      delete res.headers['x-ad-network'];

      proxyRes.pipe(res);
    });

    proxyReq.on('error', (err) => {
      stats.errors++;
      log('WARN', `Proxy error: ${err.message}`, { hostname });
      res.writeHead(502, { 'Content-Type': 'text/plain' });
      res.end('Bad Gateway');
    });

    req.pipe(proxyReq);
  });
}

// ─── Stats Endpoint ───────────────────────────────────────────────────────────
function attachStats(server) {
  const origEmit = server.emit;
  // We'll use a separate lightweight server for stats
}

function startStatsServer(engine) {
  const statsServer = http.createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');

    if (req.url === '/stats') {
      const top = [...stats.blockedDomains.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 20)
        .map(([domain, count]) => ({ domain, count }));

      res.end(JSON.stringify({
        uptime: Math.round((Date.now() - stats.startTime) / 1000) + 's',
        totalRequests: stats.total,
        blocked: stats.blocked,
        passed: stats.passed,
        errors: stats.errors,
        blockRate: stats.total ? (stats.blocked / stats.total * 100).toFixed(1) + '%' : '0%',
        blocklistSize: engine.size,
        topBlocked: top,
      }));
    } else if (req.url === '/blocklist') {
      res.end(JSON.stringify([...engine.domains].sort()));
    } else if (req.url === '/health') {
      res.end(JSON.stringify({ status: 'ok', blocklistSize: engine.size }));
    } else {
      res.statusCode = 404;
      res.end(JSON.stringify({ error: 'Not found' }));
    }
  });

  statsServer.listen(CONFIG.port + 1, () => {
    console.log(`\n📊 Stats: http://localhost:${CONFIG.port + 1}/stats`);
    console.log(`📋 Blocklist: http://localhost:${CONFIG.port + 1}/blocklist`);
  });
}

// ─── Main ─────────────────────────────────────────────────────────────────────
function main() {
  console.log('╔══════════════════════════════════════╗');
  console.log('║   SENTINEL ADBLOCK v1.0         ║');
  console.log('║   Zero-dependency Node.js proxy  ║');
  console.log('╚══════════════════════════════════════╝\n');

  // Load blocklist
  const engine = new BlocklistEngine();
  engine.load(CONFIG.blocklistFile);

  // Start proxy
  const server = createProxyServer(engine);
  server.listen(CONFIG.port, () => {
    console.log(`\n🛡️  Proxy running: http://localhost:${CONFIG.port}`);
    console.log(`📋 Blocklist: ${engine.size} domains`);
    console.log(`\nSet your system proxy to: http://localhost:${CONFIG.port}\n`);
  });

  // Stats
  if (CONFIG.stats) startStatsServer(engine);

  // Periodic stats log
  setInterval(() => {
    if (stats.total > 0) {
      console.log(
        `  [${Math.round((Date.now() - stats.startTime) / 1000)}s] ` +
        `Total: ${stats.total} | Blocked: ${stats.blocked} (${(stats.blocked/stats.total*100).toFixed(1)}%) | ` +
        `Passed: ${stats.passed} | Errors: ${stats.errors}`
      );
    }
  }, 30000);

  process.on('SIGINT', () => {
    console.log('\nShutting down...');
    server.close();
    process.exit(0);
  });
}

main();   
