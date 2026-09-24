#!/usr/bin/env node
// secdash.js — Single-file security tools dashboard for Fedora Security Lab
// Usage: sudo node secdash.js
// Open: http://localhost:8443

const http = require('http');
const { exec, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const PORT = 8100;
const TOOLS = {
  nmap:      { label: 'Nmap',      desc: 'Port / service scan',      cmd: 'nmap' },
  nikto:     { label: 'Nikto',     desc: 'Web server vuln scan',     cmd: 'nikto' },
  sqlmap:    { label: 'SQLMap',    desc: 'SQL injection tester',     cmd: 'sqlmap' },
  whatweb:   { label: 'WhatWeb',   desc: 'Tech fingerprinting',      cmd: 'whatweb' },
  dirb:      { label: 'Dirb',      desc: 'Directory brute-force',    cmd: 'dirb' },
  hydra:     { label: 'Hydra',     desc: 'Password cracker',         cmd: 'hydra' },
  john:      { label: 'John',      desc: 'Hash cracker',             cmd: 'john' },
  searchsploit: { label: 'SearchSploit', desc: 'Exploit-DB search',  cmd: 'searchsploit' },
  ffuf:      { label: 'FFuF',      desc: 'Web fuzzer',              cmd: 'ffuf' },
  gobuster:  { label: 'Gobuster',  desc: 'Directory / DNS brute',   cmd: 'gobuster' },
  nuclei:    { label: 'Nuclei',    desc: 'Template-based scanner',  cmd: 'nuclei' },
  testssl:   { label: 'testssl.sh',desc: 'SSL/TLS audit',           cmd: 'testssl.sh' },
  chkrootkit: { label: 'chkrootkit', desc: 'Detection / Configuration', cmd: 'chkrootkit',},
};

// Track running processes
const running = new Map(); // id -> { proc, tool, target }
let nextId = 1;

// --- HTML (served at /) ---
const HTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>SecDash</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#c9d1d9;padding:20px}
h1{color:#58a6ff;margin-bottom:4px}
.sub{color:#8b949e;margin-bottom:24px;font-size:14px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:16px;margin-bottom:32px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px}
.card h3{color:#58a6ff;font-size:15px;margin-bottom:4px}
.card p{color:#8b949e;font-size:13px;margin-bottom:12px}
.card input{width:100%;padding:8px 10px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#c9d1d9;font-size:13px;margin-bottom:8px}
.card input::placeholder{color:#484f58}
.card button{width:100%;padding:8px;background:#238636;color:#fff;border:none;border-radius:6px;cursor:pointer;font-size:13px;font-weight:600}
.card button:hover{background:#2ea043}
.card button:disabled{background:#21262d;color:#484f58;cursor:not-allowed}
#results{margin-top:8px}
.result-block{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin-bottom:16px}
.result-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}
.result-header span{color:#58a6ff;font-weight:600;font-size:14px}
.result-header .stop{background:#da3633;color:#fff;border:none;padding:4px 12px;border-radius:4px;cursor:pointer;font-size:12px}
.result-header .stop:hover{background:#f85149}
pre{background:#0d1117;padding:12px;border-radius:6px;font-size:12px;overflow-x:auto;max-height:400px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;color:#8b949e;font-family:'Cascadia Code','Fira Code',monospace}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600}
.badge.running{background:#1f6feb33;color:#58a6ff}
.badge.done{background:#23863633;color:#3fb950}
.badge.error{background:#da363333;color:#f85149}
</style></head><body>
<h1>🛡️ SecDash</h1>
<p class="sub">Fedora Security Lab — single-file Node.js dashboard</p>
<div class="grid" id="tools"></div>
<h2 style="color:#58a6ff;margin-bottom:12px;font-size:16px">Results</h2>
<div id="results"><p style="color:#484f58;font-size:13px">No scans yet.</p></div>
<script>
const tools = ${JSON.stringify(Object.values(TOOLS).map(t => ({ id: Object.keys(TOOLS).find(k => TOOLS[k] === t), label: t.label, desc: t.desc })))};
const grid = document.getElementById('tools');
tools.forEach(t => {
  const card = document.createElement('div');
  card.className = 'card';
  card.innerHTML = \`<h3>\${t.label}</h3><p>\${t.desc}</p>
    <input id="tgt-\${t.id}" placeholder="target (IP, URL, hash…)">
    <input id="args-\${t.id}" placeholder="extra args (optional)">
    <button id="btn-\${t.id}" onclick="run('\${t.id}')">Run</button>\`;
  grid.appendChild(card);
});
async function run(id){
  const target = document.getElementById('tgt-'+id).value.trim();
  const args = document.getElementById('args-'+id).value.trim();
  if(!target){ alert('Enter a target'); return; }
  const btn = document.getElementById('btn-'+id);
  btn.disabled = true; btn.textContent = 'Running…';
  const res = await fetch('/api/run', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tool:id,target,args})});
  const data = await res.json();
  if(data.error){ btn.disabled=false; btn.textContent='Run'; alert(data.error); return; }
  addResult(data.id, id, target);
  poll(data.id);
}
function addResult(id, tool, target){
  const div = document.createElement('div');
  div.className='result-block'; div.id='res-'+id;
  div.innerHTML=\`<div class="result-header"><span>\${tool.toUpperCase()} — \${target} <span class="badge running">running</span></span>
    <button class="stop" onclick="stopScan(\${id})">Stop</button></div><pre id="out-\${id}"></pre>\`;
  document.getElementById('results').prepend(div);
}
function poll(id){
  const iv = setInterval(async () => {
    const r = await fetch('/api/output/'+id);
    const d = await r.json();
    document.getElementById('out-'+id).textContent = d.output;
    if(d.status !== 'running'){
      clearInterval(iv);
      const badge = document.querySelector('#res-'+id+' .badge');
      badge.className = 'badge ' + (d.status==='done'?'done':'error');
      badge.textContent = d.status;
      const btn = document.getElementById('btn-'+d.tool);
      if(btn){btn.disabled=false;btn.textContent='Run';}
    }
  }, 800);
}
async function stopScan(id){
  await fetch('/api/stop/'+id,{method:'POST'});
}
</script></body></html>`;

// --- Server ---
const server = http.createServer((req, res) => {
  // CORS not needed (same origin)
  if (req.method === 'GET' && req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    return res.end(HTML);
  }

  // POST /api/run  { tool, target, args }
  if (req.method === 'POST' && req.url === '/api/run') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      try {
        const { tool, target, args } = JSON.parse(body);
        const t = TOOLS[tool];
        if (!t) { res.writeHead(400); return res.end(JSON.stringify({ error: 'Unknown tool' })); }

        // Build command: toolCmd + target + extra args
        const cmdParts = [t.cmd];
        // Heuristic: for nmap/whatweb/dirb/gobuster the target is positional;
        // for nikto use -h, sqlmap -u, hydra -s, testssl https://
        switch (tool) {
          case 'nikto':     cmdParts.push('-h', target); break;
          case 'sqlmap':    cmdParts.push('-u', target); break;
          case 'testssl':   cmdParts.push(target.startsWith('http') ? target : 'https://' + target); break;
          case 'hydra':     cmdParts.push('-s', target); break;
          default:          cmdParts.push(target);
        }
        if (args) cmdParts.push(...args.split(/\s+/));

        const id = nextId++;
        const proc = spawn(t.cmd, cmdParts.slice(1), {
          env: { ...process.env, TERM: 'dumb' }
        });
        let output = '';
        proc.stdout.on('data', d => output += d.toString());
        proc.stderr.on('data', d => output += d.toString());
        proc.on('close', code => {
          running.delete(id);
          if (code !== 0 && code !== null) output += `\n\n[exited with code ${code}]`;
        });
        running.set(id, { proc, tool, target, output: () => output });

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ id, tool }));
      } catch (e) {
        res.writeHead(500);
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  // GET /api/output/:id
  if (req.method === 'GET' && req.url.startsWith('/api/output/')) {
    const id = parseInt(req.url.split('/').pop());
    const entry = running.get(id);
    if (!entry) {
      res.writeHead(404);
      return res.end(JSON.stringify({ error: 'Not found', status: 'done', output: '' }));
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ output: entry.output(), status: 'running', tool: entry.tool }));
    return;
  }

  // POST /api/stop/:id
  if (req.method === 'POST' && req.url.startsWith('/api/stop/')) {
    const id = parseInt(req.url.split('/').pop());
    const entry = running.get(id);
    if (entry) {
      entry.proc.kill('SIGTERM');
      setTimeout(() => { if (entry.proc.exitCode === null) entry.proc.kill('SIGKILL'); }, 3000);
    }
    res.writeHead(200);
    res.end('ok');
    return;
  }

  res.writeHead(404);
  res.end('Not found');
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n  🛡️  SecDash running → http://localhost:${PORT}`);
  console.log('  Run as root/sudo for full tool access.\n');
});   
