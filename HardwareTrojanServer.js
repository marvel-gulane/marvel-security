"use strict";

const http = require("http");
const fs = require("fs");
const fsp = fs.promises;
const path = require("path");
const crypto = require("crypto");
const os = require("os");
const { execFile } = require("child_process");

const PORT = 8080;

const WATCH_DIRS = [
    "/etc",
    path.join(os.homedir(), ".config"),
    path.join(os.homedir(), ".local/bin")
];

const state = {
    started: new Date().toISOString(),
    alerts: [],
    files: {
        scanned: 0,
        changed: 0,
        created: 0,
        removed: 0
    },
    hardware: {
        baseline: "",
        current: "",
        changed: false
    },
    firmware: {
        current: "",
        changed: false
    },
    processes: 0
};

const baseline = new Map();

function alert(type, message) {
    const item = {
        time: new Date().toISOString(),
        type,
        message
    };

    state.alerts.unshift(item);

    // Keep dashboard memory bounded.
    state.alerts = state.alerts.slice(0, 200);

    console.log(`[${type}] ${message}`);
}

async function hashFile(file) {
    return new Promise((resolve, reject) => {
        const hash = crypto.createHash("sha256");
        const stream = fs.createReadStream(file);

        stream.on("data", chunk => hash.update(chunk));
        stream.on("end", () => resolve(hash.digest("hex")));
        stream.on("error", reject);
    });
}

async function walk(dir, callback) {
    let entries;

    try {
        entries = await fsp.readdir(dir, {
            withFileTypes: true
        });
    } catch {
        return;
    }

    for (const entry of entries) {
        const file = path.join(dir, entry.name);

        if (entry.isSymbolicLink()) {
            continue;
        }

        if (entry.isDirectory()) {
            await walk(file, callback);
        } else if (entry.isFile()) {
            await callback(file);
        }
    }
}

async function createFileBaseline() {
    baseline.clear();

    for (const dir of WATCH_DIRS) {
        await walk(dir, async file => {
            try {
                const hash = await hashFile(file);
                baseline.set(file, hash);
                state.files.scanned++;
            } catch {
                // File may disappear while scanning.
            }
        });
    }

    console.log(
        `File baseline: ${baseline.size} files`
    );
}

async function scanFiles() {
    const current = new Map();

    for (const dir of WATCH_DIRS) {
        await walk(dir, async file => {
            try {
                current.set(file, await hashFile(file));
            } catch {}
        });
    }

    for (const [file, hash] of current) {
        if (!baseline.has(file)) {
            state.files.created++;
            alert("FILE_CREATED", file);
            continue;
        }

        if (baseline.get(file) !== hash) {
            state.files.changed++;

            alert(
                "FILE_MODIFIED",
                `${file}\nSHA256 changed`
            );
        }
    }

    for (const file of baseline.keys()) {
        if (!current.has(file)) {
            state.files.removed++;

            alert(
                "FILE_REMOVED_OR_RENAMED",
                file
            );
        }
    }

    baseline.clear();

    for (const [file, hash] of current) {
        baseline.set(file, hash);
    }
}

function execute(command, args) {
    return new Promise(resolve => {
        execFile(
            command,
            args,
            {
                timeout: 8000,
                maxBuffer: 5 * 1024 * 1024
            },
            (error, stdout) => {
                resolve(
                    error ? "" : stdout
                );
            }
        );
    });
}

async function getHardwareInventory() {
    const outputs = [];

    for (const [cmd, args] of [
        ["lscpu", []],
        ["lspci", ["-nn"]],
        ["lsusb", []],
        ["lsblk", ["-o", "NAME,SIZE,MODEL,SERIAL,TYPE"]]
    ]) {
        const output = await execute(cmd, args);

        if (output) {
            outputs.push(
                `### ${cmd}\n${output}`
            );
        }
    }

    return outputs.join("\n");
}

async function scanHardware() {
    const current =
        await getHardwareInventory();

    state.hardware.current = current;

    if (!state.hardware.baseline) {
        state.hardware.baseline = current;
        return;
    }

    if (current !== state.hardware.baseline) {
        if (!state.hardware.changed) {
            alert(
                "HARDWARE_INVENTORY_CHANGED",
                "PCI/USB/storage/CPU inventory differs from baseline."
            );
        }

        state.hardware.changed = true;
    }
}

async function scanFirmware() {
    const output = await execute(
        "fwupdmgr",
        ["get-devices"]
    );

    if (!output) {
        return;
    }

    if (!state.firmware.current) {
        state.firmware.current = output;
        return;
    }

    if (output !== state.firmware.current) {
        if (!state.firmware.changed) {
            alert(
                "FIRMWARE_INVENTORY_CHANGED",
                "fwupd device/firmware information changed."
            );
        }

        state.firmware.changed = true;
    }
}

async function scanProcesses() {
    const output = await execute(
        "ps",
        ["-eo", "pid,user,comm,args"]
    );

    if (!output) {
        return;
    }

    state.processes =
        output.trim().split("\n").length - 1;

    for (const line of output.split("\n")) {
        // Informational detection only.
        if (
            line.includes("/tmp/") ||
            line.includes("/dev/shm/")
        ) {
            alert(
                "SUSPICIOUS_PROCESS_LOCATION",
                line.trim()
            );
        }
    }
}

function dashboard() {
    return `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Native Security Monitor</title>

<style>
body {
    background: #0b1020;
    color: #e6edf3;
    font-family: system-ui, sans-serif;
    margin: 0;
}

header {
    background: #111827;
    padding: 20px 30px;
    border-bottom: 1px solid #263244;
}

h1 {
    margin: 0;
    color: #60a5fa;
}

main {
    padding: 25px;
    max-width: 1200px;
    margin: auto;
}

.grid {
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(210px, 1fr));
    gap: 15px;
}

.card {
    background: #111827;
    border: 1px solid #263244;
    border-radius: 10px;
    padding: 18px;
}

.value {
    font-size: 30px;
    font-weight: bold;
    margin-top: 8px;
}

.good {
    color: #34d399;
}

.warning {
    color: #fbbf24;
}

.danger {
    color: #f87171;
}

.alert {
    border-left: 4px solid #f87171;
    margin: 8px 0;
    padding: 12px;
    background: #171d2b;
    white-space: pre-wrap;
}

small {
    color: #94a3b8;
}
</style>
</head>

<body>

<header>
<h1>Native Security Monitor</h1>
<small>
Fedora host security dashboard
</small>
</header>

<main>

<div class="grid">

<div class="card">
Files scanned
<div id="scanned" class="value">0</div>
</div>

<div class="card">
File changes
<div id="changes" class="value">0</div>
</div>

<div class="card">
Created
<div id="created" class="value">0</div>
</div>

<div class="card">
Removed / renamed
<div id="removed" class="value">0</div>
</div>

<div class="card">
Processes
<div id="processes" class="value">0</div>
</div>

<div class="card">
Hardware
<div id="hardware" class="value good">OK</div>
</div>

<div class="card">
Firmware
<div id="firmware" class="value good">OK</div>
</div>

</div>

<h2>Security Alerts</h2>

<div id="alerts">
Loading...
</div>

</main>

<script>
async function update() {
    const response = await fetch("/api/status");
    const data = await response.json();

    document.getElementById("scanned")
        .textContent = data.files.scanned;

    document.getElementById("changes")
        .textContent = data.files.changed;

    document.getElementById("created")
        .textContent = data.files.created;

    document.getElementById("removed")
        .textContent = data.files.removed;

    document.getElementById("processes")
        .textContent = data.processes;

    const hardware =
        document.getElementById("hardware");

    hardware.textContent =
        data.hardware.changed ? "CHANGE" : "OK";

    hardware.className =
        "value " +
        (data.hardware.changed
            ? "danger"
            : "good");

    const firmware =
        document.getElementById("firmware");

    firmware.textContent =
        data.firmware.changed ? "CHANGE" : "OK";

    firmware.className =
        "value " +
        (data.firmware.changed
            ? "danger"
            : "good");

    const alerts =
        document.getElementById("alerts");

    if (!data.alerts.length) {
        alerts.innerHTML =
            '<div class="card good">No alerts.</div>';
        return;
    }

    alerts.innerHTML =
        data.alerts.map(a => \`
            <div class="alert">
                <strong>[\${a.type}]</strong>
                <small>\${a.time}</small>
                <br>
                \${escapeHtml(a.message)}
            </div>
        \`).join("");
}

function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

update();
setInterval(update, 3000);
</script>

</body>
</html>`;
}

const server = http.createServer(
    async (req, res) => {

        if (req.url === "/") {
            res.writeHead(200, {
                "Content-Type": "text/html"
            });

            res.end(dashboard());
            return;
        }

        if (req.url === "/api/status") {
            res.writeHead(200, {
                "Content-Type": "application/json",
                "Cache-Control": "no-store"
            });

            res.end(
                JSON.stringify(state)
            );

            return;
        }

        res.writeHead(404);
        res.end("Not found");
    }
);

async function main() {
    console.log(
        "Starting Native JavaScript Security Monitor..."
    );

    await createFileBaseline();
    await scanHardware();
    await scanFirmware();

    server.listen(PORT, "127.0.0.1", () => {
        console.log(
            `Dashboard: http://127.0.0.1:${PORT}`
        );
    });

    setInterval(async () => {
        try {
            await scanFiles();
            await scanHardware();
            await scanFirmware();
            await scanProcesses();
        } catch (error) {
            alert(
                "MONITOR_ERROR",
                error.message
            );
        }
    }, 30000);
}

main().catch(error => {
    console.error(error);
    process.exit(1);
});

