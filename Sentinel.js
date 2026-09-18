
"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// ============================================================
// CONFIGURATION
// ============================================================

const WATCH_PATH = path.resolve("./target-file.bin");
const LOG_FILE = path.resolve("./sentinel.log");
const INTERVAL = 2000;

// ============================================================
// STATE
// ============================================================

let previous = {
    exists: false,
    hash: null,
    size: null,
    modified: null
};

// ============================================================
// LOGGING
// ============================================================

function log(level, message) {
    const timestamp = new Date().toISOString();
    const line = `[${timestamp}] [${level}] ${message}\n`;

    process.stdout.write(line);
    fs.appendFileSync(LOG_FILE, line);
}

// ============================================================
// SHA-256
// ============================================================

function sha256(file) {
    return new Promise((resolve, reject) => {
        const hash = crypto.createHash("sha256");
        const stream = fs.createReadStream(file);

        stream.on("data", chunk => hash.update(chunk));

        stream.on("end", () => {
            resolve(hash.digest("hex"));
        });

        stream.on("error", reject);
    });
}

// ============================================================
// FILE STATUS
// ============================================================

async function getStatus() {
    try {
        const stat = await fs.promises.stat(WATCH_PATH);

        const hash = await sha256(WATCH_PATH);

        return {
            exists: true,
            hash,
            size: stat.size,
            modified: stat.mtimeMs
        };
    } catch (error) {
        if (error.code === "ENOENT") {
            return {
                exists: false,
                hash: null,
                size: null,
                modified: null
            };
        }

        throw error;
    }
}

// ============================================================
// SENTINEL CHECK
// ============================================================

async function sentinelCheck() {
    try {
        const current = await getStatus();

        // First observation
        if (!previous.exists && current.exists) {
            log("INFO", `File detected: ${WATCH_PATH}`);
            log("BASELINE", `SHA-256: ${current.hash}`);

            previous = current;
            return;
        }

        // File deleted
        if (previous.exists && !current.exists) {
            log("ALERT", `FILE DELETED: ${WATCH_PATH}`);

            previous = current;
            return;
        }

        // Nothing to compare
        if (!current.exists) {
            return;
        }

        // Hash changed
        if (current.hash !== previous.hash) {
            log("ALERT", `POSSIBLE ALTERATION: ${WATCH_PATH}`);
            log("CHANGE", `Old SHA-256: ${previous.hash}`);
            log("CHANGE", `New SHA-256: ${current.hash}`);
            log("CHANGE", `Old size: ${previous.size}`);
            log("CHANGE", `New size: ${current.size}`);
        }

        // Metadata changed
        if (current.modified !== previous.modified) {
            log("INFO", `Modification timestamp changed: ${WATCH_PATH}`);
        }

        previous = current;

    } catch (error) {
        log("ERROR", error.message);
    }
}

// ============================================================
// START
// ============================================================

log("INFO", "======================================");
log("INFO", "SENTINEL FILE INTEGRITY MONITOR");
log("INFO", "======================================");
log("INFO", `Monitoring: ${WATCH_PATH}`);
log("INFO", `Interval: ${INTERVAL} ms`);

sentinelCheck();

const timer = setInterval(sentinelCheck, INTERVAL);

// ============================================================
// SHUTDOWN
// ============================================================

function shutdown() {
    clearInterval(timer);

    log("INFO", "Sentinel stopped.");

    process.exit(0);
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
