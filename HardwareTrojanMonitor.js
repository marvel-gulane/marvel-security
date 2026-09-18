
const fs = require("fs");
const crypto = require("crypto");
const path = require("path");

// ============================================================
// Configuration
// ============================================================

const FILE_TO_MONITOR = path.resolve("./target-file.bin");
const LOG_FILE = path.resolve("./hardware-monitor.log");
const CHECK_INTERVAL = 2000; // milliseconds

let lastHash = null;
let lastExists = false;

// ============================================================
// Logging
// ============================================================

function log(message) {
    const timestamp = new Date().toISOString();
    const entry = `[${timestamp}] ${message}\n`;

    console.log(entry.trim());

    fs.appendFileSync(LOG_FILE, entry);
}

// ============================================================
// Calculate SHA-256 hash
// ============================================================

function calculateHash(file) {
    return new Promise((resolve, reject) => {
        const hash = crypto.createHash("sha256");
        const stream = fs.createReadStream(file);

        stream.on("error", reject);

        stream.on("data", chunk => {
            hash.update(chunk);
        });

        stream.on("end", () => {
            resolve(hash.digest("hex"));
        });
    });
}

// ============================================================
// Monitor the file
// ============================================================

async function checkFile() {
    const exists = fs.existsSync(FILE_TO_MONITOR);

    // File was deleted
    if (!exists) {
        if (lastExists) {
            log(`ALERT: File deleted: ${FILE_TO_MONITOR}`);
        }

        lastExists = false;
        lastHash = null;
        return;
    }

    // File was created
    if (!lastExists) {
        try {
            const hash = await calculateHash(FILE_TO_MONITOR);

            lastHash = hash;
            lastExists = true;

            log(`File detected: ${FILE_TO_MONITOR}`);
            log(`Initial SHA-256: ${hash}`);
        } catch (error) {
            log(`ERROR reading file: ${error.message}`);
        }

        return;
    }

    // Calculate current hash
    try {
        const currentHash = await calculateHash(FILE_TO_MONITOR);

        // File changed
        if (currentHash !== lastHash) {
            log(`ALERT: POSSIBLE FILE ALTERATION`);
            log(`File: ${FILE_TO_MONITOR}`);
            log(`Previous SHA-256: ${lastHash}`);
            log(`Current SHA-256:  ${currentHash}`);

            lastHash = currentHash;
        }
    } catch (error) {
        log(`ERROR checking file: ${error.message}`);
    }
}

// ============================================================
// Startup
// ============================================================

log("==============================================");
log("Hardware File Integrity Monitor started");
log(`Monitoring: ${FILE_TO_MONITOR}`);
log(`Check interval: ${CHECK_INTERVAL} ms`);
log("==============================================");

checkFile();

setInterval(checkFile, CHECK_INTERVAL);

// ============================================================
// Graceful shutdown
// ============================================================

process.on("SIGINT", () => {
    log("Monitor stopped.");
    process.exit(0);
});

process.on("SIGTERM", () => {
    log("Monitor stopped.");
    process.exit(0);
});
