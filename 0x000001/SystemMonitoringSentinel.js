"use strict";
//∫01∫011−xy1dxdy=6π2
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// ============================================================
// CONFIGURATION
// ============================================================

// Directory to monitor.
// Examples:
//   "/home/username"
//   "/etc"
//   "/opt/my-application"
//
// Avoid "/" initially; Fedora has many continuously changing
// system files.
const ROOT = path.resolve(process.argv[2] || process.cwd());

const LOG_FILE = path.join(process.cwd(), "sentinel.log");

// Set to true to calculate SHA-256 hashes.
// Hashing every file can be expensive on very large directories.
const HASH_FILES = true;

// Ignore common noisy directories.
const IGNORED_DIRECTORIES = new Set([
    ".git",
    "node_modules",
    ".cache",
    "cache"
]);

// ============================================================
// STATE
// ============================================================

const fileDatabase = new Map();
const watchers = new Map();

let shuttingDown = false;

// ============================================================
// LOGGING
// ============================================================

function log(level, message) {
    const timestamp = new Date().toISOString();

    const line =
        `[${timestamp}] [${level}] ${message}\n`;

    process.stdout.write(line);

    try {
        fs.appendFileSync(LOG_FILE, line);
    } catch (error) {
        process.stderr.write(
            `Unable to write log: ${error.message}\n`
        );
    }
}

// ============================================================
// SHA-256
// ============================================================

function calculateHash(filePath) {
    return new Promise((resolve, reject) => {
        const hash = crypto.createHash("sha256");

        const stream = fs.createReadStream(filePath);

        stream.on("data", chunk => {
            hash.update(chunk);
        });

        stream.on("end", () => {
            resolve(hash.digest("hex"));
        });

        stream.on("error", reject);
    });
}

// ============================================================
// FILE INFORMATION
// ============================================================

async function getFileInfo(filePath) {
    try {
        const stat = await fs.promises.stat(filePath);

        if (!stat.isFile()) {
            return null;
        }

        let hash = null;

        if (HASH_FILES) {
            hash = await calculateHash(filePath);
        }

        return {
            size: stat.size,
            mtime: stat.mtimeMs,
            mode: stat.mode,
            hash
        };

    } catch (error) {
        return null;
    }
}

// ============================================================
// IGNORE CHECK
// ============================================================

function shouldIgnore(filePath) {
    const relative = path.relative(ROOT, filePath);

    const parts = relative.split(path.sep);

    return parts.some(part =>
        IGNORED_DIRECTORIES.has(part)
    );
}

// ============================================================
// INITIAL SCAN
// ============================================================

async function scanDirectory(directory) {
    let entries;

    try {
        entries = await fs.promises.readdir(
            directory,
            { withFileTypes: true }
        );
    } catch (error) {
        log(
            "ERROR",
            `Cannot read directory ${directory}: ${error.message}`
        );

        return;
    }

    for (const entry of entries) {
        const fullPath = path.join(directory, entry.name);

        if (shouldIgnore(fullPath)) {
            continue;
        }

        if (entry.isDirectory()) {
            await scanDirectory(fullPath);
            continue;
        }

        if (!entry.isFile()) {
            continue;
        }

        const info = await getFileInfo(fullPath);

        if (info) {
            fileDatabase.set(fullPath, info);
        }
    }
}

// ============================================================
// COMPARE FILE
// ============================================================

async function checkFile(filePath) {
    if (shouldIgnore(filePath)) {
        return;
    }

    const previous = fileDatabase.get(filePath);

    const current = await getFileInfo(filePath);

    // --------------------------------------------------------
    // File deleted
    // --------------------------------------------------------

    if (!current) {
        if (previous) {
            fileDatabase.delete(filePath);

            log(
                "ALERT",
                `FILE DELETED: ${filePath}`
            );
        }

        return;
    }

    // --------------------------------------------------------
    // New file
    // --------------------------------------------------------

    if (!previous) {
        fileDatabase.set(filePath, current);

        log(
            "ALERT",
            `NEW FILE: ${filePath}`
        );

        if (current.hash) {
            log(
                "INFO",
                `SHA-256: ${current.hash}`
            );
        }

        return;
    }

    // --------------------------------------------------------
    // File changed
    // --------------------------------------------------------

    const hashChanged =
        HASH_FILES &&
        previous.hash !== current.hash;

    const sizeChanged =
        previous.size !== current.size;

    const timestampChanged =
        previous.mtime !== current.mtime;

    if (hashChanged || sizeChanged || timestampChanged) {

        log(
            "ALERT",
            `FILE ALTERED: ${filePath}`
        );

        if (sizeChanged) {
            log(
                "CHANGE",
                `Size: ${previous.size} -> ${current.size}`
            );
        }

        if (timestampChanged) {
            log(
                "CHANGE",
                `Modification time changed`
            );
        }

        if (hashChanged) {
            log(
                "CHANGE",
                `Old SHA-256: ${previous.hash}`
            );

            log(
                "CHANGE",
                `New SHA-256: ${current.hash}`
            );
        }

        fileDatabase.set(filePath, current);
    }
}

// ============================================================
// DIRECTORY WATCHER
// ============================================================

function watchDirectory(directory) {
    if (shuttingDown) {
        return;
    }

    if (watchers.has(directory)) {
        return;
    }

    try {
        const watcher = fs.watch(
            directory,
            (eventType, filename) => {

                if (shuttingDown) {
                    return;
                }

                if (!filename) {
                    return;
                }

                const name = filename.toString();

                const fullPath =
                    path.join(directory, name);

                if (shouldIgnore(fullPath)) {
                    return;
                }

                // Give the filesystem a moment to finish the
                // operation before inspecting the file.
                setTimeout(async () => {

                    try {
                        const stat =
                            await fs.promises.stat(fullPath);

                        // New directory
                        if (stat.isDirectory()) {

                            log(
                                "INFO",
                                `DIRECTORY DETECTED: ${fullPath}`
                            );

                            await scanDirectory(fullPath);

                            watchDirectory(fullPath);

                            return;
                        }

                        // New or modified file
                        if (stat.isFile()) {
                            await checkFile(fullPath);
                        }

                    } catch (error) {

                        // File may have been deleted between
                        // the filesystem event and stat().
                        await checkFile(fullPath);
                    }

                }, 100);
            }
        );

        watcher.on("error", error => {
            log(
                "ERROR",
                `Watcher error ${directory}: ${error.message}`
            );

            watchers.delete(directory);
        });

        watchers.set(directory, watcher);

    } catch (error) {
        log(
            "ERROR",
            `Cannot watch ${directory}: ${error.message}`
        );
    }
}

// ============================================================
// WATCH ALL EXISTING DIRECTORIES
// ============================================================

async function watchTree(directory) {

    if (shouldIgnore(directory)) {
        return;
    }

    watchDirectory(directory);

    let entries;

    try {
        entries = await fs.promises.readdir(
            directory,
            { withFileTypes: true }
        );
    } catch {
        return;
    }

    for (const entry of entries) {

        if (!entry.isDirectory()) {
            continue;
        }

        const fullPath =
            path.join(directory, entry.name);

        if (shouldIgnore(fullPath)) {
            continue;
        }

        await watchTree(fullPath);
    }
}

// ============================================================
// START
// ============================================================

async function start() {

    log("INFO", "========================================");
    log("INFO", "        FEDORA SENTINEL MONITOR");
    log("INFO", "========================================");

    log("INFO", `Root: ${ROOT}`);
    log("INFO", `Hashing: ${HASH_FILES ? "enabled" : "disabled"}`);
    log("INFO", `Log: ${LOG_FILE}`);

    if (!fs.existsSync(ROOT)) {
        log(
            "ERROR",
            `Directory does not exist: ${ROOT}`
        );

        process.exit(1);
    }

    log("INFO", "Building initial file database...");

    await scanDirectory(ROOT);

    log(
        "INFO",
        `Indexed ${fileDatabase.size} files`
    );

    log("INFO", "Starting recursive filesystem watchers...");

    await watchTree(ROOT);

    log(
        "INFO",
        `Watching ${watchers.size} directories`
    );

    log("INFO", "Sentinel is running.");
}

// ============================================================
// SHUTDOWN
// ============================================================

function shutdown() {

    if (shuttingDown) {
        return;
    }

    shuttingDown = true;

    log("INFO", "Stopping Sentinel...");

    for (const watcher of watchers.values()) {
        try {
            watcher.close();
        } catch {
            // Ignore shutdown errors.
        }
    }

    watchers.clear();

    log("INFO", "Sentinel stopped.");

    process.exit(0);
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

// ============================================================
// RUN
// ============================================================

start().catch(error => {

    log(
        "ERROR",
        `Fatal error: ${error.message}`
    );

    shutdown();
});
