"use strict";

const fs = require("fs");
const fsp = fs.promises;
const path = require("path");
const crypto = require("crypto");
const os = require("os");
const { execFile } = require("child_process");

const CONFIG = {
    directories: [
        "/etc",
        path.join(os.homedir(), ".config"),
        path.join(os.homedir(), ".local/bin")
    ],

    scanInterval: 30000,

    // Files that deserve extra attention.
    sensitiveFiles: [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/ssh/sshd_config"
    ],

    logFile: path.join(
        os.homedir(),
        "native-security-monitor.log"
    )
};

const baseline = new Map();

function log(level, message) {
    const line =
        `[${new Date().toISOString()}] [${level}] ${message}`;

    console.log(line);

    fs.appendFileSync(
        CONFIG.logFile,
        line + "\n"
    );
}

function alert(message) {
    log("ALERT", message);
}

async function sha256(file) {
    return new Promise((resolve, reject) => {
        const hash = crypto.createHash("sha256");
        const stream = fs.createReadStream(file);

        stream.on("data", chunk => hash.update(chunk));
        stream.on("end", () => resolve(hash.digest("hex")));
        stream.on("error", reject);
    });
}

async function inventoryFile(file) {
    try {
        const stat = await fsp.lstat(file);

        if (!stat.isFile()) {
            return null;
        }

        return {
            size: stat.size,
            mode: stat.mode,
            uid: stat.uid,
            gid: stat.gid,
            mtime: stat.mtimeMs,
            hash: await sha256(file)
        };
    } catch {
        return null;
    }
}

async function walk(directory, callback) {
    let entries;

    try {
        entries = await fsp.readdir(directory, {
            withFileTypes: true
        });
    } catch (error) {
        log("WARN",
            `Cannot read ${directory}: ${error.message}`);
        return;
    }

    for (const entry of entries) {
        const fullPath = path.join(
            directory,
            entry.name
        );

        if (entry.isSymbolicLink()) {
            continue;
        }

        if (entry.isDirectory()) {
            await walk(fullPath, callback);
        } else if (entry.isFile()) {
            await callback(fullPath);
        }
    }
}

async function buildBaseline() {
    log("INFO", "Building file-integrity baseline...");

    for (const directory of CONFIG.directories) {
        await walk(directory, async file => {
            const metadata = await inventoryFile(file);

            if (metadata) {
                baseline.set(file, metadata);
            }
        });
    }

    log(
        "INFO",
        `Baseline contains ${baseline.size} files.`
    );
}

async function scanFiles() {
    const current = new Map();

    for (const directory of CONFIG.directories) {
        await walk(directory, async file => {
            const metadata = await inventoryFile(file);

            if (metadata) {
                current.set(file, metadata);
            }
        });
    }

    // Detect new and modified files.
    for (const [file, info] of current) {
        const old = baseline.get(file);

        if (!old) {
            alert(`NEW FILE: ${file}`);
            continue;
        }

        if (old.hash !== info.hash) {
            alert(
                `FILE CONTENT CHANGED: ${file}\n` +
                `Old SHA256: ${old.hash}\n` +
                `New SHA256: ${info.hash}`
            );
        }

        if (
            old.uid !== info.uid ||
            old.gid !== info.gid ||
            old.mode !== info.mode
        ) {
            alert(
                `FILE PERMISSIONS/OWNER CHANGED: ${file}`
            );
        }
    }

    // Detect deleted or renamed-away files.
    for (const file of baseline.keys()) {
        if (!current.has(file)) {
            alert(`FILE REMOVED/RENAMED: ${file}`);
        }
    }

    baseline.clear();

    for (const [file, info] of current) {
        baseline.set(file, info);
    }
}

function run(command, args) {
    return new Promise(resolve => {
        execFile(
            command,
            args,
            {
                timeout: 5000,
                maxBuffer: 1024 * 1024
            },
            (error, stdout, stderr) => {
                resolve({
                    error,
                    stdout,
                    stderr
                });
            }
        );
    });
}

async function hardwareInventory() {
    log("INFO", "Collecting hardware inventory...");

    const commands = [
        ["lscpu", []],
        ["lsblk", ["-o", "NAME,SIZE,MODEL,SERIAL,TYPE"]],
        ["lspci", ["-nn"]],
        ["lsusb", []],
        ["dmidecode", ["-t", "system"]]
    ];

    for (const [command, args] of commands) {
        const result = await run(command, args);

        if (result.error) {
            log(
                "WARN",
                `${command}: ${result.error.message}`
            );
            continue;
        }

        const filename =
            path.join(
                os.homedir(),
                `hardware-${command}.txt`
            );

        await fsp.writeFile(
            filename,
            result.stdout
        );

        log(
            "INFO",
            `Hardware inventory saved: ${filename}`
        );
    }
}

async function firmwareInventory() {
    log("INFO", "Checking firmware information...");

    const result = await run(
        "fwupdmgr",
        ["get-devices"]
    );

    if (result.error) {
        log(
            "WARN",
            "fwupdmgr unavailable or permission denied."
        );
        return;
    }

    const filename =
        path.join(
            os.homedir(),
            "firmware-inventory.txt"
        );

    await fsp.writeFile(
        filename,
        result.stdout
    );

    log(
        "INFO",
        `Firmware inventory saved: ${filename}`
    );
}

async function processInventory() {
    log("INFO", "Checking running processes...");

    const result = await run(
        "ps",
        ["-eo", "pid,user,comm,args"]
    );

    if (result.error) {
        return;
    }

    const lines =
        result.stdout.trim().split("\n");

    for (const line of lines) {
        // Keep this intentionally informational.
        // It does not kill processes automatically.
        if (
            /\/tmp\/|\/dev\/shm\//.test(line)
        ) {
            alert(
                `PROCESS RUNNING FROM TEMPORARY LOCATION: ${line}`
            );
        }
    }
}

async function sensitiveFileCheck() {
    for (const file of CONFIG.sensitiveFiles) {
        const info = await inventoryFile(file);

        if (!info) {
            log(
                "WARN",
                `Cannot inspect sensitive file: ${file}`
            );
            continue;
        }

        log(
            "INFO",
            `Sensitive file ${file} SHA256=${info.hash}`
        );
    }
}

async function main() {
    log("INFO", "Hardware trojan monitoring security starting.");

    await hardwareInventory();
    await firmwareInventory();
    await sensitiveFileCheck();
    await buildBaseline();

    setInterval(async () => {
        try {
            await scanFiles();
            await processInventory();
        } catch (error) {
            log(
                "ERROR",
                error.stack || error.message
            );
        }
    }, CONFIG.scanInterval);

    log(
        "INFO",
        `Continuous monitoring enabled (${CONFIG.scanInterval} ms).`
    );
}

main().catch(error => {
    log(
        "ERROR",
        error.stack || error.message
    );
    process.exit(1);
});

