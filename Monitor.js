#!/usr/bin/env node

"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const os = require("os");

// ============================================================
// CONFIGURATION
// ============================================================

const CONFIG = {
    watchDirectory: process.argv[2] || process.cwd(),

    extensions: [
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".json",
        ".v",
        ".sv",
        ".vh",
        ".vhd",
        ".vhdl"
    ],

    hardwareExtensions: [
        ".v",
        ".sv",
        ".vh",
        ".vhd",
        ".vhdl"
    ],

    maxFileSize: 20 * 1024 * 1024,

    suspiciousNames: [
        "trojan",
        "backdoor",
        "payload",
        "trigger",
        "bypass",
        "override",
        "secret",
        "hidden",
        "unlock",
        "malicious"
    ],

    suspiciousJSPatterns: [
        /child_process/i,
        /eval\s*\(/i,
        /new\s+Function\s*\(/i,
        /process\.binding/i,
        /require\s*\(\s*['"`]net['"`]\s*\)/i,
        /require\s*\(\s*['"`]http['"`]\s*\)/i,
        /require\s*\(\s*['"`]https['"`]\s*\)/i,
        /Buffer\.from\s*\([^)]*,\s*['"`]base64/i
    ],

    suspiciousHDLPatterns: [
        /\bassign\s+\w+\s*=\s*.*\b\d+'[bodh]/i,

        /\bif\s*\([^)]*(==|!=|===|!==)[^)]*\)/i,

        /\bcase\s*\([^)]*\)/i,

        /\b(always|always_ff|always_comb)\b/i,

        /\bforce\b/i,

        /\brelease\b/i,

        /\bdisable\s+\w+/i
    ]
};

// ============================================================
// DATABASE
// ============================================================

const fileDatabase = new Map();

const alerts = [];

// ============================================================
// LOGGING
// ============================================================

function timestamp() {
    return new Date().toISOString();
}

function log(message) {
    console.log(`[${timestamp()}] ${message}`);
}

function alert(level, type, file, message, score = 0) {
    const item = {
        time: timestamp(),
        level,
        type,
        file,
        message,
        score
    };

    alerts.push(item);

    const prefix =
        level === "CRITICAL" ? "[!!!]" :
        level === "HIGH" ? "[!!]" :
        level === "MEDIUM" ? "[!]" :
        "[*]";

    console.log(
        `${prefix} ${level} ${type}: ${message}`
    );
}

// ============================================================
// HASHING
// ============================================================

function sha256File(file) {
    const hash = crypto.createHash("sha256");

    const data = fs.readFileSync(file);

    hash.update(data);

    return hash.digest("hex");
}

// ============================================================
// FILE TYPE
// ============================================================

function extension(file) {
    return path.extname(file).toLowerCase();
}

function isSupported(file) {
    return CONFIG.extensions.includes(
        extension(file)
    );
}

function isHardware(file) {
    return CONFIG.hardwareExtensions.includes(
        extension(file)
    );
}

// ============================================================
// BASIC ANTIVIRUS-STYLE SCANNING
// ============================================================

function scanJavaScript(file, content) {
    let score = 0;

    for (const pattern of CONFIG.suspiciousJSPatterns) {
        if (pattern.test(content)) {
            score += 15;

            alert(
                "MEDIUM",
                "SCRIPT",
                file,
                `Suspicious JavaScript pattern detected: ${pattern}`,
                15
            );
        }
    }

    // Look for suspicious encoded blobs.
    const base64 =
        /(?:[A-Za-z0-9+/]{100,}={0,2})/g;

    const matches = content.match(base64);

    if (matches && matches.length > 0) {
        score += 10;

        alert(
            "MEDIUM",
            "ENCODED_DATA",
            file,
            "Large Base64-like encoded data detected.",
            10
        );
    }

    return score;
}

// ============================================================
// HARDWARE TROJAN ANALYSIS
// ============================================================

function analyzeHardware(file, content) {
    let score = 0;

    const lines = content.split(/\r?\n/);

    lines.forEach((line, index) => {
        for (const pattern of CONFIG.suspiciousHDLPatterns) {

            if (pattern.test(line)) {
                score += 5;

                alert(
                    "MEDIUM",
                    "HARDWARE",
                    file,
                    `Suspicious HDL construct at line ${index + 1}: ${line.trim()}`,
                    5
                );
            }
        }
    });

    // --------------------------------------------------------
    // Suspicious signal names
    // --------------------------------------------------------

    const identifiers =
        content.match(
            /\b[A-Za-z_][A-Za-z0-9_]*\b/g
        ) || [];

    const uniqueIdentifiers =
        [...new Set(identifiers)];

    for (const id of uniqueIdentifiers) {

        const lower = id.toLowerCase();

        for (const word of CONFIG.suspiciousNames) {

            if (lower.includes(word)) {

                score += 15;

                alert(
                    "HIGH",
                    "HARDWARE_SIGNAL",
                    file,
                    `Suspicious HDL identifier "${id}" contains "${word}".`,
                    15
                );

                break;
            }
        }
    }

    // --------------------------------------------------------
    // Complex conditional logic
    // --------------------------------------------------------

    const conditions =
        content.match(
            /\bif\s*\(([^)]*)\)/gi
        ) || [];

    for (const condition of conditions) {

        const operators =
            condition.match(
                /&&|\|\||==|!=|===|!==/g
            ) || [];

        if (operators.length >= 2) {

            score += 20;

            alert(
                "HIGH",
                "TROJAN_TRIGGER",
                file,
                `Complex conditional/trigger-like expression: ${condition}`,
                20
            );
        }
    }

    // --------------------------------------------------------
    // Constant comparison
    // --------------------------------------------------------

    const constants =
        content.match(
            /\b[A-Za-z_][A-Za-z0-9_]*\s*(==|!=|===|!==)\s*\d+'[bodhBODH][0-9a-fA-F_xXzZ]+/g
        ) || [];

    for (const expression of constants) {

        score += 20;

        alert(
            "HIGH",
            "TROJAN_TRIGGER",
            file,
            `Constant-based comparison detected: ${expression}`,
            20
        );
    }

    // --------------------------------------------------------
    // Force/release
    // --------------------------------------------------------

    if (/\bforce\b/i.test(content)) {

        score += 25;

        alert(
            "HIGH",
            "HDL_OVERRIDE",
            file,
            "Verilog force statement detected.",
            25
        );
    }

    if (/\brelease\b/i.test(content)) {

        score += 25;

        alert(
            "HIGH",
            "HDL_OVERRIDE",
            file,
            "Verilog release statement detected.",
            25
        );
    }

    return score;
}

// ============================================================
// GENERAL FILE SCAN
// ============================================================

function scanFile(file) {

    try {

        const stat =
            fs.statSync(file);

        if (!stat.isFile()) {
            return;
        }

        if (stat.size > CONFIG.maxFileSize) {

            alert(
                "MEDIUM",
                "FILE_SIZE",
                file,
                `File exceeds scan limit: ${stat.size} bytes.`,
                5
            );

            return;
        }

        if (!isSupported(file)) {
            return;
        }

        const content =
            fs.readFileSync(file, "utf8");

        const hash =
            sha256File(file);

        const previous =
            fileDatabase.get(file);

        // ----------------------------------------------------
        // File integrity
        // ----------------------------------------------------

        if (previous && previous.hash !== hash) {

            alert(
                "MEDIUM",
                "FILE_CHANGED",
                file,
                `File hash changed from ${previous.hash} to ${hash}.`,
                10
            );
        }

        fileDatabase.set(file, {
            hash,
            size: stat.size,
            modified: stat.mtimeMs
        });

        let score = 0;

        // ----------------------------------------------------
        // Antivirus-style analysis
        // ----------------------------------------------------

        if (
            [".js", ".mjs", ".cjs", ".ts"]
                .includes(extension(file))
        ) {
            score += scanJavaScript(
                file,
                content
            );
        }

        // ----------------------------------------------------
        // Hardware Trojan analysis
        // ----------------------------------------------------

        if (isHardware(file)) {

            score += analyzeHardware(
                file,
                content
            );
        }

        // ----------------------------------------------------
        // Final risk
        // ----------------------------------------------------

        if (score >= 60) {

            alert(
                "CRITICAL",
                "SECURITY_RISK",
                file,
                `High-risk file detected. Score: ${score}/100`,
                score
            );

        } else if (score >= 30) {

            alert(
                "HIGH",
                "SECURITY_RISK",
                file,
                `Suspicious file detected. Score: ${score}/100`,
                score
            );
        }
    }

    catch (error) {

        alert(
            "MEDIUM",
            "SCAN_ERROR",
            file,
            error.message
        );
    }
}

// ============================================================
// DIRECTORY SCANNER
// ============================================================

function scanDirectory(directory) {

    let entries;

    try {
        entries =
            fs.readdirSync(
                directory,
                { withFileTypes: true }
            );
    }

    catch (error) {

        alert(
            "HIGH",
            "DIRECTORY_ERROR",
            directory,
            error.message
        );

        return;
    }

    for (const entry of entries) {

        // Ignore common dependency/cache directories.
        if (
            entry.name === "node_modules" ||
            entry.name === ".git" ||
            entry.name === ".cache"
        ) {
            continue;
        }

        const fullPath =
            path.join(
                directory,
                entry.name
            );

        if (entry.isDirectory()) {

            scanDirectory(fullPath);

        } else {

            scanFile(fullPath);
        }
    }
}

// ============================================================
// MONITOR
// ============================================================

function monitor(directory) {

    log(
        `Monitoring: ${path.resolve(directory)}`
    );

    log(
        `Host: ${os.hostname()}`
    );

    log(
        `Platform: ${process.platform}`
    );

    console.log("");

    scanDirectory(directory);

    console.log("");

    log(
        "Initial security scan completed."
    );

    console.log("");

    // --------------------------------------------------------
    // Watch for changes
    // --------------------------------------------------------

    fs.watch(
        directory,
        { recursive: true },
        (eventType, filename) => {

            if (!filename) {
                return;
            }

            const fullPath =
                path.join(
                    directory,
                    filename
                );

            if (
                !isSupported(fullPath)
            ) {
                return;
            }

            setTimeout(() => {

                if (fs.existsSync(fullPath)) {

                    log(
                        `Change detected: ${fullPath}`
                    );

                    scanFile(fullPath);
                }

            }, 100);
        }
    );

    log(
        "Real-time monitoring active."
    );

    log(
        "Press Ctrl+C to stop."
    );
}

// ============================================================
// REPORT
// ============================================================

function saveReport() {

    const report = {

        generatedAt: timestamp(),

        host: os.hostname(),

        platform: process.platform,

        monitoredDirectory:
            path.resolve(
                CONFIG.watchDirectory
            ),

        filesScanned:
            fileDatabase.size,

        alerts
    };

    fs.writeFileSync(
        "security_report.json",
        JSON.stringify(
            report,
            null,
            2
        )
    );
}

// ============================================================
// SHUTDOWN
// ============================================================

process.on(
    "SIGINT",
    () => {

        console.log("");

        log(
            "Stopping security monitor..."
        );

        saveReport();

        log(
            "Report saved to security_report.json"
        );

        process.exit(0);
    }
);

// ============================================================
// START
// ============================================================

console.log("");
console.log("==============================================");
console.log(" JavaScript Security Monitor");
console.log(" Antivirus + Hardware Trojan Defense");
console.log("==============================================");
console.log("");

monitor(
    CONFIG.watchDirectory
);

