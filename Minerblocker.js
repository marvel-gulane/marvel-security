//about:debugging#/runtime/this-firefox
// generate-extension.js
const fs = require("fs");
const path = require("path");

const outDir = path.join(__dirname, "Firefox-Security-Extensions");

const files = {
  "manifest.json": JSON.stringify({
    manifest_version: 2,
    name: "Firefox Security & Miner Blocker",
    version: "1.0.0",
    description:
      "Blocks known malicious domains, cryptominers, tracking requests, and unwanted third-party network requests.",
    permissions: [
      "webRequest",
      "webRequestBlocking",
      "<all_urls>"
    ],
    background: {
      scripts: ["background.js"]
    },
    browser_specific_settings: {
      gecko: {
        id: "security-miner-blocker@example.local"
      }
    }
  }, null, 2),

  "background.js": `
"use strict";

/*
 * Known cryptomining / malicious URL patterns.
 * Keep this list maintained from reputable threat-intelligence sources.
 */
const BLOCKED_PATTERNS = [
  /(^|\\\\.)coinhive\\\\./i,
  /(^|\\\\.)cryptoloot\\\\./i,
  /(^|\\\\.)crypto-loot\\\\./i,
  /(^|\\\\.)coin-hive\\\\./i,
  /(^|\\\\.)minero\\\\./i,
  /(^|\\\\.)webmine\\\\./i,
  /(^|\\\\.)coinimp\\\\./i,
  /(^|\\\\.)cryptonight\\\\./i
];

/*
 * Requests to these resource types are particularly useful
 * to restrict when hardening a browser.
 */
const HIGH_RISK_TYPES = new Set([
  "script",
  "sub_frame",
  "object",
  "media",
  "websocket"
]);

function isBlocked(url) {
  if (!url || !/^https?:/i.test(url)) {
    return false;
  }

  return BLOCKED_PATTERNS.some(pattern => pattern.test(url));
}

/*
 * Block known malicious/mining URLs before Firefox loads them.
 */
browser.webRequest.onBeforeRequest.addListener(
  details => {
    if (isBlocked(details.url)) {
      console.warn("[BLOCKED MINER/MALICIOUS]", details.url);
      return { cancel: true };
    }

    return {};
  },
  {
    urls: ["<all_urls>"],
    types: [
      "main_frame",
      "sub_frame",
      "script",
      "object",
      "media",
      "xmlhttprequest",
      "websocket"
    ]
  },
  ["blocking"]
);

/*
 * Basic third-party blocking.
 *
 * Main-frame navigation is allowed.
 * Requests from one origin to a different origin are blocked.
 */
browser.webRequest.onBeforeRequest.addListener(
  details => {
    if (!details.originUrl) {
      return {};
    }

    let request;
    let origin;

    try {
      request = new URL(details.url);
      origin = new URL(details.originUrl);
    } catch {
      return {};
    }

    if (
      request.protocol !== "http:" &&
      request.protocol !== "https:"
    ) {
      return {};
    }

    if (
      request.origin !== origin.origin &&
      HIGH_RISK_TYPES.has(details.type)
    ) {
      console.warn("[BLOCKED THIRD-PARTY]", details.url);
      return { cancel: true };
    }

    return {};
  },
  {
    urls: ["<all_urls>"],
    types: [
      "sub_frame",
      "script",
      "object",
      "media",
      "websocket"
    ]
  },
  ["blocking"]
);

console.log("Firefox Security & Miner Blocker loaded.");
`
};

fs.mkdirSync(outDir, { recursive: true });

for (const [filename, contents] of Object.entries(files)) {
  fs.writeFileSync(
    path.join(outDir, filename),
    contents.trimStart(),
    "utf8"
  );
}

console.log(`Extension created at: ${outDir}`);
console.log("");
console.log("Files:");
console.log("  manifest.json");
console.log("  background.js");
console.log("");
console.log("Load it in Firefox with:");
console.log("  about:debugging");
console.log("  → This Firefox");
console.log("  → Load Temporary Add-on");
console.log("  → select manifest.json");
