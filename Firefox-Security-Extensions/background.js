"use strict";

/*
 * Known cryptomining / malicious URL patterns.
 * Keep this list maintained from reputable threat-intelligence sources.
 */
const BLOCKED_PATTERNS = [
  /(^|\\.)coinhive\\./i,
  /(^|\\.)cryptoloot\\./i,
  /(^|\\.)crypto-loot\\./i,
  /(^|\\.)coin-hive\\./i,
  /(^|\\.)minero\\./i,
  /(^|\\.)webmine\\./i,
  /(^|\\.)coinimp\\./i,
  /(^|\\.)cryptonight\\./i
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
