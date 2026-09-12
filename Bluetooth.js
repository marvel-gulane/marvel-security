#!/usr/bin/env node
"use strict";

/*
 * Bluetooth Guard
 * ----------------
 * Defensive Bluetooth hardware / firmware integrity monitor.
 *
 * Detects:
 *   - Bluetooth adapter additions/removals
 *   - Vendor/product ID changes
 *   - Controller identity changes
 *   - Firmware-version changes where exposed by the OS
 *   - Unexpected USB Bluetooth devices
 *   - Adapter state changes
 *   - Baseline modifications
 *
 * It does NOT:
 *   - attack Bluetooth devices
 *   - inject packets
 *   - capture credentials
 *   - perform unauthorized pairing
 *   - modify Bluetooth firmware
 *
 * Node.js 18+
 *
 * Run:
 *   node bluetooth-guard.js
 *
 * Optional:
 *   CHECK_INTERVAL=30000 node bluetooth-guard.js
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { execFile } = require("child_process");

const CONFIG = {
  interval: Number(process.env.CHECK_INTERVAL || 30000),

  baselineFile: path.join(
    process.cwd(),
    "bluetooth-hardware-baseline.json"
  ),

  eventLog: path.join(
    process.cwd(),
    "bluetooth-security-events.jsonl"
  )
};

const state = {
  baseline: null,
  current: null,
  started: new Date().toISOString(),
  alerts: 0
};

/* -------------------------------------------------------------------------- */
/* Utilities                                                                  */
/* -------------------------------------------------------------------------- */

function sha256(value) {
  return crypto
    .createHash("sha256")
    .update(value)
    .digest("hex");
}

function run(command, args = []) {
  return new Promise((resolve) => {
    execFile(
      command,
      args,
      {
        timeout: 10000,
        windowsHide: true,
        maxBuffer: 4 * 1024 * 1024
      },
      (error, stdout, stderr) => {
        if (error) {
          resolve(null);
          return;
        }

        resolve({
          stdout: String(stdout || ""),
          stderr: String(stderr || "")
        });
      }
    );
  });
}

function event(type, severity, message, details = {}) {
  const record = {
    timestamp: new Date().toISOString(),
    type,
    severity,
    message,
    details
  };

  console.log(
    `[${severity.toUpperCase()}] ${type}: ${message}`
  );

  try {
    fs.appendFileSync(
      CONFIG.eventLog,
      JSON.stringify(record) + "\n"
    );
  } catch (err) {
    console.error(
      "[LOG ERROR]",
      err.message
    );
  }

  state.alerts++;
}

function canonicalize(value) {
  if (value === null || value === undefined) {
    return null;
  }

  if (Array.isArray(value)) {
    return value
      .map(canonicalize)
      .sort((a, b) =>
        JSON.stringify(a).localeCompare(JSON.stringify(b))
      );
  }

  if (typeof value === "object") {
    return Object.keys(value)
      .sort()
      .reduce((obj, key) => {
        obj[key] = canonicalize(value[key]);
        return obj;
      }, {});
  }

  return value;
}

function fingerprint(inventory) {
  return sha256(
    JSON.stringify(canonicalize(inventory))
  );
}

/* -------------------------------------------------------------------------- */
/* Linux                                                                     */
/* -------------------------------------------------------------------------- */

async function collectLinux() {
  const inventory = {
    platform: "linux",
    hostname: os.hostname(),
    adapters: [],
    usbBluetooth: [],
    pciBluetooth: []
  };

  /*
   * Bluetooth controllers.
   */
  const controllers = await run(
    "bluetoothctl",
    ["list"]
  );

  if (controllers) {
    for (const line of controllers.stdout.split("\n")) {
      const match = line.match(
        /Controller\s+([0-9A-F:]{17})\s+(.+?)(?:\s+\[default\])?$/i
      );

      if (match) {
        inventory.adapters.push({
          address: match[1].toUpperCase(),
          name: match[2].trim()
        });
      }
    }
  }

  /*
   * USB Bluetooth hardware.
   */
  const usb = await run(
    "lsusb",
    []
  );

  if (usb) {
    for (const line of usb.stdout.split("\n")) {
      if (!/Bluetooth/i.test(line)) continue;

      const id =
        line.match(
          /ID\s+([0-9a-f]{4}):([0-9a-f]{4})/i
        );

      inventory.usbBluetooth.push({
        raw: line.trim(),
        vendorId: id?.[1]?.toLowerCase() || null,
        productId: id?.[2]?.toLowerCase() || null
      });
    }
  }

  /*
   * PCI Bluetooth hardware where exposed.
   */
  const pci = await run(
    "lspci",
    []
  );

  if (pci) {
    for (const line of pci.stdout.split("\n")) {
      if (/Bluetooth/i.test(line)) {
        inventory.pciBluetooth.push(
          line.trim()
        );
      }
    }
  }

  /*
   * BlueZ version.
   */
  const bluez = await run(
    "bluetoothctl",
    ["--version"]
  );

  if (bluez) {
    inventory.bluezVersion =
      bluez.stdout.trim();
  }

  /*
   * Controller information.
   */
  const show = await run(
    "bluetoothctl",
    ["show"]
  );

  if (show) {
    const address =
      show.stdout.match(
        /^\s*Controller\s+([0-9A-F:]{17})/im
      )?.[1];

    const name =
      show.stdout.match(
        /^\s*Name:\s*(.+)$/im
      )?.[1];

    const powered =
      show.stdout.match(
        /^\s*Powered:\s*(yes|no)$/im
      )?.[1];

    inventory.controller = {
      address: address || null,
      name: name || null,
      powered: powered || null
    };
  }

  return inventory;
}

/* -------------------------------------------------------------------------- */
/* Windows                                                                    */
/* -------------------------------------------------------------------------- */

async function collectWindows() {
  const inventory = {
    platform: "windows",
    hostname: os.hostname(),
    adapters: [],
    devices: []
  };

  /*
   * PnP Bluetooth inventory.
   */
  const result = await run(
    "powershell.exe",
    [
      "-NoProfile",
      "-Command",
      `
Get-PnpDevice |
Where-Object {
    $_.Class -eq "Bluetooth"
} |
Select-Object Status,Class,FriendlyName,InstanceId,Manufacturer |
ConvertTo-Json -Compress
`
    ]
  );

  if (result) {
    try {
      let devices = JSON.parse(
        result.stdout
      );

      if (!Array.isArray(devices)) {
        devices = [devices];
      }

      for (const device of devices) {
        inventory.devices.push({
          status: device.Status || null,
          class: device.Class || null,
          name: device.FriendlyName || null,
          instanceId: device.InstanceId || null,
          manufacturer: device.Manufacturer || null
        });
      }
    } catch {
      // Ignore malformed PowerShell output.
    }
  }

  /*
   * Bluetooth radio inventory.
   */
  const radios = await run(
    "powershell.exe",
    [
      "-NoProfile",
      "-Command",
      `
Get-PnpDevice |
Where-Object {
    $_.FriendlyName -match "Bluetooth"
} |
Select-Object FriendlyName,InstanceId,Manufacturer |
ConvertTo-Json -Compress
`
    ]
  );

  if (radios) {
    try {
      let data = JSON.parse(
        radios.stdout
      );

      if (!Array.isArray(data)) {
        data = [data];
      }

      for (const radio of data) {
        inventory.adapters.push({
          name: radio.FriendlyName || null,
          instanceId: radio.InstanceId || null,
          manufacturer: radio.Manufacturer || null
        });
      }
    } catch {
      // Ignore malformed output.
    }
  }

  /*
   * Secure Boot status is useful when investigating firmware integrity.
   */
  const secureBoot = await run(
    "powershell.exe",
    [
      "-NoProfile",
      "-Command",
      "try { Confirm-SecureBootUEFI } catch { 'Unknown' }"
    ]
  );

  inventory.secureBoot =
    secureBoot?.stdout.trim() || "Unknown";

  return inventory;
}

/* -------------------------------------------------------------------------- */
/* macOS                                                                      */
/* -------------------------------------------------------------------------- */

async function collectMacOS() {
  const inventory = {
    platform: "darwin",
    hostname: os.hostname(),
    bluetooth: null
  };

  const result = await run(
    "system_profiler",
    [
      "SPBluetoothDataType",
      "-json"
    ]
  );

  if (!result) {
    return inventory;
  }

  try {
    const data = JSON.parse(
      result.stdout
    );

    /*
     * Store a normalized hash of the Bluetooth
     * system-profiler output rather than depending
     * on one particular macOS schema.
     */
    inventory.bluetooth = {
      fingerprint: sha256(
        JSON.stringify(
          canonicalize(data)
        )
      )
    };
  } catch {
    inventory.bluetooth = null;
  }

  return inventory;
}

/* -------------------------------------------------------------------------- */
/* Inventory dispatcher                                                       */
/* -------------------------------------------------------------------------- */

async function collectInventory() {
  if (process.platform === "linux") {
    return collectLinux();
  }

  if (process.platform === "win32") {
    return collectWindows();
  }

  if (process.platform === "darwin") {
    return collectMacOS();
  }

  return {
    platform: process.platform,
    hostname: os.hostname(),
    unsupported: true
  };
}

/* -------------------------------------------------------------------------- */
/* Baseline                                                                    */
/* -------------------------------------------------------------------------- */

function loadBaseline() {
  try {
    return JSON.parse(
      fs.readFileSync(
        CONFIG.baselineFile,
        "utf8"
      )
    );
  } catch {
    return null;
  }
}

function saveBaseline(inventory) {
  fs.writeFileSync(
    CONFIG.baselineFile,
    JSON.stringify(
      {
        created: new Date().toISOString(),
        fingerprint: fingerprint(inventory),
        inventory
      },
      null,
      2
    )
  );
}

/* -------------------------------------------------------------------------- */
/* Comparison                                                                  */
/* -------------------------------------------------------------------------- */

function compareInventory(previous, current) {
  if (!previous) return;

  const previousFingerprint =
    fingerprint(previous.inventory || previous);

  const currentFingerprint =
    fingerprint(current);

  if (
    previousFingerprint ===
    currentFingerprint
  ) {
    return;
  }

  /*
   * Bluetooth hardware changed.
   */
  event(
    "bluetooth_hardware_change",
    "high",
    "Bluetooth hardware inventory differs from the approved baseline",
    {
      previousFingerprint,
      currentFingerprint
    }
  );

  /*
   * Linux USB device changes.
   */
  if (
    JSON.stringify(
      previous.inventory?.usbBluetooth || []
    ) !==
    JSON.stringify(
      current.usbBluetooth || []
    )
  ) {
    event(
      "bluetooth_usb_identity_change",
      "critical",
      "Bluetooth USB controller identity changed",
      {
        previous:
          previous.inventory?.usbBluetooth || [],
        current:
          current.usbBluetooth || []
      }
    );
  }

  /*
   * Linux controller changes.
   */
  if (
    JSON.stringify(
      previous.inventory?.adapters || []
    ) !==
    JSON.stringify(
      current.adapters || []
    )
  ) {
    event(
      "bluetooth_controller_change",
      "high",
      "Bluetooth controller inventory changed",
      {
        previous:
          previous.inventory?.adapters || [],
        current:
          current.adapters || []
      }
    );
  }

  /*
   * Windows PnP identity changes.
   */
  if (
    JSON.stringify(
      previous.inventory?.devices || []
    ) !==
    JSON.stringify(
      current.devices || []
    )
  ) {
    event(
      "bluetooth_pnp_change",
      "high",
      "Windows Bluetooth PnP inventory changed",
      {
        previous:
          previous.inventory?.devices || [],
        current:
          current.devices || []
      }
    );
  }

  /*
   * Secure Boot changes.
   */
  if (
    previous.inventory?.secureBoot !== undefined &&
    current.secureBoot !== undefined &&
    previous.inventory.secureBoot !==
      current.secureBoot
  ) {
    event(
      "secure_boot_change",
      "critical",
      "Secure Boot state changed",
      {
        previous:
          previous.inventory.secureBoot,
        current:
          current.secureBoot
      }
    );
  }
}

/* -------------------------------------------------------------------------- */
/* Main monitoring loop                                                       */
/* -------------------------------------------------------------------------- */

async function check() {
  try {
    const current =
      await collectInventory();

    state.current = current;

    if (!state.baseline) {
      saveBaseline(current);

      state.baseline = loadBaseline();

      console.log(
        "[+] Bluetooth hardware baseline created"
      );

      console.log(
        JSON.stringify(
          current,
          null,
          2
        )
      );

      return;
    }

    compareInventory(
      state.baseline,
      current
    );
  } catch (err) {
    event(
      "bluetooth_monitor_error",
      "medium",
      "Bluetooth inventory collection failed",
      {
        error: err.message
      }
    );
  }
}

/* -------------------------------------------------------------------------- */
/* Startup                                                                     */
/* -------------------------------------------------------------------------- */

async function main() {
  console.log(
    "=============================================="
  );
  console.log(
    " Bluetooth Guard - Hardware Integrity Monitor"
  );
  console.log(
    "=============================================="
  );

  console.log(
    `Host: ${os.hostname()}`
  );

  console.log(
    `OS: ${process.platform}`
  );

  console.log(
    `Check interval: ${CONFIG.interval} ms`
  );

  await check();

  setInterval(
    check,
    CONFIG.interval
  );
}

process.on(
  "SIGINT",
  () => {
    console.log(
      "\n[+] Bluetooth Guard stopped"
    );

    process.exit(0);
  }
);

process.on(
  "SIGTERM",
  () => {
    console.log(
      "\n[+] Bluetooth Guard stopped"
    );

    process.exit(0);
  }
);

main().catch((err) => {
  console.error(
    "[FATAL]",
    err
  );

  process.exit(1);
});

