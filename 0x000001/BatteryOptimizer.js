#!/usr/bin/env node
/**
 * battery-optimizer.js — Simple Fedora battery optimizer
 * Usage: sudo node battery-optimizer.js
 * No dependencies. Writes directly to /sys.
 */

const fs = require('fs');
const path = require('path');

// ─── Helpers ────────────────────────────────────────────────────────────────

function writeSysfs(filePath, value, label) {
  try {
    fs.writeFileSync(filePath, value);
    console.log(`  ✓ ${label} → ${value}`);
    return true;
  } catch (e) {
    console.log(`  ✗ ${label} (${e.code === 'ENOENT' ? 'not supported' : e.message})`);
    return false;
  }
}

function readSysfs(filePath) {
  try { return fs.readFileSync(filePath, 'utf-8').trim(); }
  catch { return null; }
}

function exists(p) { return fs.existsSync(p); }

// ─── Power source detection ─────────────────────────────────────────────────

function getPowerSource() {
  const acPaths = [
    '/sys/class/power_supply/AC/online',
    '/sys/class/power_supply/ACAD/online',
    '/sys/class/power_supply/ADP/online',
    '/sys/class/power_supply/USB/online',
    '/sys/class/power_supply/AC0/online',
  ];
  for (const p of acPaths) {
    const val = readSysfs(p);
    if (val !== null) return val === '1' ? 'AC' : 'BAT';
  }
  return 'UNKNOWN';
}

function getBatteryInfo() {
  const batPaths = [
    '/sys/class/power_supply/BAT0',
    '/sys/class/power_supply/BAT1',
    '/sys/class/power_supply/battery',
  ];
  for (const dir of batPaths) {
    if (!exists(dir)) continue;
    return {
      dir,
      capacity: readSysfs(path.join(dir, 'capacity')),
      status: readSysfs(path.join(dir, 'status')),
      health: readSysfs(path.join(dir, 'health')),
    };
  }
  return null;
}

// ─── CPU Governor ───────────────────────────────────────────────────────────

function setCpuGovernor(governor) {
  console.log(`\n[CPU Governor] Setting: ${governor}`);
  let count = 0;
  for (let i = 0; ; i++) {
    const govPath = `/sys/devices/system/cpu/cpu${i}/cpufreq/scaling_governor`;
    if (!exists(govPath)) break;
    writeSysfs(govPath, governor, `cpu${i}`);
    count++;
  }
  if (count === 0) console.log('  (no cpufreq interface found — using pstate)');
}

// ─── Intel P-state ──────────────────────────────────────────────────────────

function setIntelPstate(mode) {
  console.log(`\n[Intel P-state] Mode: ${mode}`);
  const base = '/sys/devices/system/cpu/intel_pstate';
  if (!exists(base)) return;

  if (mode === 'BAT') {
    writeSysfs(path.join(base, 'no_turbo'), '1', 'Disable turbo');
    writeSysfs(path.join(base, 'max_perf_pct'), '60', 'Max perf 60%');
  } else {
    writeSysfs(path.join(base, 'no_turbo'), '0', 'Enable turbo');
    writeSysfs(path.join(base, 'max_perf_pct'), '100', 'Max perf 100%');
  }
}

// ─── Energy Performance Preference (Intel + AMD) ────────────────────────────

function setEPP(preference) {
  console.log(`\n[EPP] Setting: ${preference}`);
  for (let i = 0; ; i++) {
    const eppPath = `/sys/devices/system/cpu/cpu${i}/cpufreq/energy_performance_preference`;
    if (!exists(eppPath)) break;
    writeSysfs(eppPath, preference, `cpu${i}`);
  }
}

// ─── USB Autosuspend ────────────────────────────────────────────────────────

function setUsbAutosuspend(enabled) {
  console.log(`\n[USB] Autosuspend: ${enabled ? 'ON' : 'OFF'}`);
  writeSysfs('/sys/module/usbcore/parameters/autosuspend',
    enabled ? '1' : '2', 'usbcore autosuspend');
}

// ─── PCIe ASPM ──────────────────────────────────────────────────────────────

function setPcieAspm(policy) {
  console.log(`\n[PCIe ASPM] Policy: ${policy}`);
  writeSysfs('/sys/module/pcie_aspm/parameters/policy', policy, 'pcie_aspm');
}

// ─── WiFi Power Save ────────────────────────────────────────────────────────

function setWifiPowerSave(enabled) {
  console.log(`\n[WiFi] Power save: ${enabled ? 'ON' : 'OFF'}`);
  const { execSync } = require('child_process');
  try {
    execSync(`iwconfig 2>/dev/null | grep -oP '^\\w+' | head -1`, { encoding: 'utf-8' });
    const iface = execSync(`iwconfig 2>/dev/null | grep -oP '^\\w+' | head -1`, { encoding: 'utf-8' }).trim();
    if (iface) {
      execSync(`iw dev ${iface} set power_save ${enabled ? 'on' : 'off'}`, { stdio: 'pipe' });
      console.log(`  ✓ ${iface} power_save ${enabled ? 'on' : 'off'}`);
    }
  } catch {
    console.log('  (iw not available or no WiFi interface)');
  }
}

// ─── Disk APM ───────────────────────────────────────────────────────────────

function setDiskAPM(level) {
  console.log(`\n[Disk] APM level: ${level}`);
  const { execSync } = require('child_process');
  try {
    const disks = execSync('ls /sys/block/ 2>/dev/null | grep -E "^(sd|nvme|vd)"', { encoding: 'utf-8' }).trim().split('\n');
    for (const disk of disks) {
      const apmPath = `/sys/block/${disk}/device/queue/rotational`;
      if (exists(apmPath) && readSysfs(apmPath) === '1') {
        // Only set APM on spinning disks
        try {
          execSync(`hdparm -B ${level} /dev/${disk}`, { stdio: 'pipe' });
          console.log(`  ✓ /dev/${disk} APM=${level}`);
        } catch {}
      }
    }
  } catch {}
}

// ─── SATA Link Power ────────────────────────────────────────────────────────

function setSataLinkPwr(mode) {
  console.log(`\n[SATA Link] Power: ${mode}`);
  const { execSync } = require('child_process');
  try {
    const links = execSync('find /sys/class/ata_link -name "power_management" 2>/dev/null', { encoding: 'utf-8' }).trim().split('\n');
    for (const f of links) {
      if (f) writeSysfs(f, mode, path.basename(path.dirname(f)));
    }
    if (links.length === 0) console.log('  (no SATA links found)');
  } catch {}
}

// ─── Battery Charge Thresholds ──────────────────────────────────────────────

function setChargeThresholds(startPct, endPct) {
  console.log(`\n[Battery Thresholds] Start: ${startPct}%, Stop: ${endPct}%`);
  const bat = getBatteryInfo();
  if (!bat) return;

  const startPath = path.join(bat.dir, 'charge_control_start_threshold');
  const endPath = path.join(bat.dir, 'charge_control_end_threshold');

  if (exists(startPath)) writeSysfs(startPath, String(startPct), 'start threshold');
  else console.log('  (charge_control_start_threshold not available on this hardware)');

  if (exists(endPath)) writeSysfs(endPath, String(endPct), 'stop threshold');
  else console.log('  (charge_control_end_threshold not available on this hardware)');
}

// ─── Runtime PM for PCI devices ─────────────────────────────────────────────

function setPciRuntimePm(mode) {
  console.log(`\n[PCI Runtime PM] Mode: ${mode}`);
  const { execSync } = require('child_process');
  try {
    const files = execSync('find /sys/bus/pci/devices -name "power/control" 2>/dev/null', { encoding: 'utf-8' }).trim().split('\n');
    let count = 0;
    for (const f of files) {
      if (f) {
        try { fs.writeFileSync(f, mode); count++; } catch {}
      }
    }
    console.log(`  ✓ ${count} PCI devices set to "${mode}"`);
  } catch {}
}

// ─── Main ───────────────────────────────────────────────────────────────────

function applyProfile(source) {
  const isBattery = source === 'BAT';
  const profile = isBattery ? 'BATTERY (power save)' : 'AC (performance)';
  console.log(`\n${'═'.repeat(50)}`);
  console.log(`  Applying profile: ${profile}`);
  console.log(`${'═'.repeat(50)}`);

  // CPU
  setCpuGovernor(isBattery ? 'powersave' : 'performance');
  setIntelPstate(isBattery ? 'BAT' : 'AC');
  setEPP(isBattery ? 'power' : 'performance');

  // USB
  setUsbAutosuspend(isBattery);

  // PCIe
  setPcieAspm(isBattery ? 'powersupersave' : 'performance');

  // WiFi
  setWifiPowerSave(isBattery);

  // Disk
  setDiskAPM(isBattery ? '128' : '254');
  setSataLinkPwr(isBattery ? 'med_power_with_dipm' : 'max_performance');

  // PCI runtime PM
  setPciRuntimePm(isBattery ? 'auto' : 'on');

  // Battery thresholds (only meaningful on battery)
  if (isBattery) {
    setChargeThresholds(75, 80);
  }

  // Status
  const bat = getBatteryInfo();
  if (bat) {
    console.log(`\n🔋 Battery: ${bat.capacity}% (${bat.status})`);
  }
  console.log('');
}



function main() {
  if (process.getuid() !== 0) {
    console.error('⚠️  Run with sudo: sudo node battery-optimizer.js');
    process.exit(1);
  }

  console.log('🔋 Battery Optimizer for Fedora');
  console.log(`   Node ${process.version} | PID ${process.pid}\n`);

  // Initial apply
  const source = getPowerSource();
  applyProfile(source);

  // Watch for power source changes
  console.log('⏳ Monitoring power source changes (Ctrl+C to stop)...');
  let lastSource = source;

  const interval = setInterval(() => {
    const current = getPowerSource();
    if (current !== lastSource) {
      console.log(`\n⚡ Power source changed: ${lastSource} → ${current}`);
      lastSource = current;
      applyProfile(current);
    }
  }, 5000); // check every 5s

  process.on('SIGINT', () => {
    console.log('\n👋 Stopped. Settings persist until reboot or next profile switch.');
    process.exit(0);
  });
}

main(); 
