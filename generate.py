#!/usr/bin/env python3
"""
Wireless IDS - Traffic Generator

Automates capturing labeled pcap samples for four classes:
  normal, deauth, beacon_flood, probe_flood

Prerequisites (run these first, in their own terminals, and leave them running):
  Terminal 1: sudo hostapd ~/wids/ap.conf
  Terminal 2: sudo wpa_supplicant -i wlan1 -c ~/wids/client.conf -B

Run this script with:
  sudo python3 generate.py
"""

import subprocess
import time
import random
import os
import signal
from pathlib import Path

# ---- Config ----
AP_MAC = "02:00:00:00:00:00"
CLIENT_MAC = "02:00:00:00:01:00"
SNIFF_IFACE = "wlan3"      # monitor-mode sniffer
ATTACK_IFACE = "wlan2"     # monitor-mode attacker

DATA_DIR = Path("/home/james/wids/data")
SAMPLES_PER_CLASS = 20      # set to 20 once the smoke test passes
MIN_DURATION = 15          # seconds
MAX_DURATION = 25

CLASSES = ["normal", "deauth", "beacon_flood", "probe_flood"]


def ensure_dirs():
    for c in CLASSES:
        (DATA_DIR / c).mkdir(parents=True, exist_ok=True)


def start_capture(out_path, duration):
    """Start dumpcap writing to out_path, for `duration` seconds.

    The output file is opened here, by this (root) process, and handed
    to dumpcap as its stdout. This sidesteps the permission issue we hit
    earlier: dumpcap drops privileges before it opens a -w file itself,
    but it keeps writing to an already-open stdout without a problem.
    """
    f = open(out_path, "wb")
    proc = subprocess.Popen(
        ["dumpcap", "-i", SNIFF_IFACE, "-a", f"duration:{duration}",
         "-F", "pcap", "-w", "-"],
        stdout=f, stderr=subprocess.DEVNULL
    )
    return proc, f


def run_attack(label, duration):
    """Launch the attack process for this label; returns a Popen or None."""
    if label == "normal":
        return None
    if label == "deauth":
        # 0 = send continuously until we stop it ourselves
        return subprocess.Popen(
            ["aireplay-ng", "--deauth", "0", "-a", AP_MAC, "-c", CLIENT_MAC, ATTACK_IFACE],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    if label == "beacon_flood":
        return subprocess.Popen(
            ["mdk4", ATTACK_IFACE, "b", "-c", "6"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    if label == "probe_flood":
        return subprocess.Popen(
            ["mdk4", ATTACK_IFACE, "p", "-e", "LabNet", "-s", "50"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    raise ValueError(f"Unknown label: {label}")


def stop_attack(proc):
    if proc is None:
        return
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()


def capture_sample(label, index):
    duration = random.randint(MIN_DURATION, MAX_DURATION)
    out_path = DATA_DIR / label / f"{label}_{index:03d}.pcap"
    print(f"[{label}] sample {index}/{SAMPLES_PER_CLASS}: {duration}s -> {out_path.name}")

    cap_proc, f = start_capture(out_path, duration)
    time.sleep(2)  # let the capture spin up before the attack starts

    attack_proc = run_attack(label, duration)

    cap_proc.wait()  # blocks until dumpcap's own duration timer ends
    f.close()
    stop_attack(attack_proc)

    size = out_path.stat().st_size if out_path.exists() else 0
    print(f"    done ({size} bytes)")


def main():
    if os.geteuid() != 0:
        raise SystemExit("Run with sudo: sudo python3 generate.py")

    ensure_dirs()
    for label in CLASSES:
        for i in range(1, SAMPLES_PER_CLASS + 1):
            capture_sample(label, i)
            time.sleep(1)  # brief gap between samples

    print("Done. Samples saved under", DATA_DIR)


if __name__ == "__main__":
    main()
