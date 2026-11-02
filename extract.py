#!/usr/bin/env python3
"""
Wireless IDS - Feature Extractor

Reads every labeled pcap under DATA_DIR (produced by generate.py) and turns
it into one row per time window (default 1 second), with columns for:
  - frame type counts (deauth, disassoc, beacon, probe_req, management/
    control/data totals)
  - signal strength (avg / min RSSI in that window)
  - frames per second, and the busiest single device's frames per second
    (a stand-in for "frames/sec per device" while keeping one row per window)

Run with:
  python3 extract.py
(No sudo needed - this only reads pcap files, it doesn't touch the network.)
"""

from pathlib import Path
from collections import Counter, defaultdict
import pandas as pd
from scapy.all import rdpcap, Dot11, RadioTap

DATA_DIR = Path("/home/james/wids/data")
OUTPUT_CSV = Path("/home/james/wids/data/features.csv")
WINDOW_SECONDS = 1.0

# 802.11 management-frame subtypes we care about by name
SUBTYPE_NAMES = {
    0: "assoc_req", 1: "assoc_resp", 4: "probe_req", 5: "probe_resp",
    8: "beacon", 10: "disassoc", 11: "auth", 12: "deauth",
}


def classify_frame(pkt):
    """Return (type, subtype_name) for a Dot11 frame."""
    dot11 = pkt[Dot11]
    ftype = dot11.type          # 0=management, 1=control, 2=data
    subtype = dot11.subtype
    name = SUBTYPE_NAMES.get(subtype, f"type{ftype}_sub{subtype}")
    return ftype, name


def get_rssi(pkt):
    """Pull signal strength (dBm) from the RadioTap header, if present."""
    if pkt.haslayer(RadioTap):
        rssi = getattr(pkt[RadioTap], "dBm_AntSignal", None)
        return rssi
    return None


def extract_windows(pcap_path, label):
    packets = rdpcap(str(pcap_path))
    if len(packets) == 0:
        return []

    t0 = float(packets[0].time)
    windows = defaultdict(lambda: {
        "frame_counts": Counter(),
        "rssi_values": [],
        "src_counts": Counter(),
    })

    for pkt in packets:
        if not pkt.haslayer(Dot11):
            continue
        w_idx = int((float(pkt.time) - t0) // WINDOW_SECONDS)
        w = windows[w_idx]

        ftype, subtype_name = classify_frame(pkt)
        w["frame_counts"]["total"] += 1
        w["frame_counts"][f"type_{ftype}"] += 1
        w["frame_counts"][subtype_name] += 1

        rssi = get_rssi(pkt)
        if rssi is not None:
            w["rssi_values"].append(rssi)

        src = pkt[Dot11].addr2
        if src:
            w["src_counts"][src] += 1

    rows = []
    for w_idx in sorted(windows.keys()):
        w = windows[w_idx]
        fc = w["frame_counts"]
        rssi_vals = w["rssi_values"]
        src_counts = w["src_counts"]

        total_frames = fc.get("total", 0)
        busiest_device_frames = max(src_counts.values()) if src_counts else 0

        rows.append({
            "pcap": pcap_path.name,
            "window": w_idx,
            "label": label,
            # frame type counts
            "mgmt_count": fc.get("type_0", 0),
            "ctrl_count": fc.get("type_1", 0),
            "data_count": fc.get("type_2", 0),
            "beacon_count": fc.get("beacon", 0),
            "deauth_count": fc.get("deauth", 0),
            "disassoc_count": fc.get("disassoc", 0),
            "probe_req_count": fc.get("probe_req", 0),
            # signal strength
            "avg_rssi": sum(rssi_vals) / len(rssi_vals) if rssi_vals else 0,
            "min_rssi": min(rssi_vals) if rssi_vals else 0,
            # rate features
            "frames_per_sec": total_frames / WINDOW_SECONDS,
            "unique_devices": len(src_counts),
            "busiest_device_frames_per_sec": busiest_device_frames / WINDOW_SECONDS,
        })

    return rows


def main():
    all_rows = []
    for class_dir in sorted(DATA_DIR.iterdir()):
        if not class_dir.is_dir():
            continue
        label = class_dir.name
        pcaps = sorted(class_dir.glob("*.pcap"))
        print(f"[{label}] {len(pcaps)} pcap file(s)")
        for pcap_path in pcaps:
            rows = extract_windows(pcap_path, label)
            all_rows.extend(rows)
            print(f"    {pcap_path.name}: {len(rows)} window(s)")

    df = pd.DataFrame(all_rows)
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"\nWrote {len(df)} rows to {OUTPUT_CSV}")
    print(df["label"].value_counts())


if __name__ == "__main__":
    main()
