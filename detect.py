#!/usr/bin/env python3
"""
Wireless IDS - Real-Time Detector

Sniffs live 802.11 traffic on the monitor-mode interface, computes the same
per-second window features that extract.py used for training, and runs each
window through the saved Random Forest model. Prints an alert whenever a
window is classified as anything other than "normal".

Run with:
  sudo python3 detect.py
"""

from pathlib import Path
from collections import Counter
import warnings
import time
import joblib
from scapy.all import sniff, Dot11, RadioTap

warnings.filterwarnings("ignore", category=UserWarning)

SNIFF_IFACE = "wlan3"
WINDOW_SECONDS = 1.0
MODELS_DIR = Path("/home/james/wids/models")

# Smoothing: require this many consecutive windows predicting the SAME
# attack, each above CONFIDENCE_THRESHOLD, before raising an alert. This
# stops a single noisy/borderline window from triggering a false alarm.
CONSECUTIVE_WINDOWS_REQUIRED = 3
CONFIDENCE_THRESHOLD = 0.70

SUBTYPE_NAMES = {
    0: "assoc_req", 1: "assoc_resp", 4: "probe_req", 5: "probe_resp",
    8: "beacon", 10: "disassoc", 11: "auth", 12: "deauth",
}


class WindowState:
    """Accumulates frames for the current 1-second window."""
    def __init__(self):
        self.reset()

    def reset(self):
        self.start_time = time.time()
        self.frame_counts = Counter()
        self.rssi_values = []
        self.src_counts = Counter()

    def add(self, pkt):
        dot11 = pkt[Dot11]
        ftype = dot11.type
        subtype_name = SUBTYPE_NAMES.get(dot11.subtype, f"type{ftype}_sub{dot11.subtype}")

        self.frame_counts["total"] += 1
        self.frame_counts[f"type_{ftype}"] += 1
        self.frame_counts[subtype_name] += 1

        if pkt.haslayer(RadioTap):
            rssi = getattr(pkt[RadioTap], "dBm_AntSignal", None)
            if rssi is not None:
                self.rssi_values.append(rssi)

        src = dot11.addr2
        if src:
            self.src_counts[src] += 1

    def to_feature_row(self, feature_cols):
        fc = self.frame_counts
        rssi_vals = self.rssi_values
        src_counts = self.src_counts

        total_frames = fc.get("total", 0)
        busiest_device_frames = max(src_counts.values()) if src_counts else 0

        row = {
            "mgmt_count": fc.get("type_0", 0),
            "ctrl_count": fc.get("type_1", 0),
            "data_count": fc.get("type_2", 0),
            "beacon_count": fc.get("beacon", 0),
            "deauth_count": fc.get("deauth", 0),
            "disassoc_count": fc.get("disassoc", 0),
            "probe_req_count": fc.get("probe_req", 0),
            "avg_rssi": sum(rssi_vals) / len(rssi_vals) if rssi_vals else 0,
            "min_rssi": min(rssi_vals) if rssi_vals else 0,
            "frames_per_sec": total_frames / WINDOW_SECONDS,
            "unique_devices": len(src_counts),
            "busiest_device_frames_per_sec": busiest_device_frames / WINDOW_SECONDS,
        }
        # keep the exact column order the model was trained on
        return [row[c] for c in feature_cols]


def main():
    print("Loading model...")
    model = joblib.load(MODELS_DIR / "random_forest.joblib")
    feature_cols = joblib.load(MODELS_DIR / "feature_cols.joblib")
    print(f"Model loaded. Watching {SNIFF_IFACE} for attacks (Ctrl+C to stop)...\n")

    state = WindowState()
    streak_label = None
    streak_count = 0
    alert_active = False

    def handle_packet(pkt):
        nonlocal state, streak_label, streak_count, alert_active
        if not pkt.haslayer(Dot11):
            return

        state.add(pkt)

        elapsed = time.time() - state.start_time
        if elapsed >= WINDOW_SECONDS:
            row = state.to_feature_row(feature_cols)
            prediction = model.predict([row])[0]
            proba = model.predict_proba([row])[0]
            confidence = max(proba)
            timestamp = time.strftime("%H:%M:%S")

            is_confident_attack = (prediction != "normal") and (confidence >= CONFIDENCE_THRESHOLD)

            if is_confident_attack and prediction == streak_label:
                streak_count += 1
            elif is_confident_attack:
                streak_label = prediction
                streak_count = 1
            else:
                streak_label = None
                streak_count = 0
                if alert_active:
                    print(f"[{timestamp}] back to normal")
                alert_active = False

            if is_confident_attack and streak_count >= CONSECUTIVE_WINDOWS_REQUIRED:
                print(f"[{timestamp}] *** ALERT: {prediction.upper()} DETECTED "
                      f"(confidence {confidence:.2f}, {streak_count} consecutive windows) ***")
                alert_active = True
            elif not is_confident_attack:
                print(f"[{timestamp}] normal (confidence {confidence:.2f})")
            else:
                print(f"[{timestamp}] watching: possible {prediction} "
                      f"({streak_count}/{CONSECUTIVE_WINDOWS_REQUIRED}, confidence {confidence:.2f})")

            state.reset()

    sniff(iface=SNIFF_IFACE, prn=handle_packet, store=False)


if __name__ == "__main__":
    main()
