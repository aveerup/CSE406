import csv
import os
import re
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = os.path.join(os.path.dirname(__file__), "..")
LOGS = os.path.join(ROOT, "logs")
PLOTS = os.path.join(LOGS, "plots")

ATTACKER_LOG = os.path.join(LOGS, "attacker.log")
GUARD_LOG = os.path.join(LOGS, "dhcp_guard_alerts.log")
BENCHMARK_CSV = os.path.join(LOGS, "benchmark.csv")

TS_RE = r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})"


def _read_lines(path):
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        print(f"[skip] {path} missing/empty")
        return []
    with open(path) as f:
        return f.readlines()


def plot_benchmark():
    if not os.path.exists(BENCHMARK_CSV):
        print(f"[skip] {BENCHMARK_CSV} missing - run tests/benchmark.py first")
        return
    ops, avgs = [], []
    with open(BENCHMARK_CSV) as f:
        for row in csv.DictReader(f):
            ops.append(row["operation"])
            avgs.append(float(row["avg_microseconds"]))

    fig, ax = plt.subplots(figsize=(9, 5))
    bars = ax.barh(ops, avgs, color="#c0392b")
    ax.set_xlabel("Average time per operation (microseconds)")
    ax.set_title("Hand-rolled packet crafting/parsing performance\n(no packet-crafting library, pure struct)")
    ax.bar_label(bars, fmt="%.2f us")
    fig.tight_layout()
    _save(fig, "benchmark_packet_crafting.png")


def plot_attack_timeline():
    lines = _read_lines(ATTACKER_LOG)
    if not lines:
        return
    discover_latencies, ack_latencies = [], []
    victims = 0
    discovers = 0
    for line in lines:
        if "forged OFFER" in line:
            discovers += 1
            m = re.search(r"in ([\d.]+) ms", line)
            if m:
                discover_latencies.append(float(m.group(1)))
        elif "forged ACK" in line:
            m = re.search(r"in ([\d.]+) ms", line)
            if m:
                ack_latencies.append(float(m.group(1)))
        elif "VICTIM CAPTURED" in line:
            victims += 1

    if discover_latencies:
        fig, ax = plt.subplots(figsize=(7, 5))
        ax.hist(discover_latencies, bins=min(20, max(5, len(discover_latencies) // 2)), color="#c0392b", alpha=0.8, label="DISCOVER -> forged OFFER")
        if ack_latencies:
            ax.hist(ack_latencies, bins=min(20, max(5, len(ack_latencies) // 2)), color="#2980b9", alpha=0.6, label="REQUEST -> forged ACK")
        ax.set_xlabel("Latency (ms)")
        ax.set_ylabel("Count")
        ax.set_title("Rogue DHCP server response latency (live capture)")
        ax.legend()
        fig.tight_layout()
        _save(fig, "attack_response_latency.png")
    else:
        print("[skip] no timed DISCOVER/OFFER lines found in attacker.log yet - run the live attack first")

    fig, ax = plt.subplots(figsize=(5, 5))
    labels = ["DHCPDISCOVER seen", "Victims captured\n(forged ACK accepted)"]
    values = [discovers, victims]
    bars = ax.bar(labels, values, color=["#7f8c8d", "#c0392b"])
    ax.set_ylabel("Count")
    ax.set_title("Attack outcome (live capture)")
    ax.bar_label(bars)
    fig.tight_layout()
    _save(fig, "attack_outcome.png")


def plot_defense_alerts():
    lines = _read_lines(GUARD_LOG)
    if not lines:
        return
    rogue, race, legit = 0, 0, 0
    for line in lines:
        if "ROGUE DHCP" in line:
            rogue += 1
        elif "RACE CONDITION" in line:
            race += 1
        elif "Legit DHCP" in line:
            legit += 1

    fig, ax = plt.subplots(figsize=(6, 5))
    labels = ["Legit DHCP\nreplies", "ROGUE DHCP\nalerts", "Multi-server\nrace alerts"]
    values = [legit, rogue, race]
    bars = ax.bar(labels, values, color=["#27ae60", "#c0392b", "#e67e22"])
    ax.set_ylabel("Count")
    ax.set_title("DHCP Guard detections (live capture)")
    ax.bar_label(bars)
    fig.tight_layout()
    _save(fig, "defense_alerts.png")


def _save(fig, name):
    os.makedirs(PLOTS, exist_ok=True)
    path = os.path.join(PLOTS, name)
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"[ok] wrote {path}")


if __name__ == "__main__":
    plot_benchmark()
    plot_attack_timeline()
    plot_defense_alerts()
