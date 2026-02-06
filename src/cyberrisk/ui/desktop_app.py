"""CyberRisk Monitor - Desktop UI

Displays the latest analysis run from the backend storage layer.
Run `cyberrisk analyze <logfile>` first to generate data.
"""

import tkinter as tk
from tkinter import ttk

from cyberrisk.storage import load_latest_run


def _load_run_data():
    """Load the latest run and return normalized UI data."""
    run = load_latest_run()
    if run is None:
        return None

    summary = run.get("summary", {})
    detections = run.get("detections", [])
    generated_at = run.get("generated_at", "N/A")

    # Count detections by severity label
    counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    alerts = []
    for det in detections:
        if isinstance(det, dict):
            sev = det.get("severity_label", "Unknown")
            counts[sev] = counts.get(sev, 0) + 1
            alerts.append((
                det.get("rule_name", "Unknown"),
                sev,
                det.get("group_key", "N/A"),
                det.get("timestamp", "N/A"),
            ))
        else:
            # Fallback for string-serialized detections
            counts["Medium"] += 1
            alerts.append((str(det)[:50], "Medium", "N/A", "N/A"))

    return {
        "total_score": summary.get("total_score", 0),
        "risk_level": summary.get("risk_level", "Unknown"),
        "counts": counts,
        "alerts": alerts,
        "generated_at": generated_at,
        "parsed_entries": run.get("parsed_entries", 0),
        "detections_count": run.get("detections_count", 0),
    }


def main():
    root = tk.Tk()
    root.title("CyberRisk Monitor")
    root.geometry("900x650")

    # -- Header Section --
    header_frame = ttk.Frame(root, padding="10")
    header_frame.pack(fill=tk.X)

    title_label = ttk.Label(
        header_frame, text="CyberRisk Monitor", font=("Arial", 24, "bold")
    )
    title_label.pack(side=tk.LEFT)

    button_frame = ttk.Frame(header_frame)
    button_frame.pack(side=tk.RIGHT)

    export_btn = ttk.Button(button_frame, text="Export")
    export_btn.pack(side=tk.LEFT, padx=5)

    refresh_btn = ttk.Button(button_frame, text="Refresh")
    refresh_btn.pack(side=tk.LEFT, padx=5)

    timestamp_label = ttk.Label(
        root, text="Last Analysis: N/A", font=("Arial", 10)
    )
    timestamp_label.pack(anchor=tk.W, padx=10)

    ttk.Separator(root, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)

    # -- Risk Summary Section --
    summary_frame = ttk.LabelFrame(root, text="Risk Summary", padding="10")
    summary_frame.pack(fill=tk.X, padx=10, pady=5)

    counts_frame = ttk.Frame(summary_frame)
    counts_frame.pack(fill=tk.X)

    colors = {"Low": "green", "Medium": "orange", "High": "red", "Critical": "darkred"}
    count_labels = {}
    for category in ("Low", "Medium", "High", "Critical"):
        frame = ttk.Frame(counts_frame)
        frame.pack(side=tk.LEFT, expand=True, padx=20)
        ttk.Label(frame, text=category, font=("Arial", 12)).pack()
        lbl = tk.Label(frame, text="0", font=("Arial", 24, "bold"), fg=colors[category])
        lbl.pack()
        count_labels[category] = lbl

    score_label = ttk.Label(
        summary_frame, text="Overall Risk Score: --", font=("Arial", 14, "bold")
    )
    score_label.pack(pady=10)

    ttk.Separator(root, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)

    # -- Alerts Section --
    alerts_frame = ttk.LabelFrame(root, text="Alerts", padding="10")
    alerts_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    filter_frame = ttk.Frame(alerts_frame)
    filter_frame.pack(fill=tk.X, pady=(0, 10))

    ttk.Label(filter_frame, text="Filter by Severity:").pack(side=tk.LEFT)
    severity_filter = ttk.Combobox(
        filter_frame,
        values=["All", "Low", "Medium", "High", "Critical"],
        state="readonly",
        width=15,
    )
    severity_filter.set("All")
    severity_filter.pack(side=tk.LEFT, padx=10)

    columns = ("alert_type", "severity", "source_ip", "timestamp")
    tree = ttk.Treeview(alerts_frame, columns=columns, show="headings", height=10)

    tree.heading("alert_type", text="Alert Type")
    tree.heading("severity", text="Severity")
    tree.heading("source_ip", text="Source IP")
    tree.heading("timestamp", text="Timestamp")

    tree.column("alert_type", width=200)
    tree.column("severity", width=100)
    tree.column("source_ip", width=150)
    tree.column("timestamp", width=150)

    scrollbar = ttk.Scrollbar(alerts_frame, orient=tk.VERTICAL, command=tree.yview)
    tree.configure(yscrollcommand=scrollbar.set)

    tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # -- State holding the current alerts for filtering --
    current_alerts = []

    def refresh_alerts(event=None):
        """Filter the alerts table based on selected severity."""
        tree.delete(*tree.get_children())
        selected = severity_filter.get()
        for alert in current_alerts:
            if selected == "All" or alert[1] == selected:
                tree.insert("", tk.END, values=alert)

    def load_data():
        """Load latest run data from storage and update all UI elements."""
        nonlocal current_alerts
        data = _load_run_data()

        if data is None:
            timestamp_label.config(
                text="No analysis data found. Run: cyberrisk analyze <logfile>"
            )
            score_label.config(text="Overall Risk Score: --")
            for cat in count_labels:
                count_labels[cat].config(text="0")
            current_alerts = []
            refresh_alerts()
            return

        timestamp_label.config(text=f"Last Analysis: {data['generated_at']}")
        score_label.config(
            text=f"Overall Risk Score: {data['total_score']}  |  "
                 f"Level: {data['risk_level']}  |  "
                 f"Entries: {data['parsed_entries']}  |  "
                 f"Detections: {data['detections_count']}"
        )

        for cat, lbl in count_labels.items():
            lbl.config(text=str(data["counts"].get(cat, 0)))

        current_alerts = data["alerts"]
        refresh_alerts()

    severity_filter.bind("<<ComboboxSelected>>", refresh_alerts)
    refresh_btn.config(command=load_data)

    # Initial load
    load_data()

    root.mainloop()


if __name__ == "__main__":
    main()
