"""CyberRisk Monitor - Desktop UI"""
import tkinter as tk
from tkinter import ttk


def main():
    root = tk.Tk()
    root.title("CyberRisk Monitor")
    root.geometry("900x650")

    # Header Section
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
        root, text="Last Analysis: 2026-01-20 14:30:00", font=("Arial", 10)
    )
    timestamp_label.pack(anchor=tk.W, padx=10)

    ttk.Separator(root, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)

    # Risk Summary Section
    summary_frame = ttk.LabelFrame(root, text="Risk Summary", padding="10")
    summary_frame.pack(fill=tk.X, padx=10, pady=5)

    counts_frame = ttk.Frame(summary_frame)
    counts_frame.pack(fill=tk.X)

    risk_counts = [
        ("Low", "5", "green"),
        ("Medium", "3", "orange"),
        ("High", "2", "red"),
        ("Critical", "1", "darkred"),
    ]

    for label_text, count, color in risk_counts:
        frame = ttk.Frame(counts_frame)
        frame.pack(side=tk.LEFT, expand=True, padx=20)
        ttk.Label(frame, text=label_text, font=("Arial", 12)).pack()
        count_label = tk.Label(
            frame, text=count, font=("Arial", 24, "bold"), fg=color
        )
        count_label.pack()

    score_label = ttk.Label(
        summary_frame, text="Overall Risk Score: 65%", font=("Arial", 14, "bold")
    )
    score_label.pack(pady=10)

    ttk.Separator(root, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)

    # Alerts Section
    alerts_frame = ttk.LabelFrame(root, text="Alerts", padding="10")
    alerts_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    # Filter row
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

    # Alerts table
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

    # Mock data
    mock_alerts = [
        ("Brute Force Attack", "High", "192.168.1.1", "Jan 20, 2026"),
        ("Port Scanning", "Medium", "192.168.1.2", "Jan 20, 2026"),
        ("Privilege Escalation", "Critical", "192.168.1.3", "Jan 20, 2026"),
    ]

    for alert in mock_alerts:
        tree.insert("", tk.END, values=alert)

    # Scrollbar
    scrollbar = ttk.Scrollbar(alerts_frame, orient=tk.VERTICAL, command=tree.yview)
    tree.configure(yscrollcommand=scrollbar.set)

    tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    root.mainloop()


if __name__ == "__main__":
    main()
