"""CyberRisk Monitor - Desktop UI"""
import csv
import io
import json
import re
import tkinter as tk
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


RUN_PATH = Path("data/runs/latest.json")


def load_latest_run():
    """Load the most recent backend run JSON saved at data/runs/latest.json."""
    if not RUN_PATH.exists():
        messagebox.showwarning(
            "No Analysis Found",
            "No saved run found at data/runs/latest.json.\n"
            "Run the CLI analyze command first to generate it."
        )
        return None

    with RUN_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


# ── Helper: timestamp parsing ──

def _parse_timestamp(ts_str):
    """Parse an ISO-format timestamp string into a datetime object."""
    try:
        return datetime.fromisoformat(ts_str)
    except (ValueError, TypeError):
        return None


# ── Helper: time-window filtering ──

def _filter_by_time_window(rows, time_window, generated_at_str):
    """Return rows whose timestamp falls within *time_window* of now (UTC).

    Each row is a ``(name, severity, source, timestamp)`` tuple.  The
    per-row timestamp (index 3) is tried first; *generated_at_str* is
    the fallback when the field cannot be parsed.
    """
    if time_window == "Entire run":
        return list(rows)

    now = datetime.now(timezone.utc)
    if time_window == "Last 5 minutes":
        cutoff = now - timedelta(minutes=5)
    elif time_window == "Last hour":
        cutoff = now - timedelta(hours=1)
    else:
        return list(rows)

    result = []
    for row in rows:
        ts = _parse_timestamp(row[3]) or _parse_timestamp(generated_at_str)
        if ts is not None:
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if ts >= cutoff:
                result.append(row)
    return result


# ── Helper: entity grouping ──

def _group_alerts(rows, group_by):
    """Group *rows* into ``{key: [rows]}``.

    *group_by*: ``"None"`` | ``"Source IP"`` | ``"User"`` | ``"Rule"``.
    """
    if group_by == "None":
        return {"All": list(rows)}

    groups = {}
    for row in rows:
        if group_by in ("Source IP", "User"):
            key = row[2]  # source / user field
        elif group_by == "Rule":
            key = row[0]  # rule_name
        else:
            key = "All"
        groups.setdefault(key, []).append(row)
    return groups


# ── Helper: entity chart aggregation ──

def _get_entity_counts(rows, group_by, top_n=5):
    """Top *top_n* entities by alert count.

    Returns ``(labels_list, counts_list)`` sorted descending by count.
    """
    groups = _group_alerts(rows, group_by)
    entity_counts = {k: len(v) for k, v in groups.items()}
    sorted_entities = sorted(entity_counts.items(),
                             key=lambda x: x[1], reverse=True)[:top_n]
    if not sorted_entities:
        return [], []
    labels, counts = zip(*sorted_entities)
    return list(labels), list(counts)


def apply_theme(style: ttk.Style, dark: bool):
    if dark:
        bg = "#1e1e1e"
        fg = "#ffffff"
        panel = "#252526"
        border = "#3c3c3c"
        btn_bg = "#2d2d30"
        btn_active = "#3a3a3f"
        entry_bg = "#2b2b2b"
        select_bg = "#007acc"
        heading_bg = "#2d2d30"
        heading_fg = "#ffffff"
    else:
        bg = "#f0f0f0"
        fg = "#000000"
        panel = "#ffffff"
        border = "#d0d0d0"
        btn_bg = "#f0f0f0"
        btn_active = "#e6e6e6"
        entry_bg = "#ffffff"
        select_bg = "#cce8ff"
        heading_bg = "#f0f0f0"
        heading_fg = "#000000"

    # Root background
    style.configure("App.TFrame", background=bg)
    style.configure("Panel.TFrame", background=panel)

    style.configure("App.TLabel", background=bg, foreground=fg)
    style.configure("Panel.TLabel", background=panel, foreground=fg)

    # Labelframe and its label (fixes white separators + headers)
    style.configure("App.TLabelframe", background=bg, foreground=fg, bordercolor=border)
    style.configure("App.TLabelframe.Label", background=bg, foreground=fg)

    # Separator line
    style.configure("App.TSeparator", background=border)

    # Buttons (fixes Export/Refresh text unreadable)
    style.configure("App.TButton", background=btn_bg, foreground=fg, padding=(10, 4))
    style.map("App.TButton",
              background=[("active", btn_active), ("pressed", btn_active)],
              foreground=[("disabled", "#888888")])

    # Checkbutton
    style.configure("App.TCheckbutton", background=bg, foreground=fg)

    # Combobox
    style.configure("App.TCombobox",
                    fieldbackground=entry_bg,
                    background=btn_bg,
                    foreground=fg,
                    arrowcolor=fg)
    style.map("App.TCombobox",
              fieldbackground=[("readonly", entry_bg)],
              foreground=[("readonly", fg)],
              background=[("readonly", btn_bg)])

    # Treeview (table)
    style.configure("Treeview",
                    background=panel,
                    foreground=fg,
                    fieldbackground=panel,
                    bordercolor=border,
                    rowheight=24)
    style.map("Treeview",
              background=[("selected", select_bg)],
              foreground=[("selected", "#ffffff")])

    # Treeview headings
    style.configure("Treeview.Heading",
                    background=heading_bg,
                    foreground=heading_fg)
    style.map("Treeview.Heading",
              background=[("active", heading_bg)])



def main():
    root = tk.Tk()
    style = ttk.Style(root)
    default_theme = style.theme_use()
    dark_mode = tk.BooleanVar(value=False)
    root.configure(bg="#1e1e1e" if dark_mode.get() else "#f0f0f0")
    root.title("CyberRisk Monitor")

    # Variables that we can update on Refresh
    last_analysis_var = tk.StringVar(value="Last Analysis: (not loaded yet)")
    last_loaded_var = tk.StringVar(value="Last Loaded At: (not loaded yet)")
    low_var = tk.StringVar(value="0")
    med_var = tk.StringVar(value="0")
    high_var = tk.StringVar(value="0")
    crit_var = tk.StringVar(value="0")
    score_var = tk.StringVar(value="Overall Risk Score: (not loaded yet)")

    # New filter variables
    time_window_var = tk.StringVar(value="Entire run")
    group_by_var = tk.StringVar(value="None")
    generated_at_ref = [""]  # mutable container for the run's generated_at timestamp

    root.geometry("1000x850")

    # Header Section — two rows using grid
    header_top = ttk.Frame(root, padding=(10, 10, 10, 0), style="App.TFrame")
    header_top.pack(fill=tk.X)
    header_top.columnconfigure(0, weight=1)
    header_top.columnconfigure(1, weight=0)
    header_top.columnconfigure(2, weight=1)

    title_label = ttk.Label(
        header_top, text="CyberRisk Monitor", style="App.TLabel", font=("Arial", 24, "bold")
    )
    title_label.grid(row=0, column=1)

    button_frame = ttk.Frame(header_top, style="App.TFrame")
    button_frame.grid(row=0, column=2, sticky="e")

    def _get_filtered_rows():
        """Return alerts_data rows matching current severity + time-window filters."""
        selected = severity_var.get()
        tw = time_window_var.get()
        rows = _filter_by_time_window(alerts_data, tw, generated_at_ref[0])
        return [row for row in rows
                if selected == "All" or row[1] == selected]

    def _build_txt_report(data):
        """Build a human-readable text summary from the run dict."""
        summary = data.get("summary", {})
        generated_at = data.get("generated_at", "N/A")
        risk_level = summary.get("risk_level", "N/A")
        total_score = summary.get("total_score", "N/A")
        detections_count = data.get("detections_count", len(alerts_data))

        # Severity counts from current alerts_data
        counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
        for _, sev, _, _ in alerts_data:
            if sev in counts:
                counts[sev] += 1

        filtered = _get_filtered_rows()

        # Chart summary for selected category
        cat = category_var.get()
        cat_counts = _get_chart_counts(cat)

        lines = [
            "=" * 60,
            "CYBERRISK MONITOR - EXPORT REPORT",
            "=" * 60,
            f"Generated: {generated_at}",
            f"Risk Level: {risk_level}",
            f"Total Score: {total_score}",
            f"Total Detections: {detections_count}",
            "",
            "Severity Counts (All):",
            f"  Low:      {counts['Low']}",
            f"  Medium:   {counts['Medium']}",
            f"  High:     {counts['High']}",
            f"  Critical: {counts['Critical']}",
            "",
            f"Chart Severity Counts (Category: {cat}):",
            f"  Low:      {cat_counts['Low']}",
            f"  Medium:   {cat_counts['Medium']}",
            f"  High:     {cat_counts['High']}",
            f"  Critical: {cat_counts['Critical']}",
            "",
            "-" * 60,
            f"Top Alerts (showing up to 10, filter: {severity_var.get()}):",
            "-" * 60,
        ]
        for i, (name, sev, source, ts) in enumerate(filtered[:10], 1):
            lines.append(f"  {i:>2}. [{sev}] {name} | Source: {source} | {ts}")
        if not filtered:
            lines.append("  (no alerts match current filter)")
        lines.append("")
        lines.append("=" * 60)
        return "\n".join(lines)

    def _render_chart_png():
        """Render the current matplotlib chart to an in-memory PNG."""
        buf = io.BytesIO()
        fig.savefig(buf, format="png", facecolor=fig.get_facecolor(), bbox_inches="tight")
        buf.seek(0)
        return buf

    def _export_pdf(dest, data):
        """Export an analyst-ready PDF report with four sections:
        1) Executive Summary  2) Detection Breakdown
        3) Charts             4) Analyst Notes & Status
        """
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.utils import ImageReader
            from reportlab.pdfgen import canvas
        except ImportError:
            messagebox.showwarning(
                "reportlab Not Installed",
                "PDF export requires reportlab.\n\n"
                "Install it with:\n  python -m pip install reportlab")
            return False

        c = canvas.Canvas(str(dest), pagesize=letter)
        width, height = letter
        y = height - 40
        LEFT = 40
        INDENT = 60

        # ── Helpers for clean page management ──

        def _need(space):
            nonlocal y
            if y < space:
                c.showPage()
                y = height - 40

        def _heading(text, size=12):
            nonlocal y
            _need(50)
            y -= 8
            c.setFont("Helvetica-Bold", size)
            c.drawString(LEFT, y, text)
            y -= 4
            c.setFont("Helvetica", 8)
            c.drawString(LEFT, y, "\u2500" * 85)
            y -= 14

        def _line(text, font="Helvetica", size=9, indent=LEFT):
            nonlocal y
            _need(20)
            c.setFont(font, size)
            c.drawString(indent, y, text)
            y -= 13

        def _kv(key, val, indent=INDENT):
            _line(f"{key}:  {val}", indent=indent)

        # Gather filtered data once
        filtered = _get_filtered_rows()
        row_id_map = {id(r): f"alert_{i}" for i, r in enumerate(alerts_data)}

        # ────────────────────────────────────────────────
        # Section 1 — Executive Summary
        # ────────────────────────────────────────────────
        c.setFont("Helvetica-Bold", 16)
        c.drawString(LEFT, y, "CyberRisk Monitor \u2013 Run Report")
        y -= 22

        summary = data.get("summary", {})
        generated_at = data.get("generated_at", "N/A")
        risk_level = summary.get("risk_level", "N/A")
        total_score = summary.get("total_score", "N/A")
        det_count = data.get("detections_count", len(alerts_data))

        _heading("Executive Summary")
        _kv("Generated At", generated_at)
        _kv("Last Loaded At", last_loaded_var.get().replace("Last Loaded At: ", ""))
        _kv("Risk Level", risk_level)
        _kv("Total Score", str(total_score))
        _kv("Total Detections", str(det_count))
        _kv("Exported Alerts", str(len(filtered)))

        # Active filters
        y -= 6
        _line("Active Filters:", font="Helvetica-Bold", size=9)
        _kv("Severity", severity_var.get(), indent=INDENT + 10)
        _kv("Time Window", time_window_var.get(), indent=INDENT + 10)
        _kv("Group By", group_by_var.get(), indent=INDENT + 10)
        _kv("Alert Category", category_var.get(), indent=INDENT + 10)

        # ────────────────────────────────────────────────
        # Section 2 — Detection Breakdown
        # ────────────────────────────────────────────────
        _heading("Detection Breakdown")

        # Severity counts from exported rows
        sev_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
        type_counts = {}
        source_counts = {}
        for row in filtered:
            name, sev, source, _ts = row
            if sev in sev_counts:
                sev_counts[sev] += 1
            type_counts[name] = type_counts.get(name, 0) + 1
            if source and source != "N/A":
                source_counts[source] = source_counts.get(source, 0) + 1

        _line("Severity Counts:", font="Helvetica-Bold", size=9)
        for s in ["Low", "Medium", "High", "Critical"]:
            _kv(f"  {s}", str(sev_counts[s]), indent=INDENT + 10)

        y -= 6
        _line("Top 5 Alert Types:", font="Helvetica-Bold", size=9)
        top_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        if top_types:
            for name, cnt in top_types:
                _kv(f"  {name[:45]}", str(cnt), indent=INDENT + 10)
        else:
            _line("  (none)", indent=INDENT + 10)

        y -= 6
        _line("Top 5 Sources:", font="Helvetica-Bold", size=9)
        top_sources = sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        if top_sources:
            for src, cnt in top_sources:
                _kv(f"  {src}", str(cnt), indent=INDENT + 10)
        else:
            _line("  (none)", indent=INDENT + 10)

        # ────────────────────────────────────────────────
        # Section 3 — Charts
        # ────────────────────────────────────────────────
        _heading("Charts")
        chart_buf = _render_chart_png()
        img = ImageReader(chart_buf)
        chart_w, chart_h = 480, 160
        _need(chart_h + 20)
        y -= chart_h + 5
        c.drawImage(img, LEFT, y, width=chart_w, height=chart_h,
                    preserveAspectRatio=True)
        y -= 10

        # ────────────────────────────────────────────────
        # Section 4 — Analyst Notes & Status
        # ────────────────────────────────────────────────
        _heading("Analyst Notes & Status")

        has_any_notes = False
        for row in filtered:
            rid = row_id_map.get(id(row), "")
            status = triage_status.get(rid, "New")
            notes = analyst_notes.get(rid, "")

            if status == "New" and not notes:
                continue

            has_any_notes = True
            name, sev, source, ts = row
            _need(60)
            _line(f"[{sev}] {name}  |  {source}  |  {ts}",
                  font="Helvetica-Bold", size=8)
            _line(f"Status: {status}", font="Helvetica", size=8, indent=INDENT)
            if notes:
                for note_line in notes.split("\n")[:5]:
                    _line(f"  {note_line[:90]}", font="Helvetica", size=8,
                          indent=INDENT)
            y -= 4

        if not has_any_notes:
            _line("(No analyst notes were recorded.)", font="Helvetica-Oblique",
                  size=9)

        c.save()
        return True

    def export_run():
        if not RUN_PATH.exists():
            messagebox.showwarning("No Run Data",
                                   "No saved run found.\nRun the CLI analyze command first.")
            return

        raw = RUN_PATH.read_text(encoding="utf-8")
        data = json.loads(raw)
        run_id = data.get("run_id", "unknown")
        default_name = f"cyberrisk_run_{run_id}"

        dest = filedialog.asksaveasfilename(
            title="Export Run As",
            initialfile=default_name,
            defaultextension=".json",
            filetypes=[
                ("JSON files", "*.json"),
                ("CSV files", "*.csv"),
                ("Text files", "*.txt"),
                ("PDF files", "*.pdf"),
                ("All files", "*.*"),
            ],
        )
        if not dest:
            return

        dest_path = Path(dest)
        ext = dest_path.suffix.lower()

        if ext == ".json":
            dest_path.write_text(raw, encoding="utf-8")

        elif ext == ".csv":
            filtered = _get_filtered_rows()
            # Map tuple identity -> row_id for notes/status lookup
            row_id_map = {id(r): f"alert_{i}" for i, r in enumerate(alerts_data)}
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(["Alert Type", "Severity", "Source", "Timestamp",
                             "Status", "Analyst Notes"])
            for row in filtered:
                rid = row_id_map.get(id(row), "")
                status = triage_status.get(rid, "New")
                notes = analyst_notes.get(rid, "").replace("\n", " ")
                writer.writerow(list(row) + [status, notes])
            dest_path.write_text(buf.getvalue(), encoding="utf-8")

        elif ext == ".txt":
            txt = _build_txt_report(data)
            dest_path.write_text(txt, encoding="utf-8")

        elif ext == ".pdf":
            if not _export_pdf(dest_path, data):
                return

        else:
            # Fallback: export as JSON
            dest_path.write_text(raw, encoding="utf-8")

        messagebox.showinfo("Export Complete", f"Run exported to:\n{dest}")

    export_btn = tk.Button(button_frame, text="Export", relief="flat", padx=10, pady=4)
    export_btn.configure(command=export_run)
    export_btn.pack(side=tk.LEFT, padx=5)

    refresh_btn = tk.Button(button_frame, text="Refresh", relief="flat", padx=10, pady=4)
    refresh_btn.pack(side=tk.LEFT, padx=5)

    # Collect tk widgets that need explicit color updates in dark mode
    tk_buttons = [export_btn, refresh_btn]

    def _apply_tk_colors(dark):
        if dark:
            bg = "#1e1e1e"
            fg = "#ffffff"
            panel = "#252526"
            btn_bg = "#2d2d30"
            btn_active = "#3a3a3f"
            heading_bg, heading_fg = "#2d2d30", "#ffffff"
            menu_bg, menu_fg = "#2b2b2b", "#ffffff"
            muted_fg = "#888888"
        else:
            bg = "#f0f0f0"
            fg = "#000000"
            panel = "#ffffff"
            btn_bg = "#f0f0f0"
            btn_active = "#e6e6e6"
            heading_bg, heading_fg = "#f0f0f0", "#000000"
            menu_bg, menu_fg = "#ffffff", "#000000"
            muted_fg = "#666666"

        # Buttons
        for btn in tk_buttons:
            btn.configure(bg=btn_bg, fg=fg, activebackground=btn_active, activeforeground=fg)

        # Table heading row
        for lbl in heading_labels:
            lbl.configure(bg=heading_bg, fg=heading_fg)
        heading_frame.configure(bg=heading_bg)

        # Filter row
        filter_label.configure(bg=bg, fg=fg)
        severity_filter.configure(bg=menu_bg, fg=menu_fg, activebackground=btn_active,
                                  activeforeground=fg, highlightthickness=0)
        severity_filter["menu"].configure(bg=menu_bg, fg=menu_fg)

        # Time window filter
        time_window_label.configure(bg=bg, fg=fg)
        time_window_menu.configure(bg=menu_bg, fg=menu_fg, activebackground=btn_active,
                                   activeforeground=fg, highlightthickness=0)
        time_window_menu["menu"].configure(bg=menu_bg, fg=menu_fg)

        # Group by filter
        group_by_label.configure(bg=bg, fg=fg)
        group_by_menu.configure(bg=menu_bg, fg=menu_fg, activebackground=btn_active,
                                activeforeground=fg, highlightthickness=0)
        group_by_menu["menu"].configure(bg=menu_bg, fg=menu_fg)

        # Guidance note
        guidance_label.configure(bg=bg, fg=muted_fg)

        # Risk summary count blocks (big numbers keep their severity color)
        for num_lbl, sev_color in count_number_labels:
            num_lbl.configure(bg=panel)
        for title_lbl in count_title_labels:
            title_lbl.configure(bg=panel, fg=fg)

        # Overall Risk Score label
        score_label.configure(bg=panel, fg=fg)

        # Chart filter row
        chart_view_label.configure(bg=bg, fg=fg)
        chart_view_menu.configure(bg=menu_bg, fg=menu_fg, activebackground=btn_active,
                                  activeforeground=fg, highlightthickness=0)
        chart_view_menu["menu"].configure(bg=menu_bg, fg=menu_fg)
        chart_type_label.configure(bg=bg, fg=fg)
        chart_type_menu.configure(bg=menu_bg, fg=menu_fg, activebackground=btn_active,
                                  activeforeground=fg, highlightthickness=0)
        chart_type_menu["menu"].configure(bg=menu_bg, fg=menu_fg)
        chart_filter_label.configure(bg=bg, fg=fg)
        category_menu.configure(bg=menu_bg, fg=menu_fg, activebackground=btn_active,
                                activeforeground=fg, highlightthickness=0)
        category_menu["menu"].configure(bg=menu_bg, fg=menu_fg)


    def toggle_dark_mode():
        dark = dark_mode.get()
        if dark:
            style.theme_use("clam")
        else:
            style.theme_use(default_theme)
        apply_theme(style, dark)
        root.configure(bg="#1e1e1e" if dark else "#f0f0f0")
        _apply_tk_colors(dark)
        apply_tree_theme(dark)
        update_chart()

    dark_btn = ttk.Checkbutton(
        button_frame,
        text="Dark Mode",
        style="App.TCheckbutton",
        variable=dark_mode,
        command=toggle_dark_mode
    )
    dark_btn.pack(side=tk.LEFT, padx=5)

    header_bottom = ttk.Frame(root, padding=(10, 2, 10, 5), style="App.TFrame")
    header_bottom.pack(fill=tk.X)
    header_bottom.columnconfigure(0, weight=1)
    header_bottom.columnconfigure(1, weight=1)

    timestamp_label = ttk.Label(header_bottom, textvariable=last_analysis_var, style="App.TLabel", font=("Arial", 10))
    timestamp_label.grid(row=0, column=0, sticky="w")

    loaded_label = ttk.Label(header_bottom, textvariable=last_loaded_var, style="App.TLabel", font=("Arial", 10))
    loaded_label.grid(row=0, column=1, sticky="e")

    ttk.Separator(root, orient=tk.HORIZONTAL, style="App.TSeparator").pack(fill=tk.X, pady=10)

    # Risk Summary Section
    summary_frame = ttk.LabelFrame(root, text="Risk Summary", padding="10", style="App.TLabelframe")
    summary_frame.pack(fill=tk.X, padx=10, pady=5)

    counts_frame = ttk.Frame(summary_frame, style="App.TFrame")
    counts_frame.pack(fill=tk.X)

    count_number_labels = []  # track the big number tk.Labels for theme updates
    count_title_labels = []   # track the title tk.Labels for theme updates

    def make_count_block(parent, title, var, color):
        frame = ttk.Frame(parent, style="App.TFrame")
        frame.pack(side=tk.LEFT, expand=True, padx=20)
        title_lbl = tk.Label(frame, text=title, font=("Arial", 12))
        title_lbl.pack()
        count_title_labels.append(title_lbl)
        num_lbl = tk.Label(frame, textvariable=var, font=("Arial", 24, "bold"), fg=color)
        num_lbl.pack()
        count_number_labels.append((num_lbl, color))

    make_count_block(counts_frame, "Low", low_var, "green")
    make_count_block(counts_frame, "Medium", med_var, "orange")
    make_count_block(counts_frame, "High", high_var, "red")
    make_count_block(counts_frame, "Critical", crit_var, "darkred")

    score_label = tk.Label(summary_frame, textvariable=score_var, font=("Arial", 14, "bold"))
    score_label.pack(pady=10)

    ttk.Separator(root, orient=tk.HORIZONTAL, style="App.TSeparator").pack(fill=tk.X, pady=10)

    # ── Charts Section ──
    charts_frame = ttk.LabelFrame(root, text="Severity Chart", padding="10", style="App.TLabelframe")
    charts_frame.pack(fill=tk.X, padx=10, pady=5)

    # Filter row: Chart View + Chart Type + Alert Category
    chart_filter_frame = ttk.Frame(charts_frame, style="App.TFrame")
    chart_filter_frame.pack(fill=tk.X, pady=(0, 5))

    chart_view_label = tk.Label(chart_filter_frame, text="Chart View:")
    chart_view_label.pack(side=tk.LEFT)
    chart_view_var = tk.StringVar(value="Single")
    chart_view_menu = tk.OptionMenu(chart_filter_frame, chart_view_var, "Single", "All")
    chart_view_menu.config(width=8)
    chart_view_menu.pack(side=tk.LEFT, padx=(5, 20))

    chart_type_label = tk.Label(chart_filter_frame, text="Chart Type:")
    chart_type_label.pack(side=tk.LEFT)
    chart_type_var = tk.StringVar(value="Bar")
    chart_type_menu = tk.OptionMenu(chart_filter_frame, chart_type_var, "Bar", "Line", "Pie")
    chart_type_menu.config(width=8)
    chart_type_menu.pack(side=tk.LEFT, padx=(5, 20))

    chart_filter_label = tk.Label(chart_filter_frame, text="Alert Category:")
    chart_filter_label.pack(side=tk.LEFT)
    category_var = tk.StringVar(value="All")
    category_menu = tk.OptionMenu(chart_filter_frame, category_var, "All")
    category_menu.config(width=25)
    category_menu.pack(side=tk.LEFT, padx=10)

    # Single Matplotlib figure + canvas (axes rebuilt dynamically)
    fig = plt.Figure(figsize=(8, 2.6), dpi=90)
    chart_canvas = FigureCanvasTkAgg(fig, master=charts_frame)
    chart_canvas.get_tk_widget().pack(fill=tk.X, expand=True)

    BAR_COLORS = {"Low": "#4caf50", "Medium": "#ff9800", "High": "#f44336", "Critical": "#b71c1c"}
    SEV_ORDER = ["Low", "Medium", "High", "Critical"]
    ENTITY_COLORS = ["#007acc", "#4caf50", "#ff9800", "#e91e63", "#9c27b0",
                     "#00bcd4", "#ff5722", "#795548"]
    ENTITY_CHART_TITLES = {
        "Source IP": "Top Source IPs",
        "User": "Top Users",
        "Rule": "Top Rules Triggered",
    }

    def _get_chart_counts(category="All"):
        """Compute severity counts, optionally filtered by category and time window."""
        tw = time_window_var.get()
        filtered = _filter_by_time_window(alerts_data, tw, generated_at_ref[0])
        counts = {s: 0 for s in SEV_ORDER}
        for name, sev, _, _ in filtered:
            if sev in counts and (category == "All" or name == category):
                counts[sev] += 1
        return counts

    def _style_axis(a, dark, bg, fg):
        """Apply dark/light colors to a single axes."""
        a.set_facecolor(bg)
        a.title.set_color(fg)
        a.tick_params(colors=fg, labelsize=7)
        for spine in a.spines.values():
            spine.set_color(fg if dark else "#cccccc")
        if a.get_ylabel():
            a.yaxis.label.set_color(fg)

    # ── Severity chart drawing helpers (original) ──

    def _draw_bar(a, values, colors, cat_label, fg):
        bars = a.bar(SEV_ORDER, values, color=colors, edgecolor="none")
        for bar, v in zip(bars, values):
            if v > 0:
                a.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.3,
                       str(v), ha="center", va="bottom", fontsize=8, color=fg)
        a.set_title(f"Bar ({cat_label})", fontsize=9)
        a.set_ylabel("Count", fontsize=8)
        a.set_ylim(0, max(max(values), 1) + 2)

    def _draw_line(a, values, fg, grid_color, cat_label):
        a.plot(SEV_ORDER, values, marker="o", color="#007acc", linewidth=2, markersize=5)
        for i, v in enumerate(values):
            a.annotate(str(v), (i, v), textcoords="offset points",
                        xytext=(0, 7), ha="center", fontsize=8, color=fg)
        a.set_title(f"Line ({cat_label})", fontsize=9)
        a.set_ylabel("Count", fontsize=8)
        a.set_ylim(0, max(max(values), 1) + 2)
        a.grid(True, alpha=0.3, color=grid_color)

    def _draw_pie(a, values, colors, fg, cat_label):
        total = sum(values)
        if total == 0:
            a.text(0.5, 0.5, "No data", ha="center", va="center",
                   fontsize=11, color=fg, transform=a.transAxes)
        else:
            wedges, texts, autotexts = a.pie(
                values, labels=SEV_ORDER, colors=colors, autopct="%1.0f%%",
                startangle=90, textprops={"fontsize": 7})
            for t in texts:
                t.set_color(fg)
            for t in autotexts:
                t.set_color("#ffffff")
                t.set_fontsize(6)
        a.set_title(f"Pie ({cat_label})", fontsize=9)

    # ── Entity chart drawing helpers (new) ──

    def _draw_entity_bar(a, labels, counts, title, fg):
        """Bar chart for entity-centric view (top N entities by count)."""
        if not labels:
            a.text(0.5, 0.5, "No data", ha="center", va="center",
                   fontsize=11, color=fg, transform=a.transAxes)
            a.set_title(f"Bar — {title}", fontsize=9)
            return
        colors = [ENTITY_COLORS[i % len(ENTITY_COLORS)] for i in range(len(labels))]
        bars = a.bar(range(len(labels)), counts, color=colors, edgecolor="none")
        a.set_xticks(range(len(labels)))
        short = [l[:15] + "\u2026" if len(l) > 15 else l for l in labels]
        a.set_xticklabels(short, fontsize=7, rotation=30, ha="right")
        for bar, v in zip(bars, counts):
            if v > 0:
                a.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.3,
                       str(v), ha="center", va="bottom", fontsize=8, color=fg)
        a.set_title(f"Bar — {title}", fontsize=9)
        a.set_ylabel("Count", fontsize=8)
        a.set_ylim(0, max(max(counts), 1) + 2)

    def _draw_entity_line(a, labels, counts, title, fg, grid_color):
        """Line chart for entity-centric view."""
        if not labels:
            a.text(0.5, 0.5, "No data", ha="center", va="center",
                   fontsize=11, color=fg, transform=a.transAxes)
            a.set_title(f"Line — {title}", fontsize=9)
            return
        a.plot(range(len(labels)), counts, marker="o", color="#007acc",
               linewidth=2, markersize=5)
        a.set_xticks(range(len(labels)))
        short = [l[:15] + "\u2026" if len(l) > 15 else l for l in labels]
        a.set_xticklabels(short, fontsize=7, rotation=30, ha="right")
        for i, v in enumerate(counts):
            a.annotate(str(v), (i, v), textcoords="offset points",
                       xytext=(0, 7), ha="center", fontsize=8, color=fg)
        a.set_title(f"Line — {title}", fontsize=9)
        a.set_ylabel("Count", fontsize=8)
        a.set_ylim(0, max(max(counts), 1) + 2)
        a.grid(True, alpha=0.3, color=grid_color)

    def _draw_entity_pie(a, labels, counts, title, fg):
        """Pie chart for entity-centric view."""
        total = sum(counts) if counts else 0
        if total == 0:
            a.text(0.5, 0.5, "No data", ha="center", va="center",
                   fontsize=11, color=fg, transform=a.transAxes)
        else:
            colors = [ENTITY_COLORS[i % len(ENTITY_COLORS)] for i in range(len(labels))]
            short = [l[:12] + "\u2026" if len(l) > 12 else l for l in labels]
            wedges, texts, autotexts = a.pie(
                counts, labels=short, colors=colors, autopct="%1.0f%%",
                startangle=90, textprops={"fontsize": 7})
            for t in texts:
                t.set_color(fg)
            for t in autotexts:
                t.set_color("#ffffff")
                t.set_fontsize(6)
        a.set_title(f"Pie — {title}", fontsize=9)

    # ── Main chart update ──

    def update_chart(*_args):
        """Redraw chart(s) based on all current filter/grouping settings."""
        dark = dark_mode.get()
        bg = "#252526" if dark else "#ffffff"
        fg = "#ffffff" if dark else "#000000"
        grid_color = "#444444" if dark else "#dddddd"

        gb = group_by_var.get()
        tw = time_window_var.get()
        cat_label = category_var.get()
        view = chart_view_var.get()

        # Time-window-filtered rows
        time_filtered = _filter_by_time_window(alerts_data, tw, generated_at_ref[0])

        # Optionally filter by alert category
        if cat_label != "All":
            time_filtered = [r for r in time_filtered if r[0] == cat_label]

        fig.clear()
        fig.set_facecolor(bg)

        if gb != "None":
            # ── Entity-centric chart mode ──
            charts_frame.configure(text=f"Entity Chart \u2014 grouped by {gb}")
            entity_title = ENTITY_CHART_TITLES.get(gb, f"Top by {gb}")
            labels, entity_counts = _get_entity_counts(time_filtered, gb)

            if view == "All":
                chart_type_menu.configure(state="disabled")
                ax_bar = fig.add_subplot(1, 3, 1)
                ax_line = fig.add_subplot(1, 3, 2)
                ax_pie = fig.add_subplot(1, 3, 3)

                _draw_entity_bar(ax_bar, labels, entity_counts, entity_title, fg)
                _style_axis(ax_bar, dark, bg, fg)
                _draw_entity_line(ax_line, labels, entity_counts, entity_title, fg, grid_color)
                _style_axis(ax_line, dark, bg, fg)
                _draw_entity_pie(ax_pie, labels, entity_counts, entity_title, fg)
                _style_axis(ax_pie, dark, bg, fg)

                fig.subplots_adjust(left=0.06, right=0.96, top=0.85, bottom=0.25, wspace=0.35)
            else:
                chart_type_menu.configure(state="normal")
                chart_type = chart_type_var.get()
                a = fig.add_subplot(1, 1, 1)

                if chart_type == "Pie":
                    _draw_entity_pie(a, labels, entity_counts, entity_title, fg)
                    fig.subplots_adjust(left=0.05, right=0.75, top=0.88, bottom=0.05)
                elif chart_type == "Line":
                    _draw_entity_line(a, labels, entity_counts, entity_title, fg, grid_color)
                    fig.subplots_adjust(left=0.08, right=0.95, top=0.85, bottom=0.25)
                else:
                    _draw_entity_bar(a, labels, entity_counts, entity_title, fg)
                    fig.subplots_adjust(left=0.08, right=0.95, top=0.85, bottom=0.25)

                _style_axis(a, dark, bg, fg)
        else:
            # ── Severity-based chart mode (original behavior) ──
            charts_frame.configure(text="Severity Chart")
            sev_counts = {s: 0 for s in SEV_ORDER}
            for name, sev, _, _ in time_filtered:
                if sev in sev_counts:
                    sev_counts[sev] += 1
            values = [sev_counts[s] for s in SEV_ORDER]
            colors = [BAR_COLORS[s] for s in SEV_ORDER]

            if view == "All":
                chart_type_menu.configure(state="disabled")
                ax_bar = fig.add_subplot(1, 3, 1)
                ax_line = fig.add_subplot(1, 3, 2)
                ax_pie = fig.add_subplot(1, 3, 3)

                _draw_bar(ax_bar, values, colors, cat_label, fg)
                _style_axis(ax_bar, dark, bg, fg)
                _draw_line(ax_line, values, fg, grid_color, cat_label)
                _style_axis(ax_line, dark, bg, fg)
                _draw_pie(ax_pie, values, colors, fg, cat_label)
                _style_axis(ax_pie, dark, bg, fg)

                fig.subplots_adjust(left=0.06, right=0.96, top=0.85, bottom=0.18, wspace=0.35)
            else:
                chart_type_menu.configure(state="normal")
                chart_type = chart_type_var.get()
                a = fig.add_subplot(1, 1, 1)

                if chart_type == "Pie":
                    _draw_pie(a, values, colors, fg, cat_label)
                    fig.subplots_adjust(left=0.05, right=0.75, top=0.88, bottom=0.05)
                elif chart_type == "Line":
                    _draw_line(a, values, fg, grid_color, cat_label)
                    fig.subplots_adjust(left=0.08, right=0.95, top=0.85, bottom=0.2)
                else:
                    _draw_bar(a, values, colors, cat_label, fg)
                    fig.subplots_adjust(left=0.08, right=0.95, top=0.85, bottom=0.2)

                _style_axis(a, dark, bg, fg)

        chart_canvas.draw()

    chart_view_var.trace_add("write", update_chart)
    chart_type_var.trace_add("write", update_chart)
    category_var.trace_add("write", update_chart)

    def _update_category_menu():
        """Rebuild the category dropdown options from current alerts_data."""
        categories = sorted({row[0] for row in alerts_data})
        menu = category_menu["menu"]
        menu.delete(0, "end")
        menu.add_command(label="All", command=lambda: category_var.set("All"))
        for cat in categories:
            menu.add_command(label=cat, command=lambda c=cat: category_var.set(c))
        if category_var.get() not in ["All"] + categories:
            category_var.set("All")

    ttk.Separator(root, orient=tk.HORIZONTAL, style="App.TSeparator").pack(fill=tk.X, pady=10)

    # ── Alerts Section ──
    alerts_frame = ttk.LabelFrame(root, text="Alerts", padding="10", style="App.TLabelframe")
    alerts_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    # Guidance note — informational hint for users
    guidance_label = tk.Label(
        alerts_frame,
        text="Select an alert row to view more details.",
        font=("Arial", 9, "italic"),
        fg="#666666",  # muted gray; dark-mode color applied via _apply_tk_colors
    )
    guidance_label.pack(anchor="w", pady=(0, 4))

    # Filter row
    filter_frame = ttk.Frame(alerts_frame, style="App.TFrame")
    filter_frame.pack(fill=tk.X, pady=(0, 10))

    filter_label = tk.Label(filter_frame, text="Filter by Severity:")
    filter_label.pack(side=tk.LEFT)
    severity_var = tk.StringVar(value="All")
    severity_filter = tk.OptionMenu(
        filter_frame, severity_var,
        "All", "Low", "Medium", "High", "Critical",
    )
    severity_filter.config(width=12)
    severity_filter.pack(side=tk.LEFT, padx=10)

    # Time Window dropdown
    time_window_label = tk.Label(filter_frame, text="Time Window:")
    time_window_label.pack(side=tk.LEFT, padx=(10, 0))
    time_window_menu = tk.OptionMenu(
        filter_frame, time_window_var,
        "Entire run", "Last hour", "Last 5 minutes",
    )
    time_window_menu.config(width=14)
    time_window_menu.pack(side=tk.LEFT, padx=10)

    # Group Alerts By dropdown
    group_by_label = tk.Label(filter_frame, text="Group Alerts By:")
    group_by_label.pack(side=tk.LEFT, padx=(10, 0))
    group_by_menu = tk.OptionMenu(
        filter_frame, group_by_var,
        "None", "Source IP", "User", "Rule",
    )
    group_by_menu.config(width=12)
    group_by_menu.pack(side=tk.LEFT, padx=10)

    # Custom header row (tk.Labels so dark-mode colors always apply)
    heading_frame = tk.Frame(alerts_frame)
    heading_frame.pack(fill=tk.X)
    heading_labels = []
    for text, w in [("", 40), ("Alert Type", 200), ("Severity", 100), ("Source IP", 150), ("Timestamp", 150)]:
        lbl = tk.Label(heading_frame, text=text, font=("Arial", 10, "bold"),
                       anchor="w", width=w // 7, padx=4, pady=2)
        lbl.pack(side=tk.LEFT, fill=tk.X, expand=(text == "Alert Type"))
        heading_labels.append(lbl)

    # Container frame for Treeview + scrollbar (colors the empty area behind rows)
    tree_container = tk.Frame(alerts_frame)
    tree_container.pack(fill=tk.BOTH, expand=True)

    # Alerts table (headings hidden — we draw our own above)
    columns = ("level", "alert_type", "severity", "source_ip", "timestamp")
    tree = ttk.Treeview(tree_container, columns=columns, show="", height=10)

    tree.column("level", width=40, anchor="center")
    tree.column("alert_type", width=200)
    tree.column("severity", width=100)
    tree.column("source_ip", width=150)
    tree.column("timestamp", width=150)

    alerts_data = []  # list of tuples: (Alert Type, Severity, Source IP, Timestamp)
    alert_details_map = {}  # row_id -> {rule_name, severity, source, timestamp, raw_detection, parsed}

    # In-memory SOC workflow state (keyed by row_id, e.g. "alert_0")
    analyst_notes = {}   # row_id -> str
    triage_status = {}   # row_id -> str ("New", "Investigating", ...)

    SEV_TAG_MAP = {"Low": "sev_low", "Medium": "sev_medium",
                   "High": "sev_high", "Critical": "sev_critical"}

    def refresh_alerts(*_args):
        """Rebuild the alerts table respecting severity, time-window, and grouping filters.

        Also updates the Risk Summary severity counts to reflect the
        current time-window filter.
        """
        tree.delete(*tree.get_children())
        selected = severity_var.get()
        tw = time_window_var.get()
        gb = group_by_var.get()

        # Phase 1 — time-window filter (keeps original indices for detail lookup)
        now = datetime.now(timezone.utc)
        cutoff = None
        if tw == "Last 5 minutes":
            cutoff = now - timedelta(minutes=5)
        elif tw == "Last hour":
            cutoff = now - timedelta(hours=1)

        time_filtered = []  # list of (original_idx, row)
        for idx, row in enumerate(alerts_data):
            if cutoff is not None:
                ts = _parse_timestamp(row[3]) or _parse_timestamp(generated_at_ref[0])
                if ts is None:
                    continue
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if ts < cutoff:
                    continue
            time_filtered.append((idx, row))

        # Update Risk Summary counts from time-filtered data
        counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
        for _, row in time_filtered:
            if row[1] in counts:
                counts[row[1]] += 1
        low_var.set(str(counts["Low"]))
        med_var.set(str(counts["Medium"]))
        high_var.set(str(counts["High"]))
        crit_var.set(str(counts["Critical"]))

        # Phase 2 — severity filter
        sev_filtered = [(idx, row) for idx, row in time_filtered
                        if selected == "All" or row[1] == selected]

        # Phase 3 — display (flat or grouped)
        if gb == "None":
            for idx, row in sev_filtered:
                tag = SEV_TAG_MAP.get(row[1], "sev_low")
                row_id = f"alert_{idx}"
                tree.insert("", tk.END, iid=row_id,
                            values=("\u25a0",) + row, tags=(tag,))
        else:
            # Group rows by selected entity
            groups = {}
            for idx, row in sev_filtered:
                if gb in ("Source IP", "User"):
                    key = row[2]
                elif gb == "Rule":
                    key = row[0]
                else:
                    key = "All"
                groups.setdefault(key, []).append((idx, row))

            for g_idx, group_key in enumerate(sorted(groups.keys())):
                group_rows = groups[group_key]
                count = len(group_rows)
                group_id = f"grp_{g_idx}"
                tree.insert("", tk.END, iid=group_id,
                            values=("\u25bc", f"{group_key} ({count})", "", "", ""),
                            tags=("group_header",))
                for idx, row in group_rows:
                    tag = SEV_TAG_MAP.get(row[1], "sev_low")
                    row_id = f"alert_{idx}"
                    tree.insert("", tk.END, iid=row_id,
                                values=("  \u25a0",) + row, tags=(tag,))

    severity_var.trace_add("write", refresh_alerts)

    # Time-window and group-by changes update both the table and chart
    def _on_filter_change(*_args):
        refresh_alerts()
        update_chart()

    time_window_var.trace_add("write", _on_filter_change)
    group_by_var.trace_add("write", _on_filter_change)

    # Scrollbar helper — swaps between ttk (light) and tk (dark)
    scrollbar = [None]  # mutable container so nested functions can reassign

    def _rebuild_scrollbar(dark):
        if scrollbar[0] is not None:
            scrollbar[0].pack_forget()
            scrollbar[0].destroy()
        if dark:
            # Under clam theme, ttk.Scrollbar honors style colors
            scrollbar[0] = ttk.Scrollbar(
                tree_container, orient="vertical", command=tree.yview,
                style="Dark.Vertical.TScrollbar")
        else:
            scrollbar[0] = ttk.Scrollbar(
                tree_container, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar[0].set)
        scrollbar[0].pack(side=tk.RIGHT, fill=tk.Y)

    def apply_tree_theme(dark):
        if dark:
            panel, fg, select_bg = "#252526", "#ffffff", "#007acc"
            btn_bg, bg_color, arrow_fg = "#2d2d30", "#1e1e1e", "#ffffff"
        else:
            panel, fg, select_bg = "#ffffff", "#000000", "#cce8ff"
            btn_bg, bg_color, arrow_fg = "#f0f0f0", "#f0f0f0", "#000000"

        # Named Treeview styles
        style.configure("Dark.Treeview",
                        background=panel, fieldbackground=panel,
                        foreground=fg, rowheight=24)
        style.map("Dark.Treeview",
                  background=[("selected", select_bg)],
                  foreground=[("selected", "#ffffff")])

        style.configure("Light.Treeview",
                        background=panel, fieldbackground=panel,
                        foreground=fg, rowheight=24)
        style.map("Light.Treeview",
                  background=[("selected", select_bg)],
                  foreground=[("selected", "#ffffff")])

        # Named scrollbar style for dark mode (clam theme honors these)
        style.configure("Dark.Vertical.TScrollbar",
                        background=btn_bg, troughcolor=bg_color, arrowcolor=arrow_fg)

        # Apply the correct Treeview style
        tree_style = "Dark.Treeview" if dark else "Light.Treeview"
        tree.configure(style=tree_style)

        # Severity indicator — foreground-only (no row background coloring)
        tree.tag_configure("sev_low",      foreground="#4caf50")
        tree.tag_configure("sev_medium",   foreground="#ff9800")
        tree.tag_configure("sev_high",     foreground="#f44336")
        tree.tag_configure("sev_critical", foreground="#b71c1c" if not dark else "#ff5252")

        # Group header styling
        header_fg = "#aaaaaa" if dark else "#555555"
        tree.tag_configure("group_header", foreground=header_fg,
                           font=("Arial", 10, "bold"))

        # Container frame behind the Treeview
        tree_container.configure(bg=panel)

        # Rebuild scrollbar for the current mode
        _rebuild_scrollbar(dark)

    # Initial build (use current checkbox state)
    tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    apply_tree_theme(dark_mode.get())

    def open_drill_down(event):
        """Open a detail window for the selected alert row."""
        sel = tree.selection()
        if not sel:
            return
        row_id = sel[0]
        # Skip group header rows
        details = alert_details_map.get(row_id)
        if not details:
            return

        dark = dark_mode.get()
        bg = "#1e1e1e" if dark else "#f0f0f0"
        fg = "#ffffff" if dark else "#000000"
        panel = "#252526" if dark else "#ffffff"
        border = "#3c3c3c" if dark else "#d0d0d0"
        btn_bg = "#2d2d30" if dark else "#e0e0e0"
        btn_active = "#3a3a3f" if dark else "#cccccc"
        menu_bg = "#2b2b2b" if dark else "#ffffff"

        win = tk.Toplevel(root)
        win.title("Alert Details")
        win.geometry("600x660")
        win.configure(bg=bg)
        win.resizable(False, True)

        # Close on Escape
        win.bind("<Escape>", lambda e: _on_close())

        # ── Detail fields ──
        detail_frame = tk.Frame(win, bg=panel, bd=1, relief="solid",
                                highlightbackground=border, highlightthickness=1)
        detail_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(15, 5))

        fields = [
            ("Alert Type", details["rule_name"]),
            ("Severity", details["severity"]),
            ("Source", details["source"]),
            ("Timestamp", details["timestamp"]),
        ]

        for label_text, value in fields:
            row = tk.Frame(detail_frame, bg=panel)
            row.pack(fill=tk.X, padx=10, pady=4)
            tk.Label(row, text=f"{label_text}:", font=("Arial", 10, "bold"),
                     bg=panel, fg=fg, width=12, anchor="w").pack(side=tk.LEFT)
            tk.Label(row, text=value, font=("Arial", 10),
                     bg=panel, fg=fg, anchor="w").pack(side=tk.LEFT, fill=tk.X)

        # ── Raw detection with syntax highlighting ──
        raw_frame = tk.Frame(detail_frame, bg=panel)
        raw_frame.pack(fill=tk.X, padx=10, pady=(8, 4))
        tk.Label(raw_frame, text="Raw Detection:", font=("Arial", 10, "bold"),
                 bg=panel, fg=fg, anchor="w").pack(anchor="w")

        raw_bg = "#2b2b2b" if dark else "#fafafa"
        raw_text = tk.Text(raw_frame, height=3, wrap="word", font=("Consolas", 9),
                           bg=raw_bg, fg=fg, relief="flat", bd=0)
        raw_str = details["raw_detection"]
        raw_text.insert("1.0", raw_str)

        # Configure highlight tags
        sev = details["severity"]
        sev_hl_colors = {
            "Low": "#4caf50", "Medium": "#ff9800", "High": "#f44336",
            "Critical": "#ff5252" if dark else "#b71c1c",
        }
        source_hl = "#00e5ff" if dark else "#0277bd"
        rule_hl = "#ffd740" if dark else "#e65100"

        raw_text.tag_configure("hl_sev", foreground=sev_hl_colors.get(sev, fg),
                               font=("Consolas", 9, "bold"))
        raw_text.tag_configure("hl_source", foreground=source_hl,
                               font=("Consolas", 9, "bold"))
        raw_text.tag_configure("hl_rule", foreground=rule_hl,
                               font=("Consolas", 9, "bold"))

        # Apply severity tag highlight  e.g. "[Critical]"
        sev_match = re.search(r'\[' + re.escape(sev) + r'\]', raw_str)
        if sev_match:
            raw_text.tag_add("hl_sev", f"1.{sev_match.start()}", f"1.{sev_match.end()}")

        # Apply source highlight (IP or username after "from ")
        source_val = details["source"]
        if source_val and source_val != "N/A":
            for m in re.finditer(re.escape(source_val), raw_str):
                raw_text.tag_add("hl_source", f"1.{m.start()}", f"1.{m.end()}")

        # Apply rule name highlight (first occurrence after severity tag)
        rule_name = details["rule_name"]
        if rule_name:
            rule_pos = raw_str.find(rule_name)
            if rule_pos >= 0:
                raw_text.tag_add("hl_rule", f"1.{rule_pos}",
                                 f"1.{rule_pos + len(rule_name)}")

        raw_text.configure(state="disabled")
        raw_text.pack(fill=tk.X, pady=(2, 0))

        # ── Copy buttons ──
        copy_frame = tk.Frame(detail_frame, bg=panel)
        copy_frame.pack(fill=tk.X, padx=10, pady=(4, 4))

        def _copy_to_clipboard(text, button, original_label):
            """Copy *text* to clipboard and briefly flash the button label."""
            root.clipboard_clear()
            root.clipboard_append(text)
            button.configure(text="Copied!")
            button.after(1500, lambda: button.configure(text=original_label))

        copy_raw_btn = tk.Button(
            copy_frame, text="Copy Raw Detection",
            bg=btn_bg, fg=fg, activebackground=btn_active, activeforeground=fg,
            relief="flat", padx=8, pady=2, font=("Arial", 9))
        copy_raw_btn.configure(command=lambda: _copy_to_clipboard(
            details["raw_detection"], copy_raw_btn, "Copy Raw Detection"))
        copy_raw_btn.pack(side=tk.LEFT, padx=(0, 10))

        copy_src_btn = tk.Button(
            copy_frame, text="Copy Source IP",
            bg=btn_bg, fg=fg, activebackground=btn_active, activeforeground=fg,
            relief="flat", padx=8, pady=2, font=("Arial", 9))
        copy_src_btn.configure(command=lambda: _copy_to_clipboard(
            details["source"], copy_src_btn, "Copy Source IP"))
        copy_src_btn.pack(side=tk.LEFT)

        # ── Evidence (parsed pieces) ──
        evidence_frame = tk.LabelFrame(detail_frame, text="Evidence (parsed)",
                                       bg=panel, fg=fg, font=("Arial", 9, "bold"),
                                       bd=1, relief="groove")
        evidence_frame.pack(fill=tk.X, padx=10, pady=(8, 4))

        parsed = details["parsed"]
        for key, val in parsed.items():
            ev_row = tk.Frame(evidence_frame, bg=panel)
            ev_row.pack(fill=tk.X, padx=8, pady=2)
            tk.Label(ev_row, text=f"{key}:", font=("Consolas", 9),
                     bg=panel, fg="#888888" if dark else "#666666",
                     width=18, anchor="w").pack(side=tk.LEFT)
            tk.Label(ev_row, text=val, font=("Consolas", 9),
                     bg=panel, fg=fg, anchor="w").pack(side=tk.LEFT)

        # ── Triage Status dropdown ──
        status_frame = tk.Frame(detail_frame, bg=panel)
        status_frame.pack(fill=tk.X, padx=10, pady=(8, 4))
        tk.Label(status_frame, text="Status:", font=("Arial", 10, "bold"),
                 bg=panel, fg=fg, width=12, anchor="w").pack(side=tk.LEFT)

        current_status = triage_status.get(row_id, "New")
        status_var = tk.StringVar(value=current_status)

        def _on_status_change(*_):
            triage_status[row_id] = status_var.get()

        status_var.trace_add("write", _on_status_change)
        status_menu = tk.OptionMenu(
            status_frame, status_var,
            "New", "Investigating", "Closed (Benign)", "Closed (True Positive)")
        status_menu.configure(bg=menu_bg, fg=fg, activebackground=btn_active,
                              activeforeground=fg, highlightthickness=0, width=22)
        status_menu["menu"].configure(bg=menu_bg, fg=fg)
        status_menu.pack(side=tk.LEFT, padx=5)

        # ── Analyst Notes ──
        notes_frame = tk.LabelFrame(detail_frame, text="Analyst Notes",
                                    bg=panel, fg=fg, font=("Arial", 9, "bold"),
                                    bd=1, relief="groove")
        notes_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(8, 10))

        notes_text = tk.Text(notes_frame, height=4, wrap="word",
                             font=("Consolas", 9),
                             bg="#2b2b2b" if dark else "#fafafa", fg=fg,
                             relief="flat", bd=0, insertbackground=fg)
        existing_notes = analyst_notes.get(row_id, "")
        if existing_notes:
            notes_text.insert("1.0", existing_notes)
        notes_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        def _save_notes(*_):
            analyst_notes[row_id] = notes_text.get("1.0", "end-1c")

        notes_text.bind("<FocusOut>", _save_notes)

        # Save notes + close
        def _on_close():
            _save_notes()
            win.destroy()

        win.protocol("WM_DELETE_WINDOW", _on_close)

        # ── Close button ──
        close_btn = tk.Button(win, text="Close", command=_on_close,
                              bg=btn_bg, fg=fg, activebackground=btn_active,
                              activeforeground=fg, relief="flat", padx=20, pady=4,
                              font=("Arial", 10))
        close_btn.pack(pady=(5, 15))

    tree.bind("<Double-1>", open_drill_down)
    tree.bind("<Return>", open_drill_down)

    def refresh_from_json():
        nonlocal alerts_data, alert_details_map
        run = load_latest_run()
        if not run:
            return

        # Header
        generated_at = run.get("generated_at", "")
        generated_at_ref[0] = generated_at
        last_analysis_var.set(f"Last Analysis: {generated_at}")
        last_loaded_var.set(f"Last Loaded At: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} (local)")

        # Summary
        summary = run.get("summary", {})
        risk_level = summary.get("risk_level", "")
        total_score = summary.get("total_score", "")
        if risk_level and total_score != "":
            score_var.set(f"Overall Risk Score: {total_score} ({risk_level})")
        else:
            score_var.set(f"Overall Risk Score: {total_score}")

        # Detections -> table rows
        detections = run.get("detections", [])
        alerts_data = []
        alert_details_map = {}
        for idx, det in enumerate(detections):
            severity = "Unknown"
            rule_name = det
            source = "N/A"

            # Parse severity from brackets
            if det.startswith("["):
                end = det.find("]")
                if end != -1:
                    severity = det[1:end]
                    rule_name = det[end + 2:]  # skip "] "

            # Extract rule name (text before first colon)
            colon = rule_name.find(":")
            if colon != -1:
                rule_name = rule_name[:colon].strip()

            # Extract source from "from <source> in"
            if " from " in det:
                after_from = det.split(" from ", 1)[1]
                source = after_from.split(" in ")[0].strip()

            alerts_data.append((rule_name, severity, source, generated_at))

            alert_details_map[f"alert_{idx}"] = {
                "rule_name": rule_name,
                "severity": severity,
                "source": source,
                "timestamp": generated_at,
                "raw_detection": det,
                "parsed": {
                    "severity_tag": severity,
                    "rule_name": rule_name,
                    "extracted_source": source,
                },
            }

        # refresh_alerts() will update the summary counts based on the
        # current time-window filter, so we do not set them here.
        refresh_alerts()
        _update_category_menu()
        update_chart()

    # Wire Refresh button
    refresh_btn.configure(command=refresh_from_json)

    # ── Keyboard shortcuts (Ctrl+E = Export, Ctrl+R = Refresh) ──
    root.bind("<Control-e>", lambda e: export_run())
    root.bind("<Control-E>", lambda e: export_run())
    root.bind("<Control-r>", lambda e: refresh_from_json())
    root.bind("<Control-R>", lambda e: refresh_from_json())

    # Load once at startup (optional)
    refresh_from_json()

    apply_theme(style, dark_mode.get())
    _apply_tk_colors(dark_mode.get())
    root.mainloop()


if __name__ == "__main__":
    main()
