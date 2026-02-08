"""CyberRisk Monitor - Desktop UI"""
import csv
import io
import json
import tkinter as tk
from datetime import datetime
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
        """Return alerts_data rows that match the current severity filter."""
        selected = severity_var.get()
        return [row for row in alerts_data
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
        """Export a PDF report with text summary and embedded chart."""
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

        txt = _build_txt_report(data)
        c = canvas.Canvas(str(dest), pagesize=letter)
        width, height = letter
        y = height - 40

        # Text section
        for line in txt.split("\n"):
            if y < 250:
                c.showPage()
                y = height - 40
            c.setFont("Courier", 9)
            c.drawString(40, y, line)
            y -= 12

        # Chart image
        chart_buf = _render_chart_png()
        img = ImageReader(chart_buf)
        chart_w, chart_h = 480, 140
        if y < chart_h + 40:
            c.showPage()
            y = height - 40
        y -= chart_h + 10
        c.drawImage(img, 40, y, width=chart_w, height=chart_h, preserveAspectRatio=True)

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
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(["Alert Type", "Severity", "Source", "Timestamp"])
            writer.writerows(filtered)
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
        else:
            bg = "#f0f0f0"
            fg = "#000000"
            panel = "#ffffff"
            btn_bg = "#f0f0f0"
            btn_active = "#e6e6e6"
            heading_bg, heading_fg = "#f0f0f0", "#000000"
            menu_bg, menu_fg = "#ffffff", "#000000"

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

    def _get_chart_counts(category="All"):
        """Compute severity counts, optionally filtered by alert category."""
        counts = {s: 0 for s in SEV_ORDER}
        for name, sev, _, _ in alerts_data:
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

    def update_chart(*_args):
        """Redraw chart(s) based on Chart View, Chart Type, category, and theme."""
        dark = dark_mode.get()
        bg = "#252526" if dark else "#ffffff"
        fg = "#ffffff" if dark else "#000000"
        grid_color = "#444444" if dark else "#dddddd"

        counts = _get_chart_counts(category_var.get())
        values = [counts[s] for s in SEV_ORDER]
        colors = [BAR_COLORS[s] for s in SEV_ORDER]
        cat_label = category_var.get()
        view = chart_view_var.get()

        fig.clear()
        fig.set_facecolor(bg)

        if view == "All":
            # Disable Chart Type dropdown in All mode
            chart_type_menu.configure(state="disabled")

            # 1 row x 3 columns
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
            # Single view — re-enable Chart Type dropdown
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

    # Alerts Section
    alerts_frame = ttk.LabelFrame(root, text="Alerts", padding="10", style="App.TLabelframe")
    alerts_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

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

    SEV_TAG_MAP = {"Low": "sev_low", "Medium": "sev_medium",
                   "High": "sev_high", "Critical": "sev_critical"}

    def refresh_alerts(*_args):
        tree.delete(*tree.get_children())
        selected = severity_var.get()
        for row in alerts_data:
            if selected == "All" or row[1] == selected:
                tag = SEV_TAG_MAP.get(row[1], "sev_low")
                # Prepend block character as the "level" column
                tree.insert("", tk.END, values=("\u25a0",) + row, tags=(tag,))

    severity_var.trace_add("write", refresh_alerts)

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

        # Container frame behind the Treeview
        tree_container.configure(bg=panel)

        # Rebuild scrollbar for the current mode
        _rebuild_scrollbar(dark)

    # Initial build (use current checkbox state)
    tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    apply_tree_theme(dark_mode.get())

    def refresh_from_json():
        nonlocal alerts_data
        run = load_latest_run()
        if not run:
            return

        # Header
        generated_at = run.get("generated_at", "")
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
        # Each detection is a string like:
        #   "[Critical] Brute Force Login Attempt: ... events from 192.168.1.105 in 300s"
        detections = run.get("detections", [])
        alerts_data = []
        for det in detections:
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

        # Compute severity counts from parsed alerts_data
        counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
        for _, sev, _, _ in alerts_data:
            if sev in counts:
                counts[sev] += 1

        low_var.set(str(counts["Low"]))
        med_var.set(str(counts["Medium"]))
        high_var.set(str(counts["High"]))
        crit_var.set(str(counts["Critical"]))

        refresh_alerts()  # apply current filter
        _update_category_menu()
        update_chart()

    # Wire Refresh button
    refresh_btn.configure(command=refresh_from_json)

    # Load once at startup (optional)
    refresh_from_json()

    apply_theme(style, dark_mode.get())
    _apply_tk_colors(dark_mode.get())
    root.mainloop()


if __name__ == "__main__":
    main()
