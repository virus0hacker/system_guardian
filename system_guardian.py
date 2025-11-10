#!/usr/bin/env python3
# =====================================================
#  ml-ftt System Guardian (GUI Edition)
#  Author: ml-ftt (© 2025)
#  Description:
#     Real-time system process monitor & analyzer.
#     Detects suspicious or high-risk processes using
#     heuristic analysis and provides GUI control.
# =====================================================

import psutil
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading, time, json, csv
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# ---------------- Helper: Process Risk Classifier ----------------

def classify_process(proc):
    """Heuristic risk analysis for a process."""
    try:
        cpu = proc.cpu_percent() / max(1, psutil.cpu_count())
        mem = proc.memory_percent()
        name = proc.name().lower()
        score = 0
        if cpu > 50 or mem > 30:
            score += 2
        if any(x in name for x in ["miner", "keylog", "stealer", "spy", "hack", "rat"]):
            score += 3
        if "temp" in proc.exe().lower() or "appdata" in proc.exe().lower():
            score += 1

        if score >= 4:
            return "Dangerous", "red"
        elif score >= 2:
            return "Suspicious", "orange"
        else:
            return "Safe", "green"
    except Exception:
        return "Unknown", "gray"

# ---------------- GUI Class ----------------

class SystemGuardianApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ml-ftt System Guardian — Real-time Process Monitor")
        self.root.geometry("1200x750")
        self.root.configure(bg="#04140a")

        self.running = False
        self.process_data = []

        self._build_ui()

    def _build_ui(self):
        # ===== Banner Section =====
        banner_frame = tk.Frame(self.root, bg="#052d12", pady=10)
        banner_frame.pack(fill=tk.X)
        banner_text = """
     _______.____    ____  _______.___________. _______ .___  ___.      _______  __    __       ___      .______       _______   __       ___      .__   __. 
    /       |\   \  /   / /       |           ||   ____||   \/   |     /  _____||  |  |  |     /   \     |   _  \     |       \ |  |     /   \     |  \ |  | 
   |   (----` \   \/   / |   (----`---|  |----`|  |__   |  \  /  |    |  |  __  |  |  |  |    /  ^  \    |  |_)  |    |  .--.  ||  |    /  ^  \    |   \|  | 
    \   \      \_    _/   \   \       |  |     |   __|  |  |\/|  |    |  | |_ | |  |  |  |   /  /_\  \   |      /     |  |  |  ||  |   /  /_\  \   |  . `  | 
.----)   |       |  | .----)   |      |  |     |  |____ |  |  |  |    |  |__| | |  `--'  |  /  _____  \  |  |\  \----.|  '--'  ||  |  /  _____  \  |  |\   | 
|_______/        |__| |_______/       |__|     |_______||__|  |__|     \______|  \______/  /__/     \__\ | _| `._____||_______/ |__| /__/     \__\ |__| \__| 
                                                                                                                                                             
              ⚔️ ViRuS - HaCkEr ⚔️
   Real-Time Process Analyzer & Security Monitor
=============================================================
"""
        tk.Label(banner_frame, text=banner_text, justify="center",
                 fg="#00ff88", bg="#052d12", font=("Consolas", 10), padx=10).pack()

        # ===== Control Buttons =====
        ctrl = tk.Frame(self.root, bg="#04140a", pady=10)
        ctrl.pack(fill=tk.X)
        ttk.Button(ctrl, text="Start Monitoring", command=self.start_monitor).pack(side=tk.LEFT, padx=5)
        ttk.Button(ctrl, text="Stop", command=self.stop_monitor).pack(side=tk.LEFT, padx=5)
        ttk.Button(ctrl, text="Kill Selected", command=self.kill_selected).pack(side=tk.LEFT, padx=5)
        ttk.Button(ctrl, text="Clean Suspicious", command=self.clean_suspicious).pack(side=tk.LEFT, padx=5)
        ttk.Button(ctrl, text="Export Report", command=self.export_report).pack(side=tk.RIGHT, padx=5)

        # ===== Table for Processes =====
        columns = ("PID", "Name", "User", "CPU%", "Memory%", "Status")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings")
        for col in columns:
            self.tree.heading(col, text=col)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # ===== Graph Section =====
        graph_frame = tk.Frame(self.root, bg="#04140a")
        graph_frame.pack(fill=tk.BOTH, expand=False, padx=10, pady=10)
        fig, self.ax = plt.subplots(figsize=(6, 2), facecolor="#04140a")
        self.ax.set_facecolor("#04140a")
        self.ax.tick_params(colors="white")
        self.ax.set_title("CPU & RAM Usage", color="white")
        self.canvas = FigureCanvasTkAgg(fig, master=graph_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        self.cpu_vals, self.ram_vals = [], []

        self.status_label = tk.Label(self.root, text="Status: Idle", fg="#9cf2b0", bg="#04140a")
        self.status_label.pack(fill=tk.X, pady=5)

    # ------------- Core Monitoring Logic -------------
    def start_monitor(self):
        if self.running:
            return
        self.running = True
        self.status_label.config(text="Status: Monitoring...")
        threading.Thread(target=self.update_loop, daemon=True).start()
        threading.Thread(target=self.update_graph, daemon=True).start()

    def stop_monitor(self):
        self.running = False
        self.status_label.config(text="Status: Stopped")

    def update_loop(self):
        while self.running:
            try:
                self.refresh_table()
            except Exception:
                pass
            time.sleep(2)

    def refresh_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.process_data.clear()

        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
            try:
                status, color = classify_process(proc)
                self.tree.insert("", tk.END,
                                 values=(proc.info['pid'], proc.info['name'],
                                         proc.info.get('username', 'N/A'),
                                         f"{proc.info['cpu_percent']:.1f}",
                                         f"{proc.info['memory_percent']:.1f}", status),
                                 tags=(color,))
                self.tree.tag_configure("red", foreground="red")
                self.tree.tag_configure("orange", foreground="orange")
                self.tree.tag_configure("green", foreground="green")
                self.tree.tag_configure("gray", foreground="gray")
                self.process_data.append(proc.info | {"status": status})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def update_graph(self):
        while self.running:
            cpu = psutil.cpu_percent()
            ram = psutil.virtual_memory().percent
            self.cpu_vals.append(cpu)
            self.ram_vals.append(ram)
            if len(self.cpu_vals) > 30:
                self.cpu_vals.pop(0)
                self.ram_vals.pop(0)
            self.ax.clear()
            self.ax.plot(self.cpu_vals, label="CPU %", color="#00ff80")
            self.ax.plot(self.ram_vals, label="RAM %", color="#66ccff")
            self.ax.legend(loc="upper right", facecolor="#04140a", labelcolor="white")
            self.ax.set_ylim(0, 100)
            self.ax.set_facecolor("#04140a")
            self.ax.tick_params(colors="white")
            self.ax.set_title("CPU & RAM Usage", color="white")
            self.canvas.draw()
            time.sleep(1)

    # ------------- Actions -------------
    def kill_selected(self):
        item = self.tree.selection()
        if not item:
            messagebox.showinfo("Kill Process", "Select a process first.")
            return
        pid = int(self.tree.item(item, "values")[0])
        try:
            psutil.Process(pid).terminate()
            messagebox.showinfo("Process Terminated", f"Process {pid} terminated.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def clean_suspicious(self):
        killed = 0
        for p in self.process_data:
            if p["status"] in ["Suspicious", "Dangerous"]:
                try:
                    psutil.Process(p["pid"]).terminate()
                    killed += 1
                except Exception:
                    continue
        messagebox.showinfo("Clean System", f"Terminated {killed} suspicious processes.")

    def export_report(self):
        if not self.process_data:
            messagebox.showinfo("Export", "No data to export.")
            return
        file = filedialog.asksaveasfilename(defaultextension=".json",
                                            filetypes=[("JSON", "*.json"), ("CSV", "*.csv")])
        if not file:
            return
        if file.endswith(".json"):
            json.dump(self.process_data, open(file, "w"), indent=2)
        else:
            with open(file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["PID", "Name", "User", "CPU%", "Memory%", "Status"])
                for d in self.process_data:
                    writer.writerow([d["pid"], d["name"], d.get("username", "N/A"),
                                     d["cpu_percent"], d["memory_percent"], d["status"]])
        messagebox.showinfo("Export", f"Report saved: {file}")

# ---------------- Main ----------------
def main():
    root = tk.Tk()
    app = SystemGuardianApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
