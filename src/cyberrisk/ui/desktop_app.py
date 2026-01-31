"""CyberRisk Monitor - Desktop UI"""
import tkinter as tk


def main():
    root = tk.Tk()
    root.title("CyberRisk Monitor")
    root.geometry("800x600")

    label = tk.Label(root, text="CyberRisk Monitor", font=("Arial", 24))
    label.pack(pady=20)

    root.mainloop()


if __name__ == "__main__":
    main()
