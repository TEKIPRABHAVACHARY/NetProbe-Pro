import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import customtkinter as ctk
from ui.main_window import NetProbeWindow

if __name__ == "__main__":
    app = NetProbeWindow()
    app.mainloop()
