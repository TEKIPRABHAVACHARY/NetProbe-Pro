import customtkinter as ctk
from tkinter import ttk

class ProgressBar(ctk.CTkFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.progress = ctk.CTkProgressBar(self, width=400)
        self.progress.pack(pady=10)
        self.label = ctk.CTkLabel(self, text="Ready")
        self.label.pack()
    
    def update_progress(self, value: float, text: str):
        self.progress.set(value)
        self.label.configure(text=text)
        self.update_idletasks()

class ResultsTable(ctk.CTkScrollableFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.tree = ttk.Treeview(self, columns=('Port', 'Status', 'Service', 'Banner'), show='headings')
        self.tree.heading('Port', text='Port')
        self.tree.heading('Status', text='Status')
        self.tree.heading('Service', text='Service')
        self.tree.heading('Banner', text='Banner')
        self.tree.column('Port', width=80)
        self.tree.column('Status', width=80)
        self.tree.column('Service', width=120)
        self.tree.column('Banner', width=300)
        self.tree.pack(fill='both', expand=True, padx=10, pady=10)
    
    def clear_results(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
    
    def add_result(self, port: int, status: str, service: str, banner: str):
        self.tree.insert('', 'end', values=(port, status, service, banner[:50] + '...'))
