import customtkinter as ctk

class Themes:
    @staticmethod
    def apply_light_theme():
        ctk.set_appearance_mode("light")
        ctk.set_default_color_theme("blue")
    
    @staticmethod
    def apply_dark_theme():
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
