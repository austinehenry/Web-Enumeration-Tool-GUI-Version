import customtkinter as ctk
from tkinter import scrolledtext
import threading
import json
import asyncio
from scanner_backend import WebScanner  # Import backend scanner

# Set UI theme
ctk.set_appearance_mode("Dark")  
ctk.set_default_color_theme("blue")

class ScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Web Scanner")
        self.root.geometry("1000x700")

        # Initialize WebScanner
        self.scanner = WebScanner()

        # Main Frame
        self.main_frame = ctk.CTkFrame(root)
        self.main_frame.pack(fill='both', expand=True, padx=20, pady=20)

        # URL Entry
        self.url_entry = ctk.CTkEntry(self.main_frame, placeholder_text="Enter target URL")
        self.url_entry.pack(fill='x', padx=10, pady=10)

        # Scan Button
        self.scan_button = ctk.CTkButton(self.main_frame, text="Start Scan", command=self.start_scan)
        self.scan_button.pack(pady=10)

        # Toggle Dark Mode
        self.toggle_mode = ctk.CTkSwitch(self.main_frame, text="Dark Mode", command=self.toggle_theme)
        self.toggle_mode.pack(pady=10)

        # Progress Bar (Initially Blank)
        self.progress = ctk.CTkProgressBar(self.main_frame)
        self.progress.pack(fill='x', padx=10, pady=10)
        self.progress.set(0)  # Ensure it's blank at the start

        # Notebook Tabs
        self.notebook = ctk.CTkTabview(self.main_frame)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)

        # Tabs with Larger Font Size
        self.tabs = {
            'Overview': self.create_scrolled_text("Overview"),
            'Security Headers': self.create_scrolled_text("Security Headers"),
            'SSL Info': self.create_scrolled_text("SSL Info"),
            'Subdomains': self.create_scrolled_text("Subdomains"),
            'Open Ports': self.create_scrolled_text("Open Ports"),
            'Risks': self.create_scrolled_text("Risks")
        }

    def create_scrolled_text(self, tab_name):
        """Create scrolled text widgets with larger font."""
        text_widget = scrolledtext.ScrolledText(self.notebook.add(tab_name), font=("Arial", 12))
        text_widget.pack(fill='both', expand=True, padx=5, pady=5)
        return text_widget

    def toggle_theme(self):
        """Toggle between Dark and Light mode."""
        mode = "Light" if ctk.get_appearance_mode() == "Dark" else "Dark"
        ctk.set_appearance_mode(mode)

    def start_scan(self):
        """Start scanning process."""
        url = self.url_entry.get()
        if not url:
            return

        # Clear previous results
        for tab in self.tabs.values():
            tab.delete(1.0, 'end')

        # Reset and start progress animation
        self.progress.set(0)  
        self.progress.start()  
        self.scan_button.configure(state='disabled')

        # Run scan in a separate thread
        thread = threading.Thread(target=self.run_scan, args=(url,))
        thread.start()

    def run_scan(self, url):
        """Perform the web scan."""
        try:
            results = asyncio.run(self.scanner.scan_target(url))

            # Update UI with scan results
            self.tabs['Overview'].insert('end', json.dumps(results, indent=2))
            self.tabs['Security Headers'].insert('end', json.dumps(results.get('security_headers', {}), indent=2))
            self.tabs['SSL Info'].insert('end', json.dumps(results.get('ssl_info', {}), indent=2))
            self.tabs['Subdomains'].insert('end', '\n'.join(results.get('subdomains', [])))
            self.tabs['Open Ports'].insert('end', '\n'.join(results.get('open_ports', [])))

            # Handle risks with icons
            risks = results.get('risks', [])
            if risks:
                risk_output = "\n".join([f"{risk} " for risk in risks])
            else:
                risk_output = "Safe to visit "
            self.tabs['Risks'].insert('end', risk_output)

        except Exception as e:
            for tab in self.tabs.values():
                tab.insert('end', f"Error during scan: {str(e)}")
        finally:
            # Stop progress animation and reset to blank
            self.progress.stop()
            self.progress.set(0)
            self.scan_button.configure(state='normal')

if __name__ == "__main__":
    root = ctk.CTk()
    app = ScannerGUI(root)
    root.mainloop()
