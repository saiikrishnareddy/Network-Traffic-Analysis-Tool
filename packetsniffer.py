#!/usr/bin/env python3
"""
Network Traffic Analyzer GUI Tool
A comprehensive GUI-based tool for analyzing network traffic and detecting security threats
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import scapy.all as scapy
from collections import Counter, defaultdict
import threading
import time
import datetime
from PIL import Image, ImageTk
import json

class NetworkTrafficAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Traffic Analyzer")
        self.root.geometry("1200x800")
        self.root.configure(bg='#2c3e50')
        
        # Initialize variables
        self.is_sniffing = False
        self.packets = []
        self.capture_thread = None
        self.interface = None
        
        # Configure styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.configure_styles()
        
        self.setup_gui()
        
    def configure_styles(self):
        """Configure custom styles for the GUI"""
        self.style.configure('Title.TLabel', 
                           background='#34495e', 
                           foreground='white', 
                           font=('Arial', 16, 'bold'))
        
        self.style.configure('Subtitle.TLabel',
                           background='#2c3e50',
                           foreground='#ecf0f1',
                           font=('Arial', 12, 'bold'))
        
        self.style.configure('Start.TButton',
                           background='#27ae60',
                           foreground='white',
                           font=('Arial', 10, 'bold'))
        
        self.style.configure('Stop.TButton',
                           background='#e74c3c',
                           foreground='white',
                           font=('Arial', 10, 'bold'))
        
        self.style.configure('TFrame',
                           background='#34495e')
        
        self.style.configure('TNotebook',
                           background='#2c3e50')
        
        self.style.configure('TNotebook.Tab',
                           background='#34495e',
                           foreground='white',
                           font=('Arial', 10))

    def setup_gui(self):
        """Set up the main GUI interface"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.grid(row=0, column=0, columnspan=2, pady=(0, 20), sticky=(tk.W, tk.E))
        
        title_label = ttk.Label(header_frame, 
                               text="🔍 Network Traffic Analyzer", 
                               style='Title.TLabel')
        title_label.pack(pady=10)
        
        subtitle_label = ttk.Label(header_frame,
                                  text="Detect and analyze network traffic patterns for security threats",
                                  style='Subtitle.TLabel')
        subtitle_label.pack()
        
        # Control panel
        control_frame = ttk.LabelFrame(main_frame, text="Capture Controls", padding="10")
        control_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))
        
        # Interface selection
        ttk.Label(control_frame, text="Network Interface:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.interface_var = tk.StringVar()
        interface_combo = ttk.Combobox(control_frame, textvariable=self.interface_var, width=20)
        interface_combo['values'] = self.get_network_interfaces()
        if interface_combo['values']:
            interface_combo.current(0)
        interface_combo.grid(row=0, column=1, pady=5, padx=(5, 0))
        
        # Capture duration
        ttk.Label(control_frame, text="Duration (seconds):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.duration_var = tk.StringVar(value="30")
        ttk.Entry(control_frame, textvariable=self.duration_var, width=10).grid(row=1, column=1, pady=5, padx=(5, 0))
        
        # Filter
        ttk.Label(control_frame, text="Filter:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.filter_var = tk.StringVar(value="tcp or udp or icmp")
        ttk.Entry(control_frame, textvariable=self.filter_var, width=20).grid(row=2, column=1, pady=5, padx=(5, 0))
        
        # Button frame
        button_frame = ttk.Frame(control_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        self.start_btn = ttk.Button(button_frame, text="Start Capture", 
                                   style='Start.TButton',
                                   command=self.start_capture)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(button_frame, text="Stop Capture", 
                                  style='Stop.TButton',
                                  command=self.stop_capture,
                                  state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Status
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(control_frame, textvariable=self.status_var).grid(row=4, column=0, columnspan=2, pady=5)
        
        # Statistics frame
        stats_frame = ttk.LabelFrame(main_frame, text="Real-time Statistics", padding="10")
        stats_frame.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Statistics labels
        stats = [
            ("Total Packets:", "total_packets"),
            ("TCP Packets:", "tcp_packets"),
            ("UDP Packets:", "udp_packets"),
            ("ICMP Packets:", "icmp_packets"),
            ("HTTP Packets:", "http_packets"),
            ("Suspicious:", "suspicious")
        ]
        
        self.stats_vars = {}
        for i, (label, key) in enumerate(stats):
            ttk.Label(stats_frame, text=label).grid(row=i, column=0, sticky=tk.W, pady=2)
            self.stats_vars[key] = tk.StringVar(value="0")
            ttk.Label(stats_frame, textvariable=self.stats_vars[key]).grid(row=i, column=1, sticky=tk.W, pady=2)
        
        # Create notebook for tabs
        notebook = ttk.Notebook(main_frame)
        notebook.grid(row=2, column=0, columnspan=2, pady=(20, 0), sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Visualization tab
        vis_frame = ttk.Frame(notebook, padding="10")
        notebook.add(vis_frame, text="Visualizations")
        
        # Create matplotlib figures
        fig = Figure(figsize=(10, 8), dpi=100)
        self.canvas = FigureCanvasTkAgg(fig, vis_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        self.ax1 = fig.add_subplot(221)
        self.ax2 = fig.add_subplot(222)
        self.ax3 = fig.add_subplot(223)
        self.ax4 = fig.add_subplot(224)
        
        fig.tight_layout(pad=3.0)
        
        # Packet details tab
        details_frame = ttk.Frame(notebook, padding="10")
        notebook.add(details_frame, text="Packet Details")
        
        # Packet list with scrollbar
        self.packet_text = scrolledtext.ScrolledText(details_frame, width=80, height=20)
        self.packet_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)

    def get_network_interfaces(self):
        """Get available network interfaces"""
        try:
            interfaces = scapy.get_if_list()
            return [iface for iface in interfaces if iface != 'lo']  # Exclude loopback
        except:
            return ['eth0', 'wlan0', 'en0']  # Fallback common interfaces

    def start_capture(self):
        """Start packet capture"""
        if self.is_sniffing:
            return
            
        interface = self.interface_var.get()
        if not interface:
            messagebox.showerror("Error", "Please select a network interface")
            return
            
        self.is_sniffing = True
        self.packets.clear()
        self.status_var.set("Capturing...")
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        
        # Start capture in separate thread
        self.capture_thread = threading.Thread(target=self.capture_packets, daemon=True)
        self.capture_thread.start()
        
        # Start analysis update in main thread
        self.update_analysis()

    def stop_capture(self):
        """Stop packet capture"""
        self.is_sniffing = False
        self.status_var.set("Capture stopped")
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

    def capture_packets(self):
        """Capture network packets"""
        try:
            scapy.sniff(
                iface=self.interface_var.get(),
                prn=self.packet_callback,
                filter=self.filter_var.get(),
                timeout=int(self.duration_var.get()),
                stop_filter=lambda x: not self.is_sniffing
            )
        except Exception as e:
            messagebox.showerror("Error", f"Capture error: {str(e)}")
            self.stop_capture()

    def packet_callback(self, packet):
        """Callback for each captured packet"""
        if self.is_sniffing:
            self.packets.append(packet)

    def update_analysis(self):
        """Update analysis and visualizations"""
        if not self.is_sniffing and not self.packets:
            return
            
        if self.packets:
            self.analyze_traffic()
            self.update_visualizations()
            self.update_packet_details()
            
        if self.is_sniffing:
            self.root.after(2000, self.update_analysis)  # Update every 2 seconds

    def analyze_traffic(self):
        """Analyze captured packets"""
        protocol_count = Counter()
        src_ips = Counter()
        suspicious_count = 0
        
        for packet in self.packets:
            # Count protocols
            if packet.haslayer(scapy.IP):
                protocol_count[packet[scapy.IP].proto] += 1
                src_ips[packet[scapy.IP].src] += 1
                
                # Simple suspicious activity detection
                if (packet.haslayer(scapy.TCP) and 
                    packet[scapy.TCP].flags == 2):  # SYN flood detection
                    suspicious_count += 1
        
        # Update statistics
        self.stats_vars['total_packets'].set(str(len(self.packets)))
        self.stats_vars['tcp_packets'].set(str(protocol_count.get(6, 0)))
        self.stats_vars['udp_packets'].set(str(protocol_count.get(17, 0)))
        self.stats_vars['icmp_packets'].set(str(protocol_count.get(1, 0)))
        self.stats_vars['suspicious'].set(str(suspicious_count))
        self.stats_vars['http_packets'].set(str(len([p for p in self.packets 
                                                   if p.haslayer(scapy.TCP) and 
                                                   (p[scapy.TCP].dport == 80 or p[scapy.TCP].sport == 80)])))

    def update_visualizations(self):
        """Update the visualization charts"""
        # Clear previous plots
        for ax in [self.ax1, self.ax2, self.ax3, self.ax4]:
            ax.clear()
        
        # Protocol distribution pie chart
        protocols = {}
        for packet in self.packets:
            if packet.haslayer(scapy.IP):
                proto = packet[scapy.IP].proto
                protocols[proto] = protocols.get(proto, 0) + 1
        
        if protocols:
            labels = {
                1: 'ICMP', 6: 'TCP', 17: 'UDP'
            }
            pie_data = {labels.get(k, f'Proto {k}'): v for k, v in protocols.items()}
            
            self.ax1.pie(pie_data.values(), labels=pie_data.keys(), autopct='%1.1f%%')
            self.ax1.set_title('Protocol Distribution')
        
        # Packet rate over time (simplified)
        if len(self.packets) > 10:
            packet_times = [i for i in range(len(self.packets))]
            self.ax2.plot(packet_times, [1]*len(packet_times), 'b-')
            self.ax2.set_title('Packet Timeline')
            self.ax2.set_xlabel('Packet Number')
            self.ax2.set_ylabel('Count')
        
        # Top source IPs
        src_ips = Counter()
        for packet in self.packets:
            if packet.haslayer(scapy.IP):
                src_ips[packet[scapy.IP].src] += 1
        
        if src_ips:
            top_ips = src_ips.most_common(5)
            self.ax3.bar([ip for ip, count in top_ips], [count for ip, count in top_ips])
            self.ax3.set_title('Top Source IPs')
            self.ax3.tick_params(axis='x', rotation=45)
        
        # Suspicious activity indicator
        suspicious = len([p for p in self.packets 
                         if p.haslayer(scapy.TCP) and p[scapy.TCP].flags == 2])
        
        self.ax4.bar(['Normal', 'Suspicious'], 
                    [len(self.packets) - suspicious, suspicious], 
                    color=['green', 'red'])
        self.ax4.set_title('Security Status')
        
        self.canvas.draw()

    def update_packet_details(self):
        """Update packet details text area"""
        self.packet_text.delete(1.0, tk.END)
        
        for i, packet in enumerate(self.packets[-50:]):  # Show last 50 packets
            self.packet_text.insert(tk.END, f"Packet {i+1}:\n")
            
            if packet.haslayer(scapy.IP):
                ip_layer = packet[scapy.IP]
                self.packet_text.insert(tk.END, f"  Source: {ip_layer.src}\n")
                self.packet_text.insert(tk.END, f"  Destination: {ip_layer.dst}\n")
                self.packet_text.insert(tk.END, f"  Protocol: {ip_layer.proto}\n")
                
                if packet.haslayer(scapy.TCP):
                    tcp_layer = packet[scapy.TCP]
                    self.packet_text.insert(tk.END, f"  TCP Sport: {tcp_layer.sport}\n")
                    self.packet_text.insert(tk.END, f"  TCP Dport: {tcp_layer.dport}\n")
                    self.packet_text.insert(tk.END, f"  Flags: {tcp_layer.flags}\n")
                
                if packet.haslayer(scapy.UDP):
                    udp_layer = packet[scapy.UDP]
                    self.packet_text.insert(tk.END, f"  UDP Sport: {udp_layer.sport}\n")
                    self.packet_text.insert(tk.END, f"  UDP Dport: {udp_layer.dport}\n")
            
            self.packet_text.insert(tk.END, "-" * 40 + "\n")

def main():
    """Main function"""
    root = tk.Tk()
    app = NetworkTrafficAnalyzer(root)
    root.mainloop()

if __name__ == "__main__":
    main()

