#!/usr/bin/env python3

import tkinter as tk
from tkinter import ttk, scrolledtext
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.animation import FuncAnimation
import pandas as pd
import numpy as np
import requests
import json
import time
import threading
from datetime import datetime, timedelta
from collections import deque, defaultdict
import logging
import argparse
import os

# for Network monitoring
import psutil
import socket

class NetworkMonitor:
    def __init__(self, controller_ip='127.0.0.1', controller_port=8080):
        self.controller_ip = controller_ip
        self.controller_port = controller_port
        self.controller_url = f'http://{controller_ip}:{controller_port}'

        self.packet_history = deque(maxlen=1000)
        self.attack_history = deque(maxxlen=500)
        self.performance_history = deque(maxlen=200)
        self.flow_stats = defaultdict(list)

        self.monitoring_active = False
        self.alert_threashold = {'high': 1000, 'medium': 500, 'low': 100}

        self.current_stats = {
            'total_packets': 0,
            'attacks_detected': 0,
            'blocked_ips': set(),
            'suspicious_ips': set(),
            'throughput_mbps': 0,
            'cpu_usage': 0,
            'memory_usage': 0,
            'active_flows': 0
        }

        self.setup_logging()

    def setup_logging(self): 
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        logging.basicConfig(level=logging.INFO, format=log_format)
        self.logger = logging.getLogger('NetworkMonitor')

        os.makedirs('logs', exist_ok=True)
        file_handler = logging.FileHandler('logs/network_monitor.log')
        file_handler.setFormatter(logging.Formatter(log_format))
        self.logger.addHandler(file_handler)

    def fetch_controller_stats(self): 
        try:
            response = requests.get(f'{self.controller_url}/stats', timeout=5)
            if response.status_code == 200: return response.json()
            else:
                self.logger.warning(f'Controller returned status {response.status_code}')
                return None
        except requests.exceptions.RequestException as e:
            self.logger.debug(f'Controller connection error: {e}')
            return None
        
    def fetch_system_stats(self):
        try:
            stats = {
                'timestamp': datetime.now(),
                'cpu_usage': psutil.cpu_percent(interval=1),
                'memory_usage': psutil.virtual_memory().percent,
                'disk_usage': psutil.disk_usage('/').percent,
                'network_io': psutil.net_io_counters(),
                'active_connections': len(psutil.net_connections())

            }

            return stats
        except Exception as e:
            self.logger.error(f'System stats error: {e}')        
            return None
        
    def update_statistics(self):
        controller_stats = self.fetch_controller_stats()
        if controller_stats:
            self.current_stats.update(controller_stats.get('performance_stats', {}))
            self.current_stats['blocked_ips'] = set(controller_stats.get('blocked_ips', []))
            self.current_stats['suspicious_ips'] = set(controller_stats.get('suspicious_ips', {}).keys())

            system_stats = self.fetch_system_stats()
            if system_stats:
                self.current_stats['cpu_usage'] = system_stats['cpu_usage']
                self.current_stats['memory_usage'] = system_stats['memory_usage']
                self.current_stats['active_connections'] = system_stats['active_connections']

                if hasattr(self, 'prev_network_io'):
                    bytes_sent = system_stats['network_io'].bytes_sent - self.prev_network_io.bytes_sent
                    bytes_recv = system_stats['network_io'].bytes_recv - self.prev_network_io.bytes_recv
                    total_bytes = bytes_sent + bytes_recv
                    self.current_stats['throughput_mbps'] = (total_bytes * 8) / (1024 * 1024) # Mbps
                
                self.prev_network_io = system_stats['network_io']
            
            timestamp = datetime.now()
            self.performance_history.append({
                'timestamp': timestamp,
                **self.current_stats.copy() # 딕셔너리 언패킹
            })

            self.check_alerts()

    def check_alerts(self):
        alerts = []

        if self.current_stats['cpu_usage'] > 80:
            alerts.append({
                'type': 'system',
                'severity': 'high',
                'message': f'High CPU usage: {self.current_stats['cpu_usage']:.1f}%',
                'timestamp': datetime.now()
            })

        if self.current_stats['memory_usage'] > 85:
            alerts.append({
                'type': 'system',
                'severity': 'high',
                'message': f'High memory usage: {self.current_stats['memory_usage']:.1f}%',
                'timestamp': datetime.now()
            })
        
        if len(self.current_stats['blocked_ips']) > 50:
            alerts.append({
                'type': 'security',
                'severity': 'medium',
                'message': f'Many blocked IPs: {len(self.current_stats['blocked_ips'])}',
                'timestamp': datetime.now()            
            })

        for alert in alerts:
            self.attack_history.append(alert)
            self.logger.warning(f'ALERT: {alert['message']}')

        return alerts
    
class NetworkMonitorGUI:
    def __init__(self, monitor):
        self.monitor = monitor
        self.root = tk.Tk()
        self.root.title('ML-SDN Defense Monitor')
        self.root.geometry('1400*900') # 1400x900
        
        self.update_interval = 2000 # 2s
        self.animation_running = False

        self.setup_gui()
        self.start_monitoring()

    def setup_gui(self): 
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)

        self.create_dashboard_tab(notebook)
        self.create_network_stats_tab(notebook)
        self.create_security_tab(notebook)
        self.create_performance_tab(notebook)
        self.create_alerts_tab(notebook)
        self.create_control_panel(main_frame)
        
    def create_dashboard_tab(self, parent):
        dashboard_frame = ttk.Frame(parent)
        parent.add(dashboard_frame, text='Dashboard')

        stats_frame = ttk.Frame(dashboard_frame)
        stats_frame.pack(fill=tk.X, pady=10)

        self.stats_labels = {}

        stats_info = [
            ('Total Packets', 'total_packets', 'blue'),
            ('Attacks Detected', 'attacks_detected', 'red'),
            ('Blocked IPs', 'blocked_ips_count', 'orange'),
            ('Throughput (Mbps)', 'throughput_mbps', 'green')
        ]

        for i, (title, key, color) in enumerate(stats_info):
            card_frame = tk.Frame(stats_frame, relief=tk.RAISED, borderwidth=2, bg='white')
            card_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)

            title_label = tk.Label(card_frame, text=title, font=('Arial', 12, 'bold'), bg='white')
            title_label.pack(pady=5)

            value_label = tk.Label(card_frame, text='0', font=('Arial', 20, 'bold'), fg=color, bg='white')
            value_label.pack(pady=5)

            self.stats_labels[key] = value_label

        charts_frame = ttk.Frame(dashboard_frame)
        charts_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.create_traffic_chart(charts_frame)
        self.create_attack_timeline_chart(charts_frame)

    def create_traffic_chart(self, parent): 
        chart_frame = ttk.LabelFrame(parent, text='Network Traffic')
        chart_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)

        self.traffic_fig, self.traffic_ax = plt.subplots(figsize=(6, 4))
        self.traffic_canvas = FigureCanvasTkAgg(self.traffic_fig, chart_frame)
        self.traffic_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        self.traffic_line, = self.traffic_ax.plot([], [], 'b-', linewidth=2)
        self.traffic_ax.set_title('Network Throughput (Mbps)')
        self.traffic_ax.set_xlabel('Time')
        self.traffic_ax.set_ylabel('Mbps')
        self.traffic_ax.grid(True)

    def create_attack_timeline_chart(self, parent):
        chart_frame = ttk.LabelFrame(parent, text='Attack Timeline')
        chart_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)

        self.attack_fig, self.attack_ax = plt.subplots(figsize=(6, 4))
        self.attack_canvas = FigureCanvasTkAgg(self.attack_fig, chart_frame)
        self.attack_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        self.attack_ax.selt_title('Attacks Over Time')
        self.attack_ax.set_xlabel('Time')
        self.attack_ax.set_ylabel('Attack Count')
        self.attack_ax.grid(True)
    
    def create_network_stats_tab(self, parent):
        stats_frame = ttk.Frame(parent)
        parent.add(stats_frame, text='Network Stats')

        table_frame = ttk.LabelFrame(stats_frame, text='Active Flows')
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        columns = ('Source IP', 'Destination IP', 'Protocol', 'Packets', 'Bytes', 'Duration')
        self.flow_tree = ttk.Treeview(table_frame, columns=columns, show='headings', height=15)

        for col in columns:
            self.flow_tree.heading(col, text=col)
            self.flow_tree.column(col, width=120)
        
        v_scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.flow_tree.yview)
        h_scrollbar = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.flow_tree.xview)
        self.flow_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)

        self.flow_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)

        refresh_btn = ttk.Button(stats_frame, text='Refresh Flows', command=self.refresh_flow_data)
        refresh_btn.pack(pady=10)

    def create_security_tab(self, parent): 
        security_frame = ttk.Frame(parent)
        parent.add(security_frame, text='Security')

        ip_frame = ttk.Frame(security_frame)
        ip_frame.pack(fill=tk.BOTU, expand=True, padx=10, pady=10)

        blocked_frame = ttk.LabelFrame(ip_frame, text='Blocked IPs')
        blocked_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)

        self.blocked_listbox = tk.Listbox(blocked_frame, height=15)
        self.blocked_listbox.pack(fill=tk.BOTH, expand=True)

        blocked_scroll = ttk.Scrollbar(blocked_frame, orient=tk.VERTICAL)
        blocked_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.blocked_listbox.config(yscrollcommand=blocked_scroll.set)
        blocked_scroll.config(command=self.blocked_listbox.yview)

        suspicious_frame = ttk.LabelFrame(ip_frame, text='Suspicious IPs')
        suspicious_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)

        self.suspicious_listbox = tk.Listbox(suspicious_frame, height=15)
        self.suspicious_listbox.pack(fill=tk.BOTH, expand=True)

        suspicious_scroll = ttk.Scrollbar(suspicious_frame, orient=tk.VERTICAL)
        suspicious_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.suspicious_listbox.config(yscrollcommand=suspicious_scroll.set)
        suspicious_scroll.config(command=self.suspicious_listbox.yview)

        control_frame = ttk.Frame(security_frame)
        control_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Button(control_frame, text='Unblock IP').pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text='Block IP', command=self.block_ip).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text='Clear Suspicious', command=self.clear_suspicious).pack(side=tk.LEFT, padx=5)

    def create_performance_tab(self, parent): 
        perf_frame = ttk.Frame(parent)
        parent.add(perf_frame, text='Performance')
        
        charts_frame = ttk.Frame(perf_frame)
        charts_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.perf_fig, (self.cpu_ax, self.mem_ax) = plt.subplots(2, 1, figsize=(12, 8))
        self.perf_canvas = FigureCanvasTkAgg(self.perf_fig, charts_frame)
        self.perf_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        self.cpu_line, = self.cpu_ax.plot([], [], 'r-', linewidth=2, label='CPU Usage')
        self.cpu_ax.set_title('CPU Usage (%)')
        self.cpu_ax.set_ylabel('Percentage')
        self.cpu_ax.set_ylim(0, 100)
        self.cpu_ax.grid(True)
        self.cpu_ax.legend()

        self.mem_line, = self.mem_ax.plot([], [], 'g-', linewidth=2, label='Memory Usage')
        self.mem_ax.set_title('Memory Usage (%)')
        self.mem_ax.set_xlabel('Time')
        self.mem_ax.set_ylabel('Percentage')
        self.mem_ax.set_ylim(0, 100)
        self.mem_ax.grid(True)
        self.mem_ax.legend()

    def create_alerts_tab(self, parent):
        alerts_frame = ttk.Frame(parent)
        parent.add(alerts_frame, text='Alerts')

        alerts_text_frame = ttk.LabelFrame(alerts_frame, text='Recent Alerts')
        alerts_text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.alerts_text.tag_configure('critical', foreground='red', font=('Arial', 10, 'bold'))
        self.alerts_text.tag_configure('high', foreground='orange', font=('Arial', 10, 'bold'))
        self.alerts_text.tag_configure('medium', foreground='blue')
        self.alerts_text.tag_configure('low', foreground='gray')

        clear_btn = ttk.Button(alerts_frame, text='Clear Alerts', command=self.clear_alerts)
        clear_btn.pack(pady=10)
        
    def create_control_panel(self, parent):
        control_frame = ttk.LabelFrame(parent, text='Control Panel')
        control_frame.pack(fill=tk.X, pady=10)

        status_frame = ttk.Frame(control_frame)
        status_frame.pack(side=tk.LEFT, padx=10, pady=5)

        tk.Label(status_frame, text='Controller Status:').pack(side=tk.LEFT)
        self.controller_status = tk.Label(status_frame, text='Disconnected', fg='red')
        self.controller_status.pack(side=tk.LEFT, padx=5)

        tk.Label(status_frame, text='Monitor Status:').pack(side=tk.LEFT, padx=(20, 0))
        self.monitor_status = tk.Label(status_frame, text='Stopped', fg='red')
        self.mnonitor_status.pack(side=tk.LEFT, padx=5)

        button_frame = ttk.Frame(control_frame)
        button_frame.pack(side=tk.RIGHT, padx=10, pady=5)

        self.start_btn = ttk.Button(button_frame, text='Start Monitoring', command=self.toggle_monitoring)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        ttk.Button(button_frame, text='Reset Stats', command=self.reset_stats).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text='Export Data', command=self.export_data).pack(side=tk.LEFT, padx=5)

    def start_monitoring(self): 
        self.monitoring_thread = threading.Thread(target=self.monitoring_loop, daemon=True)
        self.monitoring_thread.start()

        self.update_gui()

    def monitoring_loop(self): 
        while True:
            if self.monitor.monitoring_active:
                try:
                    self.monitor.update_statistics()

                    controller_stats = self.monitor.fetch_controller_stats()
                    if controller_stats: self.root.after(0, self.update_controller_status, 'Connected', 'green')
                    else: self.root.after(0, self.update_controller_status, 'Disconnected', 'red')

                except Exception as e: self.monitor.logger.error(f'Monitoring error: {e}')

            time.sleep(2)
            
    def update_gui(self): 
        if self.monitor.monitoring_active:
            stats = self.monitor.current_stats

            self.stats_labels['total_packets'].config(text=f'{stats.get('total_packets', 0):,}')
            self.stats_labels['attacks_detected'].config(text=f'{stats.get('attacks_detected', 0):,}')
            self.stats_labels['blocked_ips_count'].config(tex=f'{len(stats.get('blocked_ips', set())):,}')
            self.stats_labels['throughput_mbps'].config(text=f'{stats.get('throughput_mbps', 0):.1f}')

            self.update_charts()
            self.update_security_lists()
            self.update_alerts_display()

        self.root.after(self.update_interval, self.update_gui)
        
    def update_charts(self):
        if len(self.monitor.performance_history) > 1:
            recent_data = list(self.monitor.performance_history)[-50:]

            timestamps = [d['timestamp'] for d in recent_data]
            throughput = [d.get('throughput_mbps', 0) for d in recent_data]
            cpu_usage = [d.get('cpu_usage', 0) for d in recent_data]
            memory_usage = [d.get('memory_usage', 0) for d in recent_data]

            self.traffic_line.set_data(range(len(throughput)), throughput)
            self.traffic_ax.set_xlim(0, len(throughput))
            self.traffic_ax.set_ylim(0, max(throughput) * 1.1 if throughput else 10)
            self.traffic_canvas.draw()

            self.cpu_line.set_data(range(len(cpu_usage)), cpu_usage)
            self.cpu_ax.set_xlim(0, len(cpu_usage))

            self.mem_line.set_data(range(len(memory_usage)), memory_usage)
            self.mem_ax.set_xlim(0, len(memory_usage))

            self.perf_canvas.draw()

            if self.monitor.attack_history:
                attack_times = []
                attack_counts = []

                now = datetime.now()
                intervals = []
                for i in range(20):
                    interval_start = now - timedelta(minutes=(20-i)*2)
                    interval_end = interval_start + timedelta(minutes=2)
                    intervals.append((interval_start, interval_end))

                for interval_start, interval_end in intervals:
                    count = sum(1 for alert in self.monitor.attack_history
                                if interval_start <= alert.get('timestamp', now) < interval_end
                                and alert.get('type') == 'security')
                    attack_times.append(interval_start)
                    attack_counts.append(count)
                
                self.attack_ax.clear()
                if attack_counts: self.attack_ax.bar(range(len(attack_counts)), attack_counts, color='red', alpha=0.7)
                self.attack_ax.set_title('Attacks Over Time (2-min intervals)')
                self.attack_ax.set_xlabel('Time Intervals')
                self.attack_ax.set_ylabel('Attack Count')
                self.attack_ax.grid(True)
                self.attack_canvas.draw()
                
    def update_security_lists(self): 
        stats = self.monitor.current_stats

        self.blocked_listbox.delete(0, tk.END)
        for ip in sorted(stats.get('blocked_ips', set())): self.blocked_listbox.insert(tk.END, ip)

        self.suspicious_listbox.delete(0, tk.END)
        for ip in sorted(stats.get('suspicious_ips', set())): self.suspicious_listbox.insert(tk.END, ip)
        
    def update_alerts_display(self):
        recent_alerts = list(self.monitor.attack_history)[-10:]

        for alert in recent_alerts:
            if not hasattr(alert, 'displayed'):
                timestamp = alert.get('timestamp', datetime.now()).strftime('%H:%M:%S')
                severity = alert.get('severity', 'low')
                message = alert.get('message', 'Unknown alert')

                alert_text = f'[{timestamp}] {severity.upper()}: {message}\n'

                self.selarts_text.insert(tk.END, alert_text, severity)
                self.alerts_text.see(tk.END)

                alert['displayed'] = True
            
    def update_controller_status(self, status, color):
        self.controller_status.config(text=status, fg=color)

    def toggle_monitoring(self):
        if self.monitor.monitoring_active:
            self.monitor.monitoring_active = False
            self.start_btn.config(text='Start Monitoring')
            self.monitor_status.config(text='Stopped', fg='red')
        else:
            self.monitor.monitoring_active = False
            self.start_btn.config(text='Stop Monitoring')
            self.monitor_status.config(text='Running', fg='green')

    def refresh_flow_data(self):
        for item in self.flow_tree.get_children():
            self.flow_tree.delete(item)
        
        controller_stats = self.monitor.fetch_controller_stats()
        if controller_stats and 'flow_stats' in controller_stats:
            flows = controller_stats['flow_stats']

            for i, flow in enumerate(flows[:100]):
                self.flow_tree.insert('', tk.END, values=(
                    flow.get('src_ip', 'N/A'),
                    flow.get('dst_ip', 'N/A'),
                    flow.get('protocol', 'N/A'),
                    flow.get('packet_count', 0),
                    flow.get('byte_count', 0),
                    flow.get('duration', 0)
                ))

    def unblock_ip(self):
        selection = self.blocked_listbox.curselection()
        if selection:
            ip = self.blocked_listbox.get(selection[0])

            try:
                response = requests.post(f'{self.monitor.controller_url}/unblock_ip', json={'ip': ip}, timeout=5)
                if response.status_code == 200:
                    self.monitor.logger.info(f'Unblocked IP: {ip}')
                else:
                    self.monitor.logger.error(f'Failed to unblock IP: {ip}')
            except Exception as e: self.monitor.logger.error(f'Unblock request error: {e}')

    def block_ip(self):
        dialog = tk.Toplevel(self.root)
        dialog.title('Block IP Address')
        dialog.geometry('300*150') # 300x150

        tk.Label(dialog, text='Enter IP address to block:').pack(pady=10)
        ip_entry = tk.Entry(dialog, width=30)
        ip_entry.pack(pady=5)

        def do_block():
            ip = ip_entry.get().strip()
            if ip:
                try:
                    response = requests.post(f'{self.monitor.controller_url}/block_ip', json={'ip': ip}, timeout=5)
                    if response.status_code == 200:
                        self.monitor.logger.info(f'Blocked IP: {ip}')
                    else:
                        self.monitor.logger.info(f'Failed to block IP: {ip}')
                except Exception as e: self.monitor.logger.error(f'Block request error: {e}')
                dialog.destroy()
        
        ttk.Button(dialog, text='Block', command=do_block).pack(pady=10)
        ttk.Button(dialog, text='Cancel', command=dialog.destroy).pack()

    def clear_suspicious(self):
        try:
            response = requests.post(f'{self.monitor.controller_url}/clear_suspicious', timeout=5)
            if response.status_code == 200: self.monitor.logger.info('Cleared suspicious IPs list')
            else: self.monitor.logger.info('Failed to clear suspicious IPs')
        except Exception as e: self.monitor.logger.error(f'Clear suspicious request error: {e}')
        
    def clear_alerts(self):
        self.alerts_text.delete(1.0, tk.END)
        self.monitor.attack_history.clear()

    def reset_stats(self): 
        try:
            response = requests.post(f'{self.monitor.controller_url}/reset_stats', timeout=5)
            if response.status_code == 200:
                self.monitor.logger.info('Statistics reset')
                self.monitor.current_stats = {
                    'total_packets': 0,
                    'attacks_detected': 0,
                    'blocked_ips': set(),
                    'suspicious_ips': set(),
                    'throughput_mbps': 0,
                    'cpu_usage': 0,
                    'memory_usage': 0,
                    'active_flows': 0
                }
            else: self.monitor.logger.error('Failed to reset statistics')
        except Exception as e: self.monitor.logger.error(f'Reset stats request error: {e}')

    def export_data(self):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        if self.monitor.performance_history:
            perf_df = pd.DataFrame(list(self.monitor.performance_history))
            perf_df.to_csv(f'logs/performance_data_{timestamp}.csv', index=False)
    
        if self.monitor.attack_history:
            alert_df = pd.DataFrame(list(self.monitor.attack_history))
            alert_df.to_csv(f'logs/alert_data_{timestamp}.csv', index=False)
        
        self.monitor.logger.info(f'Data exported with timestamp: {timestamp}')
        
    def run(self): self.root.mainloop()

def main():
    parser = argparse.ArgumentParser(description='Real-time Network Monitor for ML-SDN Defense')
    parser.add_argument('--controller-ip', default='127.0.0.1', help='SDN Controller IP')
    parser.add_argument('--controller-port', type=int, default=8080, help='Controller REST API port')
    parser.add_argument('--headless', action='store_true', help='Run without GUI')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], default='INFO', help='Logging level')

    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level))
    monitor = NetworkMonitor(args.controller_ip, args.controller_port)

    if args.headless:
        monitor.monitoring_active = True
        print('Statring headless monitoring ...')
        print('Press Ctrl+C to stop')

        try:
            while True:
                monitor.update_statistics()
                print(f'Stats: {monitor.current_stats}')
                time.sleep(5)
        except KeyboardInterrupt: print('Monitoring stopped')
    else:
        gui = NetworkMonitorGUI(monitor)
        gui.run()

if __name__ == '__main__': main()