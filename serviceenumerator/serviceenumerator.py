#!/usr/bin/env python3
"""
Service Enumerator - A network service scanning tool

This application provides a GUI interface for scanning network services on a target IP address.
It uses Nmap for scanning and displays port and service information in a user-friendly format.
"""

import sys
import os
import json
import csv
import re
import ipaddress
import socket
import datetime
import sqlite3
import threading
import subprocess
import signal
import time
from pathlib import Path
import paramiko  # For SSH connections

try:
    import nmap
except ImportError:
    nmap = None

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QRadioButton, QButtonGroup, QSlider,
    QComboBox, QTextEdit, QGroupBox, QFormLayout, QMessageBox, QFileDialog,
    QTableWidget, QTableWidgetItem, QHeaderView, QCheckBox, QSplitter,
    QProgressBar, QFrame, QSpinBox, QMenu, QAction, QDialog, QDialogButtonBox,
    QGridLayout
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QObject
from PyQt5.QtGui import QFont, QIcon, QColor


class ScanWorker(QThread):
    """Worker thread for running Nmap scans without freezing the GUI"""
    update_progress = pyqtSignal(int, str)
    current_port = pyqtSignal(str)  # Signal for current port being scanned
    scan_complete = pyqtSignal(dict)
    scan_error = pyqtSignal(str)
    scan_cancelled = pyqtSignal()  # New signal for when scan is cancelled
    debug_info = pyqtSignal(str)  # Signal for debug information
    
    def __init__(self, target, port_range, speed, options):
        super().__init__()
        self.target = target
        self.port_range = port_range
        self.speed = speed
        self.options = options
        self.is_running = True
        self.scan_start_time = None
        self.estimated_duration = None
        self.current_port_range = "Initializing..."
        self.nmap_process = None
        self.scan_aborted = False
    
    def run(self):
        """Run the scan in a separate thread"""
        try:
            if nmap is None:
                self.scan_error.emit("python-nmap is not installed. Please install it with: pip install python-nmap")
                return
                
            # Check if nmap is installed
            try:
                subprocess.run(['nmap', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            except (subprocess.SubprocessError, FileNotFoundError):
                self.scan_error.emit("Nmap is not installed or not found in PATH. Please install Nmap before using this tool.")
                return
            
            # Map speed setting to nmap timing template
            timing_map = {
                "Stealthy": "-T0",
                "Sneaky": "-T1",
                "Polite": "-T2",
                "Normal": "-T3",
                "Aggressive": "-T4"
            }
            
            timing = timing_map.get(self.speed, "-T3")  # Default to Normal
            
            # Update the UI
            self.update_progress.emit(5, f"Initializing scan on {self.target}")
            
            # Estimate scan duration based on port range and speed
            start_port, end_port = self.parse_port_range(self.port_range)
            num_ports = end_port - start_port + 1
            
            # Rough estimation of scan time based on number of ports and speed setting
            time_per_port = {
                "Stealthy": 0.5,  # 0.5 seconds per port (very slow)
                "Sneaky": 0.3,    # 0.3 seconds per port
                "Polite": 0.2,    # 0.2 seconds per port
                "Normal": 0.1,    # 0.1 seconds per port
                "Aggressive": 0.05 # 0.05 seconds per port (very fast)
            }
            
            # Rough time estimation in seconds
            self.estimated_duration = num_ports * time_per_port.get(self.speed, 0.1)
            
            # Start timer for progress updates
            self.scan_start_time = datetime.datetime.now()
            
            # Prepare nmap command arguments
            args = f"-sV {timing} -v"
            
            if "OS Detection" in self.options and self.options["OS Detection"]:
                args += " -O"
                
            if "Script Scanning" in self.options and self.options["Script Scanning"]:
                args += " --script=default"
            
            # Start the scan
            self.update_progress.emit(10, f"Starting scan with arguments: {args}")
            self.current_port.emit(f"Scanning ports {self.port_range}")
            
            # ====== USE THE PYTHON-NMAP LIBRARY DIRECTLY ======
            # This is a more reliable approach than trying to parse XML directly
            try:
                # Initialize the scanner
                scanner = nmap.PortScanner()
                
                # Set up a stderr monitoring thread for real-time updates
                self._setup_stderr_monitoring()
                
                # Run the scan
                self.update_progress.emit(20, "Executing nmap scan...")
                scanner.scan(self.target, self.port_range, arguments=args)
                
                # Process results
                self.update_progress.emit(90, "Processing scan results")
                
                # Create a results dictionary
                scan_data = {
                    "target": self.target,
                    "port_range": self.port_range,
                    "speed": self.speed,
                    "options": self.options,
                    "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "results": {}
                }
                
                # Check if the host was scanned and exists in the results
                if scanner.all_hosts() and self.target in scanner.all_hosts():
                    host_data = scanner[self.target]
                    
                    # Get OS information if available
                    if 'osmatch' in host_data:
                        scan_data['os_info'] = host_data['osmatch']
                    
                    # Get port information
                    if 'tcp' in host_data:
                        for port, port_data in host_data['tcp'].items():
                            scan_data['results'][str(port)] = {
                                'state': port_data['state'],
                                'service': port_data['name'],
                                'product': port_data.get('product', ''),
                                'version': port_data.get('version', ''),
                                'extrainfo': port_data.get('extrainfo', '')
                            }
                    
                    # Check if we found any open ports
                    if not scan_data['results']:
                        self.current_port.emit("No open ports found, but scan completed successfully.")
                    else:
                        port_count = len(scan_data['results'])
                        open_ports = sum(1 for p in scan_data['results'].values() if p['state'] == 'open')
                        self.current_port.emit(f"Scan complete. Found {port_count} ports ({open_ports} open).")
                else:
                    # Host might be down or not responding
                    self.current_port.emit(f"Host {self.target} appears to be down or not responding to scans.")
                
                # Send the results
                self.update_progress.emit(100, "Scan completed")
                self.scan_complete.emit(scan_data)
                
            except Exception as e:
                # Try a fallback direct approach if the python-nmap library failed
                self.current_port.emit(f"Error in nmap scan: {str(e)}. Trying direct nmap command...")
                scan_data = self._run_direct_nmap_scan(args)
                if scan_data:
                    self.update_progress.emit(100, "Scan completed (fallback mode)")
                    self.scan_complete.emit(scan_data)
                else:
                    self.scan_error.emit(f"Failed to get results: {str(e)}")
                
        except Exception as e:
            self.scan_error.emit(f"Error during scan: {str(e)}")
    
    def _setup_stderr_monitoring(self):
        """Set up a thread to monitor stderr output for port information"""
        # We just set up a placeholder - actual monitoring will happen in _run_direct_nmap_scan
        pass
    
    def _run_direct_nmap_scan(self, args):
        """Run nmap scan directly using subprocess as a fallback method"""
        try:
            self.current_port.emit("Trying alternative scan method...")
            
            # Build the command
            cmd = ['nmap']
            cmd.extend(args.split())
            cmd.extend(['-p', self.port_range, self.target])
            
            # Run the command and capture output
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                universal_newlines=True
            )
            
            self.nmap_process = process
            
            # Set up monitoring thread for stderr (for real-time updates)
            stderr_thread = threading.Thread(target=self._monitor_direct_stderr)
            stderr_thread.daemon = True
            stderr_thread.start()
            
            # Collect stdout (this will block, but it's our fallback method)
            stdout, _ = process.communicate()
            
            # Process the output
            if process.returncode != 0:
                self.current_port.emit(f"Nmap command failed with return code {process.returncode}")
                return None
            
            # Parse the output using simple text parsing
            scan_data = {
                "target": self.target,
                "port_range": self.port_range,
                "speed": self.speed,
                "options": self.options,
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "results": {}
            }
            
            # Parse results from stdout using simple string matching
            lines = stdout.splitlines()
            open_port_pattern = re.compile(r'(\d+)/tcp\s+open\s+(\S+)(?:\s+(.+))?')
            
            for line in lines:
                match = open_port_pattern.search(line)
                if match:
                    port = match.group(1)
                    service = match.group(2) or ""
                    version_info = match.group(3) or ""
                    
                    # Extract product, version, extrainfo from version_info
                    product = ""
                    version = ""
                    extrainfo = ""
                    
                    # Very basic parsing - could be improved
                    parts = version_info.split()
                    if parts:
                        product = parts[0]
                        if len(parts) > 1:
                            version = parts[1]
                        if len(parts) > 2:
                            extrainfo = " ".join(parts[2:])
                    
                    scan_data['results'][port] = {
                        'state': 'open',
                        'service': service,
                        'product': product,
                        'version': version,
                        'extrainfo': extrainfo
                    }
            
            # Return the parsed results
            return scan_data
            
        except Exception as e:
            self.current_port.emit(f"Error in direct scan: {str(e)}")
            return None
    
    def _monitor_direct_stderr(self):
        """Monitor stderr output from direct nmap scan for progress updates"""
        try:
            for line in iter(self.nmap_process.stderr.readline, ''):
                if not self.is_running:
                    break
                
                # Look for lines with port information
                if "Discovered open port" in line:
                    self.current_port.emit(f"Found: {line.strip()}")
                elif "Scanning" in line and "port" in line:
                    self.current_port.emit(f"Scanning: {line.strip()}")
                elif "Initiating" in line:
                    self.current_port.emit(line.strip())
                
        except Exception as e:
            print(f"Error in direct stderr monitor: {str(e)}")
    
    def parse_port_range(self, port_range):
        """Parse port range string into start and end ports"""
        if "-" in port_range:
            parts = port_range.split("-")
            try:
                start = int(parts[0])
                end = int(parts[1])
                return start, end
            except (ValueError, IndexError):
                return 1, 1000  # Default to common ports if parsing fails
        else:
            try:
                port = int(port_range)
                return port, port  # Single port
            except ValueError:
                return 1, 1000  # Default to common ports if parsing fails
    
    def calculate_progress(self):
        """Calculate estimated progress based on elapsed time"""
        if not self.scan_start_time or not self.estimated_duration:
            return 10  # Default starting progress
            
        elapsed_seconds = (datetime.datetime.now() - self.scan_start_time).total_seconds()
        
        # Add a maximum time cap to ensure scan eventually completes
        # For stealthy scans, limit to 10 minutes (600 seconds) max regardless of port count
        max_duration = 600  # 10 minutes max for any scan
        adjusted_duration = min(self.estimated_duration, max_duration)
        
        # Ensure progress reaches at least 85% after estimated duration
        progress = min(85, 10 + (75 * elapsed_seconds / adjusted_duration))
        
        # Force progress to at least 85% if we're at 2x the estimated duration
        if elapsed_seconds > (adjusted_duration * 2):
            progress = max(progress, 85)
            
        return int(progress)
        
    def stop(self):
        """Stop the scan and ensure proper termination"""
        # Set the flag to stop the thread
        self.is_running = False
        self.scan_aborted = True
        
        # Force terminate the Nmap process if it exists
        if self.nmap_process:
            try:
                # Log the termination attempt
                print("Attempting to terminate nmap process...")
                
                # Send termination signal
                self.nmap_process.terminate()
                
                # Give it a moment to terminate gracefully
                for _ in range(5):  # Try for up to 0.5 seconds (5 * 0.1)
                    time.sleep(0.1)
                    if self.nmap_process.poll() is not None:
                        print("Process terminated gracefully")
                        break
                
                # Force kill if still running
                if self.nmap_process.poll() is None:
                    print("Process did not terminate gracefully, killing...")
                    self.nmap_process.kill()
                    self.nmap_process.wait(timeout=1)  # Wait with timeout
                    print("Process killed")
            except Exception as e:
                print(f"Error terminating nmap process: {str(e)}")
        
        # Always emit the scan_cancelled signal when stop is called
        # This ensures the UI will update even if process termination has issues
        QTimer.singleShot(500, self.scan_cancelled.emit)


class ScanHistoryManager:
    """Manages the storage and retrieval of scan history"""
    def __init__(self, db_path="scan_history.db"):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize the SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            port_range TEXT,
            speed TEXT,
            options TEXT,
            timestamp TEXT,
            results TEXT
        )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_scan(self, scan_data):
        """Save a scan to the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO scan_history (target, port_range, speed, options, timestamp, results) VALUES (?, ?, ?, ?, ?, ?)",
            (
                scan_data["target"],
                scan_data["port_range"],
                scan_data["speed"],
                json.dumps(scan_data["options"]),
                scan_data["timestamp"],
                json.dumps(scan_data["results"])
            )
        )
        
        conn.commit()
        conn.close()
    
    def get_all_scans(self):
        """Get all scans from the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, target, port_range, timestamp FROM scan_history ORDER BY timestamp DESC")
        scans = cursor.fetchall()
        
        conn.close()
        
        return scans
    
    def get_scan_by_id(self, scan_id):
        """Get a specific scan by ID"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM scan_history WHERE id = ?", (scan_id,))
        scan = cursor.fetchone()
        
        conn.close()
        
        if scan:
            return {
                "id": scan[0],
                "target": scan[1],
                "port_range": scan[2],
                "speed": scan[3],
                "options": json.loads(scan[4]),
                "timestamp": scan[5],
                "results": json.loads(scan[6])
            }
        
        return None
    
    def clear_history(self):
        """Clear all scan history and reset the ID counter"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Delete all records
        cursor.execute("DELETE FROM scan_history")
        
        # Reset the SQLite autoincrement counter to start from 1 again
        cursor.execute("DELETE FROM sqlite_sequence WHERE name='scan_history'")
        
        conn.commit()
        conn.close()
        
        # Print confirmation message
        print("Scan history cleared and ID counter reset")


class ServiceCommandExecutor(QThread):
    """Worker thread for executing commands on remote services without freezing the GUI"""
    update_status = pyqtSignal(str)
    command_complete = pyqtSignal(bool, str)
    
    def __init__(self, target, port, service, command, credentials):
        super().__init__()
        self.target = target
        self.port = port
        self.service = service
        self.command = command
        self.credentials = credentials
        self.is_running = True
    
    def run(self):
        """Attempt to execute the command on the target service"""
        try:
            # Notify about attempt
            self.update_status.emit(f"Attempting to connect to {self.target}...")
            
            if self.credentials['type'] == 'ssh':
                self._execute_via_ssh()
            elif self.credentials['type'] == 'windows':
                self._execute_via_windows()
            else:
                raise ValueError(f"Unsupported connection type: {self.credentials['type']}")
                
        except Exception as e:
            self.command_complete.emit(False, f"Error executing command: {str(e)}")
    
    def _execute_via_ssh(self):
        """Execute command via SSH connection"""
        try:
            # Create SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            self.update_status.emit("Establishing SSH connection...")
            
            # Connect to the target
            ssh.connect(
                self.target,
                port=22,
                username=self.credentials['username'],
                password=self.credentials['password'],
                timeout=10
            )
            
            self.update_status.emit(f"Executing command on {self.service} service...")
            
            # Execute the command
            if self.command == "restart":
                # Handle restart commands specially
                stdin, stdout, stderr = ssh.exec_command(f"sudo systemctl restart {self.service}")
                exit_status = stdout.channel.recv_exit_status()
                
                if exit_status != 0:
                    # If systemctl fails, try the service command
                    self.update_status.emit("systemctl failed, trying service command...")
                    stdin, stdout, stderr = ssh.exec_command(f"sudo service {self.service} restart")
                    exit_status = stdout.channel.recv_exit_status()
                    
                    if exit_status != 0:
                        # If service command fails too, report the error
                        error = stderr.read().decode('utf-8')
                        raise Exception(f"Failed to restart service: {error}")
                
                self.update_status.emit(f"Service {self.service} restarted successfully")
                self.command_complete.emit(True, f"Service {self.service} restarted successfully")
            else:
                # Execute the custom command
                full_command = f"sudo {self.command.format(service=self.service)}"
                self.update_status.emit(f"Executing: {full_command}")
                
                stdin, stdout, stderr = ssh.exec_command(full_command)
                exit_status = stdout.channel.recv_exit_status()
                
                # Get command output
                output = stdout.read().decode('utf-8')
                error = stderr.read().decode('utf-8')
                
                if exit_status != 0:
                    # Command failed
                    raise Exception(f"Command failed with exit code {exit_status}: {error}")
                
                self.update_status.emit(f"Command executed successfully")
                if output:
                    self.update_status.emit(f"Output:\n{output}")
                
                self.command_complete.emit(True, f"Command executed successfully on {self.service}")
            
        except Exception as e:
            self.command_complete.emit(False, f"SSH error: {str(e)}")
        finally:
            if 'ssh' in locals():
                ssh.close()
    
    def _execute_via_windows(self):
        """Execute command via Windows Remote Management"""
        # This is a placeholder for Windows command execution
        # In a real implementation, you would use pywinrm or similar
        self.update_status.emit("Windows command execution not implemented yet")
        self.command_complete.emit(False, "Windows command execution not implemented yet")
    
    def stop(self):
        """Stop the command execution attempt"""
        self.is_running = False


class CredentialsDialog(QDialog):
    """Dialog for entering service command credentials"""
    def __init__(self, service, parent=None):
        super().__init__(parent)
        
        self.service = service
        self.setWindowTitle("Service Command Authentication")
        
        layout = QVBoxLayout()
        
        # Command selection
        command_group = QGroupBox("Command")
        command_layout = QVBoxLayout()
        
        self.restart_radio = QRadioButton("Restart Service")
        self.restart_radio.setChecked(True)
        
        self.status_radio = QRadioButton("Check Service Status")
        
        self.custom_radio = QRadioButton("Custom Command")
        self.custom_command = QLineEdit()
        self.custom_command.setPlaceholderText("e.g., systemctl status {service}")
        self.custom_command.setEnabled(False)
        
        # Connect custom command radio button to enable/disable the text field
        self.custom_radio.toggled.connect(self.custom_command.setEnabled)
        
        command_layout.addWidget(self.restart_radio)
        command_layout.addWidget(self.status_radio)
        
        custom_layout = QHBoxLayout()
        custom_layout.addWidget(self.custom_radio)
        custom_layout.addWidget(self.custom_command)
        command_layout.addLayout(custom_layout)
        
        command_group.setLayout(command_layout)
        layout.addWidget(command_group)
        
        # Connection type selection
        type_group = QGroupBox("Connection Type")
        type_layout = QVBoxLayout()
        
        self.ssh_radio = QRadioButton("SSH (Linux/Unix)")
        self.windows_radio = QRadioButton("Windows Remote Management")
        
        self.ssh_radio.setChecked(True)
        
        type_layout.addWidget(self.ssh_radio)
        type_layout.addWidget(self.windows_radio)
        type_group.setLayout(type_layout)
        
        layout.addWidget(type_group)
        
        # Credentials form
        cred_group = QGroupBox("Authentication")
        cred_layout = QFormLayout()
        
        self.username_input = QLineEdit()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        
        cred_layout.addRow("Username:", self.username_input)
        cred_layout.addRow("Password:", self.password_input)
        
        cred_group.setLayout(cred_layout)
        layout.addWidget(cred_group)
        
        # Warning label
        warning_label = QLabel("Warning: These operations require elevated privileges and may affect service availability. Use with caution.")
        warning_label.setStyleSheet("color: red;")
        layout.addWidget(warning_label)
        
        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        
        layout.addWidget(buttons)
        
        self.setLayout(layout)
    
    def get_command(self):
        """Get the selected command"""
        if self.restart_radio.isChecked():
            return "restart"
        elif self.status_radio.isChecked():
            return "systemctl status {service}"
        else:
            return self.custom_command.text()
    
    def get_credentials(self):
        """Return the entered credentials and command"""
        connection_type = 'ssh' if self.ssh_radio.isChecked() else 'windows'
        
        return {
            'type': connection_type,
            'username': self.username_input.text(),
            'password': self.password_input.text(),
            'command': self.get_command()
        }


class ServiceEnumerator(QMainWindow):
    """Main window for the Service Enumerator application"""
    def __init__(self):
        super().__init__()
        
        # Initialize variables
        self.current_scan_data = None
        self.scan_worker = None
        self.history_manager = ScanHistoryManager()
        
        # Initialize the last save directory
        self.last_save_directory = str(Path.home())
        
        # Set up the UI
        self.init_ui()
        
        # Check for nmap
        self.check_requirements()
    
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("Service Enumerator")
        self.setMinimumSize(800, 600)
        
        # Create central widget with tab structure
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        main_layout = QVBoxLayout(self.central_widget)
        
        # Create tabs
        self.tabs = QTabWidget()
        self.scan_tab = QWidget()
        self.history_tab = QWidget()
        
        self.tabs.addTab(self.scan_tab, "Scan")
        self.tabs.addTab(self.history_tab, "History")
        
        # Set up scan tab
        self.setup_scan_tab()
        
        # Set up history tab
        self.setup_history_tab()
        
        main_layout.addWidget(self.tabs)
        
        # Show the UI
        self.show()
    
    def setup_scan_tab(self):
        """Set up the scan tab UI"""
        layout = QVBoxLayout(self.scan_tab)
        
        # Target and scan options section
        options_group = QGroupBox("Scan Configuration")
        options_layout = QFormLayout()
        
        # Target input
        target_layout = QHBoxLayout()
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter IP address (e.g., 192.168.1.1)")
        target_layout.addWidget(self.target_input)
        
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.start_scan)
        target_layout.addWidget(self.scan_button)
        
        options_layout.addRow("Target IP:", target_layout)
        
        # Port selection
        port_group = QGroupBox("Port Selection")
        port_layout = QVBoxLayout()
        
        self.port_selection = QButtonGroup(self)
        
        self.common_ports_radio = QRadioButton("Common Ports")
        self.all_ports_radio = QRadioButton("All Ports")
        self.custom_ports_radio = QRadioButton("Custom Range")
        
        self.port_selection.addButton(self.common_ports_radio)
        self.port_selection.addButton(self.all_ports_radio)
        self.port_selection.addButton(self.custom_ports_radio)
        
        self.common_ports_radio.setChecked(True)
        
        port_layout.addWidget(self.common_ports_radio)
        port_layout.addWidget(self.all_ports_radio)
        
        custom_range_layout = QHBoxLayout()
        custom_range_layout.addWidget(self.custom_ports_radio)
        
        self.start_port = QSpinBox()
        self.start_port.setRange(1, 65535)
        self.start_port.setValue(1)
        
        self.end_port = QSpinBox()
        self.end_port.setRange(1, 65535)
        self.end_port.setValue(1000)
        
        custom_range_layout.addWidget(QLabel("From:"))
        custom_range_layout.addWidget(self.start_port)
        custom_range_layout.addWidget(QLabel("To:"))
        custom_range_layout.addWidget(self.end_port)
        
        port_layout.addLayout(custom_range_layout)
        port_group.setLayout(port_layout)
        
        options_layout.addRow(port_group)
        
        # Scan speed selection
        speed_layout = QHBoxLayout()
        self.speed_combo = QComboBox()
        self.speed_combo.addItems(["Stealthy", "Sneaky", "Polite", "Normal", "Aggressive"])
        self.speed_combo.setCurrentText("Normal")
        speed_layout.addWidget(self.speed_combo)
        
        options_layout.addRow("Scan Speed:", speed_layout)
        
        # Additional options
        additional_group = QGroupBox("Additional Options")
        additional_layout = QVBoxLayout()
        
        self.os_detection = QCheckBox("OS Detection (requires administrator privileges)")
        self.script_scan = QCheckBox("Script Scanning")
        self.service_interaction = QCheckBox("Enable Service Interaction (for remote command execution)")
        
        additional_layout.addWidget(self.os_detection)
        additional_layout.addWidget(self.script_scan)
        additional_layout.addWidget(self.service_interaction)
        
        additional_group.setLayout(additional_layout)
        options_layout.addRow(additional_group)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Progress indicator
        progress_layout = QHBoxLayout()
        
        # Create a progress bar with text overlay
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setMinimumWidth(400)  # Set minimum width for consistent size
        self.progress_bar.setFixedHeight(25)    # Set fixed height
        self.progress_bar.setAlignment(Qt.AlignCenter)  # Center-align the text
        self.progress_bar.setFormat("Ready to scan")    # Initial text
        self.progress_bar.setTextVisible(True)          # Make sure text is visible
        
        # Style the progress bar to ensure text is always visible
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid grey;
                border-radius: 5px;
                text-align: center;
                font-weight: bold;
                color: white;  /* Change text color to white for better visibility */
            }
            
            QProgressBar::chunk {
                background-color: #4CAF50;
                width: 20px;
            }
        """)
        
        progress_layout.addWidget(self.progress_bar)
        
        # Add a stretch to keep the progress bar from expanding too much
        progress_layout.addStretch(1)
        
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.cancel_scan)
        self.cancel_button.setEnabled(False)
        progress_layout.addWidget(self.cancel_button)
        
        layout.addLayout(progress_layout)
        
        # Add current port label
        self.current_port_label = QLabel("No scan in progress")
        self.current_port_label.setWordWrap(True)
        self.current_port_label.setStyleSheet("color: blue;")
        layout.addWidget(self.current_port_label)
        
        # Results display
        results_group = QGroupBox("Scan Results")
        results_layout = QVBoxLayout()
        
        # Use a splitter for resizable sections
        splitter = QSplitter(Qt.Vertical)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels(["Port", "State", "Service", "Version", "Info"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.results_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.results_table.customContextMenuRequested.connect(self.show_results_context_menu)
        
        # Detailed output
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        
        splitter.addWidget(self.results_table)
        splitter.addWidget(self.output_text)
        
        results_layout.addWidget(splitter)
        
        # Export buttons
        export_layout = QHBoxLayout()
        
        self.save_log_button = QPushButton("Save Log")
        self.save_log_button.clicked.connect(self.save_log)
        self.save_log_button.setEnabled(False)
        
        self.export_csv_button = QPushButton("Export CSV")
        self.export_csv_button.clicked.connect(self.export_csv)
        self.export_csv_button.setEnabled(False)
        
        export_layout.addWidget(self.save_log_button)
        export_layout.addWidget(self.export_csv_button)
        export_layout.addStretch()
        
        results_layout.addLayout(export_layout)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
    
    def setup_history_tab(self):
        """Set up the history tab UI"""
        layout = QVBoxLayout(self.history_tab)
        
        # History controls
        controls_layout = QHBoxLayout()
        
        self.refresh_button = QPushButton("Refresh History")
        self.refresh_button.clicked.connect(self.refresh_history)
        
        self.clear_history_button = QPushButton("Clear History")
        self.clear_history_button.clicked.connect(self.clear_history)
        
        controls_layout.addWidget(self.refresh_button)
        controls_layout.addWidget(self.clear_history_button)
        controls_layout.addStretch()
        
        layout.addLayout(controls_layout)
        
        # History table
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(4)
        self.history_table.setHorizontalHeaderLabels(["ID", "Target", "Port Range", "Timestamp"])
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.history_table.itemClicked.connect(self.load_history_item)
        
        layout.addWidget(self.history_table)
        
        # History detail view
        details_group = QGroupBox("Scan Details")
        details_layout = QVBoxLayout()
        
        self.history_output = QTextEdit()
        self.history_output.setReadOnly(True)
        
        details_layout.addWidget(self.history_output)
        
        # Export buttons for history
        history_export_layout = QHBoxLayout()
        
        self.history_save_log_button = QPushButton("Save Log")
        self.history_save_log_button.clicked.connect(self.save_history_log)
        self.history_save_log_button.setEnabled(False)
        
        self.history_export_csv_button = QPushButton("Export CSV")
        self.history_export_csv_button.clicked.connect(self.export_history_csv)
        self.history_export_csv_button.setEnabled(False)
        
        history_export_layout.addWidget(self.history_save_log_button)
        history_export_layout.addWidget(self.history_export_csv_button)
        history_export_layout.addStretch()
        
        details_layout.addLayout(history_export_layout)
        
        details_group.setLayout(details_layout)
        layout.addWidget(details_group)
        
        # Load history data
        self.refresh_history()
    
    def check_requirements(self):
        """Check if nmap and python-nmap are installed"""
        if nmap is None:
            QMessageBox.warning(
                self,
                "Missing Dependency",
                "python-nmap is not installed.\n\nPlease install it with:\npip install python-nmap"
            )
        
        # Check if nmap is installed
        try:
            subprocess.run(['nmap', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        except (subprocess.SubprocessError, FileNotFoundError):
            QMessageBox.critical(
                self,
                "Missing Dependency",
                "Nmap is not installed or not found in PATH.\n\nPlease install Nmap before using this tool."
            )
    
    def start_scan(self):
        """Validate inputs and start the scan"""
        # Validate target IP
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Invalid Target", "Please enter a target IP address.")
            return
        
        try:
            ipaddress.ip_address(target)
        except ValueError:
            try:
                # Try to resolve hostname
                socket.gethostbyname(target)
            except socket.error:
                QMessageBox.warning(
                    self,
                    "Invalid Target",
                    "Please enter a valid IP address or hostname."
                )
                return
        
        # Get port range
        if self.common_ports_radio.isChecked():
            port_range = "1-1000"
        elif self.all_ports_radio.isChecked():
            port_range = "1-65535"
        else:  # Custom range
            start = self.start_port.value()
            end = self.end_port.value()
            
            if start > end:
                QMessageBox.warning(
                    self,
                    "Invalid Port Range",
                    "Start port must be less than or equal to end port."
                )
                return
                
            port_range = f"{start}-{end}"
        
        # Get scan speed
        speed = self.speed_combo.currentText()
        
        # Get additional options
        options = {
            "OS Detection": self.os_detection.isChecked(),
            "Script Scanning": self.script_scan.isChecked()
        }
        
        # Check for administrator/root privileges if needed
        if options["OS Detection"]:
            if os.name == 'nt':  # Windows
                import ctypes
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    QMessageBox.warning(
                        self,
                        "Administrator Privileges Required",
                        "OS Detection requires administrator privileges.\n\nPlease run the application as administrator."
                    )
                    return
            else:  # Unix/Linux/Mac
                if os.geteuid() != 0:
                    QMessageBox.warning(
                        self,
                        "Root Privileges Required",
                        "OS Detection requires root privileges.\n\nPlease run the application with sudo."
                    )
                    return
        
        # Clear previous results
        self.results_table.setRowCount(0)
        self.output_text.clear()
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Starting scan...")  # Update format instead of status_label
        self.current_port_label.setText("Initializing scan...")
        
        # Disable scan button and enable cancel button
        self.scan_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        
        # Create and start the scan worker
        self.scan_worker = ScanWorker(target, port_range, speed, options)
        self.scan_worker.update_progress.connect(self.update_progress)
        self.scan_worker.current_port.connect(self.update_current_port)
        self.scan_worker.scan_complete.connect(self.scan_completed)
        self.scan_worker.scan_error.connect(self.scan_error)
        self.scan_worker.scan_cancelled.connect(self.scan_cancelled)
        
        # Set up progress update timer
        self.progress_timer = QTimer()
        self.progress_timer.timeout.connect(self.update_scan_progress)
        self.progress_timer.start(500)  # Update every 500ms
        
        self.scan_worker.start()
    
    def update_scan_progress(self):
        """Update progress based on time estimation"""
        if hasattr(self, 'scan_worker') and self.scan_worker and self.scan_worker.isRunning():
            progress = self.scan_worker.calculate_progress()
            current_stage = "Scanning ports and identifying services"
            
            if progress < 30:
                current_stage = "Discovering host and initiating scan"
            elif progress < 70:
                current_stage = "Scanning ports and identifying services"
            elif progress < 85:
                current_stage = "Running additional service detection"
            else:
                # When progress is 85% or higher, show "Processing Results"
                current_stage = "Processing Results"
                
            # Update the progress bar with the percentage and current stage
            self.progress_bar.setValue(progress)
            self.progress_bar.setFormat(f"{current_stage} ({progress}%)")
        else:
            # Stop the timer if scan is not running
            if hasattr(self, 'progress_timer') and self.progress_timer.isActive():
                self.progress_timer.stop()
    
    def update_current_port(self, port_info):
        """Update the current port label with real-time port information"""
        self.current_port_label.setText(port_info)
    
    def cancel_scan(self):
        """Cancel the current scan"""
        if self.scan_worker and self.scan_worker.isRunning():
            # Update UI immediately to show cancel is in progress
            self.cancel_button.setEnabled(False)
            self.progress_bar.setFormat("Cancelling scan...")
            
            # Set the flag to stop the scan
            self.scan_worker.stop()
            
            # Stop the progress timer
            if hasattr(self, 'progress_timer') and self.progress_timer.isActive():
                self.progress_timer.stop()
            
            # Add a backup timeout to ensure the UI is reset even if something goes wrong
            QTimer.singleShot(5000, self.ensure_scan_cancelled)
    
    def ensure_scan_cancelled(self):
        """Ensure the scan is shown as cancelled if the normal process fails"""
        if self.scan_worker and self.scan_worker.isRunning():
            print("Forcing scan worker termination after timeout")
            # Try to terminate the thread forcefully if it's still running
            self.scan_worker.terminate()
            self.scan_worker.wait(1000)  # Wait with timeout
            # Reset the UI
            self.scan_cancelled()
    
    def update_progress(self, value, message):
        """Update the progress bar and status message"""
        self.progress_bar.setValue(value)
        self.progress_bar.setFormat(message)  # Set the message as the progress bar text
    
    def scan_completed(self, scan_data):
        """Process completed scan results"""
        # Stop the progress timer
        if hasattr(self, 'progress_timer') and self.progress_timer.isActive():
            self.progress_timer.stop()
            
        self.current_scan_data = scan_data
        
        # Update the results table
        self.results_table.setRowCount(0)
        
        if scan_data["results"]:
            # Sort ports numerically - ensure we're using the exact keys that exist in the results
            ports = sorted([p for p in scan_data["results"].keys()], key=lambda x: int(x) if str(x).isdigit() else 0)
            
            for port_str in ports:
                # port_str is already the exact key from the results dictionary
                port_data = scan_data["results"][port_str]
                
                row = self.results_table.rowCount()
                self.results_table.insertRow(row)
                
                # Port
                self.results_table.setItem(row, 0, QTableWidgetItem(port_str))
                
                # State
                state_item = QTableWidgetItem(port_data["state"])
                if port_data["state"] == "open":
                    state_item.setForeground(QColor("green"))
                elif port_data["state"] == "filtered":
                    state_item.setForeground(QColor("orange"))
                else:
                    state_item.setForeground(QColor("red"))
                self.results_table.setItem(row, 1, state_item)
                
                # Service
                self.results_table.setItem(row, 2, QTableWidgetItem(port_data["service"]))
                
                # Version
                version = port_data.get("product", "")
                if port_data.get("version"):
                    if version:
                        version += " "
                    version += port_data["version"]
                self.results_table.setItem(row, 3, QTableWidgetItem(version))
                
                # Extra info
                self.results_table.setItem(row, 4, QTableWidgetItem(port_data.get("extrainfo", "")))
        
        # Generate text output
        output = f"Scan Results for {scan_data['target']}\n"
        output += f"Timestamp: {scan_data['timestamp']}\n"
        output += f"Port Range: {scan_data['port_range']}\n"
        output += f"Scan Speed: {scan_data['speed']}\n\n"
        
        if "os_info" in scan_data:
            output += "OS Detection Results:\n"
            for os_match in scan_data["os_info"]:
                output += f"- {os_match['name']} (Accuracy: {os_match['accuracy']}%)\n"
            output += "\n"
        
        if scan_data["results"]:
            output += "Open Ports:\n"
            output += "--------------------------------------------------\n"
            output += "PORT\tSTATE\tSERVICE\tVERSION\n"
            output += "--------------------------------------------------\n"
            
            # Use the same exact keys as above - don't create new string representations
            for port_str in ports:
                port_data = scan_data["results"][port_str]
                
                if port_data["state"] == "open":
                    service = port_data["service"]
                    
                    version = port_data.get("product", "")
                    if port_data.get("version"):
                        if version:
                            version += " "
                        version += port_data["version"]
                    
                    if port_data.get("extrainfo"):
                        if version:
                            version += " "
                        version += f"({port_data['extrainfo']})"
                    
                    output += f"{port_str}/tcp\t{port_data['state']}\t{service}\t{version}\n"
        else:
            output += "No open ports found.\n"
        
        self.output_text.setText(output)
        
        # Enable export buttons
        self.save_log_button.setEnabled(True)
        self.export_csv_button.setEnabled(True)
        
        # Save scan to history
        self.history_manager.save_scan(scan_data)
        self.refresh_history()
        
        # Reset UI
        self.scan_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        self.progress_bar.setFormat("Scan completed")  # Update format instead of status_label
        
        # Additional cleanup
        self.current_port_label.setText("Scan completed")
    
    def scan_error(self, error_message):
        """Handle scan errors"""
        # Stop the progress timer
        if hasattr(self, 'progress_timer') and self.progress_timer.isActive():
            self.progress_timer.stop()
            
        QMessageBox.critical(self, "Scan Error", error_message)
        
        # Reset UI
        self.scan_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        self.progress_bar.setFormat(f"Scan failed")  # Simplified error message on progress bar
        
        # Additional cleanup
        self.current_port_label.setText("Scan failed: " + error_message)
    
    def save_log(self):
        """Save the scan results to a text file"""
        if not self.output_text.toPlainText():
            return
        
        default_filename = f"scan_{self.current_scan_data['target']}_{self.current_scan_data['timestamp'].replace(':', '-')}.txt"
        default_path = str(Path(self.last_save_directory) / default_filename)
            
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Save Log File",
            default_path,
            "Text Files (*.txt);;All Files (*)"
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(self.output_text.toPlainText())
                
                # Remember the directory for next time
                self.last_save_directory = str(Path(filename).parent)
                    
                QMessageBox.information(self, "Success", f"Log saved to {filename}")
                
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save log: {str(e)}")
    
    def export_csv(self):
        """Export the scan results to a CSV file"""
        if not self.current_scan_data or not self.current_scan_data["results"]:
            return
        
        default_filename = f"scan_{self.current_scan_data['target']}_{self.current_scan_data['timestamp'].replace(':', '-')}.csv"
        default_path = str(Path(self.last_save_directory) / default_filename)
            
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export CSV File",
            default_path,
            "CSV Files (*.csv);;All Files (*)"
        )
        
        if filename:
            try:
                with open(filename, 'w', newline='') as f:
                    writer = csv.writer(f)
                    
                    # Write header
                    writer.writerow(["Target", "Port", "Protocol", "State", "Service", "Product", "Version", "Extra Info", "Scan Time"])
                    
                    # Write data
                    for port_str, port_data in self.current_scan_data["results"].items():
                        writer.writerow([
                            self.current_scan_data["target"],
                            port_str,
                            "tcp",
                            port_data["state"],
                            port_data["service"],
                            port_data.get("product", ""),
                            port_data.get("version", ""),
                            port_data.get("extrainfo", ""),
                            self.current_scan_data["timestamp"]
                        ])
                
                # Remember the directory for next time
                self.last_save_directory = str(Path(filename).parent)
                    
                QMessageBox.information(self, "Success", f"CSV exported to {filename}")
                
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export CSV: {str(e)}")
    
    def refresh_history(self):
        """Refresh the history table"""
        self.history_table.setRowCount(0)
        
        scans = self.history_manager.get_all_scans()
        
        for scan in scans:
            row = self.history_table.rowCount()
            self.history_table.insertRow(row)
            
            # ID
            self.history_table.setItem(row, 0, QTableWidgetItem(str(scan[0])))
            
            # Target
            self.history_table.setItem(row, 1, QTableWidgetItem(scan[1]))
            
            # Port Range
            self.history_table.setItem(row, 2, QTableWidgetItem(scan[2]))
            
            # Timestamp
            self.history_table.setItem(row, 3, QTableWidgetItem(scan[3]))
    
    def load_history_item(self, item):
        """Load a history item when clicked"""
        row = item.row()
        scan_id = int(self.history_table.item(row, 0).text())
        
        scan_data = self.history_manager.get_scan_by_id(scan_id)
        
        if scan_data:
            # Generate text output
            output = f"Scan Results for {scan_data['target']}\n"
            output += f"Timestamp: {scan_data['timestamp']}\n"
            output += f"Port Range: {scan_data['port_range']}\n"
            output += f"Scan Speed: {scan_data['speed']}\n\n"
            
            if "os_info" in scan_data:
                output += "OS Detection Results:\n"
                for os_match in scan_data["os_info"]:
                    output += f"- {os_match['name']} (Accuracy: {os_match['accuracy']}%)\n"
                output += "\n"
            
            if scan_data["results"]:
                # Sort ports numerically - ensure we're using the exact keys that exist in the results
                ports = sorted([p for p in scan_data["results"].keys()], key=lambda x: int(x) if str(x).isdigit() else 0)
                
                output += "Open Ports:\n"
                output += "--------------------------------------------------\n"
                output += "PORT\tSTATE\tSERVICE\tVERSION\n"
                output += "--------------------------------------------------\n"
                
                for port_str in ports:
                    port_data = scan_data["results"][port_str]
                    
                    if port_data["state"] == "open":
                        service = port_data["service"]
                        
                        version = port_data.get("product", "")
                        if port_data.get("version"):
                            if version:
                                version += " "
                            version += port_data["version"]
                        
                        if port_data.get("extrainfo"):
                            if version:
                                version += " "
                            version += f"({port_data['extrainfo']})"
                        
                        output += f"{port_str}/tcp\t{port_data['state']}\t{service}\t{version}\n"
            else:
                output += "No open ports found.\n"
            
            self.history_output.setText(output)
            
            # Enable export buttons
            self.history_save_log_button.setEnabled(True)
            self.history_export_csv_button.setEnabled(True)
            
            # Store current scan data for export
            self.current_history_scan = scan_data
    
    def clear_history(self):
        """Clear all scan history after confirmation"""
        confirm = QMessageBox.question(
            self,
            "Clear History",
            "Are you sure you want to clear all scan history?\nThis action cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if confirm == QMessageBox.Yes:
            self.history_manager.clear_history()
            self.refresh_history()
            self.history_output.clear()
            self.history_save_log_button.setEnabled(False)
            self.history_export_csv_button.setEnabled(False)
    
    def save_history_log(self):
        """Save the selected history item to a text file"""
        if not self.history_output.toPlainText():
            return
        
        default_filename = f"scan_{self.current_history_scan['target']}_{self.current_history_scan['timestamp'].replace(':', '-')}.txt"
        default_path = str(Path(self.last_save_directory) / default_filename)
            
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Save Log File",
            default_path,
            "Text Files (*.txt);;All Files (*)"
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(self.history_output.toPlainText())
                
                # Remember the directory for next time
                self.last_save_directory = str(Path(filename).parent)
                    
                QMessageBox.information(self, "Success", f"Log saved to {filename}")
                
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save log: {str(e)}")
    
    def export_history_csv(self):
        """Export the selected history item to a CSV file"""
        if not hasattr(self, 'current_history_scan') or not self.current_history_scan["results"]:
            return
        
        default_filename = f"scan_{self.current_history_scan['target']}_{self.current_history_scan['timestamp'].replace(':', '-')}.csv"
        default_path = str(Path(self.last_save_directory) / default_filename)
            
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export CSV File",
            default_path,
            "CSV Files (*.csv);;All Files (*)"
        )
        
        if filename:
            try:
                with open(filename, 'w', newline='') as f:
                    writer = csv.writer(f)
                    
                    # Write header
                    writer.writerow(["Target", "Port", "Protocol", "State", "Service", "Product", "Version", "Extra Info", "Scan Time"])
                    
                    # Write data
                    for port_str, port_data in self.current_history_scan["results"].items():
                        writer.writerow([
                            self.current_history_scan["target"],
                            port_str,
                            "tcp",
                            port_data["state"],
                            port_data["service"],
                            port_data.get("product", ""),
                            port_data.get("version", ""),
                            port_data.get("extrainfo", ""),
                            self.current_history_scan["timestamp"]
                        ])
                
                # Remember the directory for next time
                self.last_save_directory = str(Path(filename).parent)
                    
                QMessageBox.information(self, "Success", f"CSV exported to {filename}")
                
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export CSV: {str(e)}")
    
    def show_results_context_menu(self, position):
        """Show context menu for results table"""
        if not self.service_interaction.isChecked() or self.results_table.rowCount() == 0:
            return
            
        # Get the row under the mouse
        row = self.results_table.indexAt(position).row()
        if row < 0:
            return
            
        # Create context menu
        menu = QMenu()
        execute_action = QAction("Execute Command on Service", self)
        execute_action.triggered.connect(lambda: self.execute_service_command(row))
        
        menu.addAction(execute_action)
        menu.exec_(self.results_table.mapToGlobal(position))
    
    def execute_service_command(self, row):
        """Show credentials dialog and attempt to execute a command on the service"""
        if not self.current_scan_data:
            return
            
        # Get service information
        port = self.results_table.item(row, 0).text()
        service = self.results_table.item(row, 2).text()
        
        # Show confirmation dialog
        confirm = QMessageBox.question(
            self,
            "Confirm Service Command",
            f"You are about to execute a command on the {service} service on port {port}.\n\n"
            "This action requires elevated privileges and may affect service availability.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if confirm != QMessageBox.Yes:
            return
            
        # Show credentials dialog
        credentials_dialog = CredentialsDialog(service, self)
        if credentials_dialog.exec_() != QDialog.Accepted:
            return
            
        credentials = credentials_dialog.get_credentials()
        command = credentials.pop('command', "restart")  # Extract command from credentials
        
        # Set up status window
        status_dialog = QDialog(self)
        status_dialog.setWindowTitle(f"Executing Command on {service} Service")
        status_dialog.setMinimumSize(400, 300)
        
        status_layout = QVBoxLayout()
        
        status_text = QTextEdit()
        status_text.setReadOnly(True)
        status_layout.addWidget(status_text)
        
        close_button = QPushButton("Close")
        close_button.setEnabled(False)
        close_button.clicked.connect(status_dialog.accept)
        status_layout.addWidget(close_button)
        
        status_dialog.setLayout(status_layout)
        
        # Create and start service command executor
        self.service_executor = ServiceCommandExecutor(
            self.current_scan_data['target'],
            port,
            service,
            command,
            credentials
        )
        
        def update_status(message):
            status_text.append(message)
        
        def command_complete(success, message):
            status_text.append(message)
            if success:
                status_text.append("\nCommand execution completed successfully.")
            else:
                status_text.append("\nCommand execution failed. See error message above.")
            close_button.setEnabled(True)
        
        self.service_executor.update_status.connect(update_status)
        self.service_executor.command_complete.connect(command_complete)
        
        self.service_executor.start()
        status_dialog.exec_()
    
    def scan_cancelled(self):
        """Handle scan cancellation"""
        # Reset UI
        self.progress_bar.setFormat("Scan cancelled")  # Update format instead of status_label
        self.scan_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        self.current_port_label.setText("Scan cancelled by user")
        self.progress_bar.setValue(0)


def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Use Fusion style for a modern look
    enumerator = ServiceEnumerator()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main() 