#!/usr/bin/env python3
"""
HoneyPot - A File System Monitoring Tool

This application allows users to set up "honeypots" - file system monitoring points
that track and alert on various file events (creation, modification, deletion, etc.).
It can also create deployable payload files for persistence monitoring.
"""

import sys
import os
import time
import datetime
import json
import platform
import shutil
import stat
from pathlib import Path
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QLabel, QLineEdit, QPushButton, QFileDialog, QCheckBox, 
    QGroupBox, QGridLayout, QTextEdit, QMessageBox, QListWidget,
    QListWidgetItem, QTabWidget, QSplitter, QComboBox, QDialog,
    QDialogButtonBox, QFormLayout
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QObject, QTimer
from PyQt5.QtGui import QIcon, QColor, QBrush, QFont
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Headless mode flag
HEADLESS_MODE = False
if len(sys.argv) > 1 and sys.argv[1] == "--headless":
    HEADLESS_MODE = True

class HoneypotHandler(FileSystemEventHandler):
    """Custom event handler for file system events"""
    def __init__(self, callback, events_to_monitor=None):
        super().__init__()
        self.callback = callback
        self.events_to_monitor = events_to_monitor or ["created", "modified", "deleted", "moved"]
    
    def on_any_event(self, event):
        """Called for any file system event"""
        # Skip if event type not in monitoring list
        event_type = event.event_type
        if event_type not in self.events_to_monitor:
            return
            
        # Extract information from the event
        what = 'directory' if event.is_directory else 'file'
        src_path = event.src_path
        
        # For moved events, we also have a destination path
        dest_path = getattr(event, 'dest_path', None)
        
        # Send to callback
        self.callback(event_type, what, src_path, dest_path)

class HoneypotMonitor(QObject):
    """Manages the file system monitoring"""
    event_detected = pyqtSignal(str, str, str, str, str)  # event_type, what, path, dest_path, timestamp
    
    def __init__(self):
        super().__init__()
        self.observer = None
        self.handlers = {}
        self.active_honeypots = {}
    
    def start_monitoring(self, path, events_to_monitor, include_subdirectories):
        """Start monitoring a specific path"""
        if path in self.active_honeypots:
            return False  # Already monitoring
            
        try:
            # Create an observer if we don't have one
            if self.observer is None:
                self.observer = Observer()
                self.observer.start()
            
            # Create event handler
            handler = HoneypotHandler(self._on_event_callback, events_to_monitor)
            
            # Schedule monitoring
            watch = self.observer.schedule(
                handler, 
                path=path, 
                recursive=include_subdirectories
            )
            
            # Store the handler and watch
            self.active_honeypots[path] = {
                'handler': handler,
                'watch': watch,
                'events': events_to_monitor,
                'include_subdirectories': include_subdirectories
            }
            
            return True
        except Exception as e:
            logging.error(f"Failed to start monitoring {path}: {str(e)}")
            return False
    
    def stop_monitoring(self, path=None):
        """Stop monitoring a specific path or all paths"""
        if path:
            # Stop monitoring specific path
            if path in self.active_honeypots:
                self.observer.unschedule(self.active_honeypots[path]['watch'])
                del self.active_honeypots[path]
        else:
            # Stop all monitoring
            if self.observer:
                for honeypot in list(self.active_honeypots.keys()):
                    self.observer.unschedule(self.active_honeypots[honeypot]['watch'])
                self.active_honeypots.clear()
                self.observer.stop()
                self.observer.join()
                self.observer = None
    
    def _on_event_callback(self, event_type, what, src_path, dest_path):
        """Callback when an event is detected"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.event_detected.emit(event_type, what, src_path, dest_path, timestamp)

class HeadlessHoneypot:
    """Headless version of the honeypot for standalone deployments"""
    def __init__(self, config_file, log_file=None):
        self.config_file = config_file
        self.log_file = log_file
        self.monitor = HoneypotMonitor()
        self.monitor.event_detected.connect(self.log_event)
        self.honeypots = {}
        
        # Setup logging
        if log_file:
            logging.basicConfig(
                filename=log_file,
                level=logging.INFO,
                format='%(asctime)s - %(message)s'
            )
        else:
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(message)s'
            )
        
        # Load configuration
        self.load_config()
        
    def load_config(self):
        """Load honeypot configuration from file"""
        try:
            with open(self.config_file, 'r') as f:
                self.honeypots = json.load(f)
                
            # Start monitoring all configured honeypots
            for path, config in self.honeypots.items():
                events = config.get('events', [])
                include_subdirs = config.get('include_subdirs', False)
                
                if os.path.exists(path):
                    if self.monitor.start_monitoring(path, events, include_subdirs):
                        logging.info(f"Started monitoring {path}")
                    else:
                        logging.error(f"Failed to start monitoring {path}")
                else:
                    logging.warning(f"Path does not exist, skipping: {path}")
        except Exception as e:
            logging.error(f"Failed to load configuration: {str(e)}")
    
    def log_event(self, event_type, what, src_path, dest_path, timestamp):
        """Log detected events"""
        # Format the event message
        if event_type == "moved":
            message = f"{timestamp} - {what.capitalize()} {event_type}: {src_path} -> {dest_path}"
        else:
            message = f"{timestamp} - {what.capitalize()} {event_type}: {src_path}"
        
        # Log the event
        logging.info(message)
        
        # Get the honeypot configuration for this path
        honeypot_path = None
        for path in self.honeypots:
            if src_path.startswith(path):
                honeypot_path = path
                break
                
        if not honeypot_path:
            return
            
        # Perform the configured action
        action_type = self.honeypots[honeypot_path].get('action_type', "Log Only")
        
        if action_type == "Run Command":
            command = self.honeypots[honeypot_path].get('command', "")
            if command:
                try:
                    # Replace placeholders with actual values
                    command = command.replace("%path%", src_path)
                    command = command.replace("%type%", event_type)
                    command = command.replace("%what%", what)
                    if dest_path:
                        command = command.replace("%dest%", dest_path)
                    
                    # Execute the command
                    import subprocess
                    subprocess.Popen(command, shell=True)
                    
                    logging.info(f"Executed command: {command}")
                except Exception as e:
                    logging.error(f"Command execution error: {str(e)}")

class DeploymentDialog(QDialog):
    """Dialog for configuring the deployment payload options"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Create Deployable Payload")
        self.setMinimumWidth(400)
        
        layout = QVBoxLayout(self)
        
        # Form layout for options
        form_layout = QFormLayout()
        
        # Output path
        self.output_path = QLineEdit()
        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self.browse_output)
        
        path_layout = QHBoxLayout()
        path_layout.addWidget(self.output_path)
        path_layout.addWidget(browse_button)
        form_layout.addRow("Output Directory:", path_layout)
        
        # Log file path
        self.log_path = QLineEdit()
        self.log_path.setText("honeypot_events.log")
        form_layout.addRow("Log File Name:", self.log_path)
        
        # Auto-start options
        self.autostart_check = QCheckBox("Configure to run at system startup")
        self.autostart_check.setChecked(True)
        form_layout.addRow("", self.autostart_check)
        
        # OS specific setup warning
        system = platform.system()
        if system == "Darwin":
            startup_method = "LaunchAgent"
        elif system == "Windows":
            startup_method = "Registry/Startup Folder"
        else:  # Linux
            startup_method = "systemd user service"
            
        self.startup_label = QLabel(f"Will configure startup using {startup_method}")
        form_layout.addRow("", self.startup_label)
        
        layout.addLayout(form_layout)
        
        # Note about elevated privileges
        note = QLabel("Note: Setting up auto-start may require administrative privileges.")
        note.setStyleSheet("color: #666;")
        layout.addWidget(note)
        
        # Buttons
        self.buttons = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel,
            Qt.Horizontal, self)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)
    
    def browse_output(self):
        """Browse for output directory"""
        directory = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if directory:
            self.output_path.setText(directory)

class HoneypotUI(QMainWindow):
    """Main UI Window for Honeypot Tool"""
    def __init__(self):
        super().__init__()
        self.monitor = HoneypotMonitor()
        self.monitor.event_detected.connect(self.log_event)
        self.honeypots = {}  # Store honeypot configurations
        self.initUI()
    
    def initUI(self):
        """Initialize the UI"""
        self.setWindowTitle("Honeypot File Monitor")
        self.setMinimumSize(800, 600)
        
        # Central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create splitter for two panels
        splitter = QSplitter(Qt.Horizontal)
        
        # Left panel: Configuration
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        
        # Honeypot configuration section
        config_group = QGroupBox("Honeypot Configuration")
        config_layout = QGridLayout()
        
        # Target Selection
        config_layout.addWidget(QLabel("Target Path:"), 0, 0)
        self.path_edit = QLineEdit()
        config_layout.addWidget(self.path_edit, 0, 1)
        
        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self.browse_path)
        config_layout.addWidget(browse_button, 0, 2)
        
        # Events to monitor
        config_layout.addWidget(QLabel("Events to Monitor:"), 1, 0)
        
        events_widget = QWidget()
        events_layout = QHBoxLayout(events_widget)
        events_layout.setContentsMargins(0, 0, 0, 0)
        
        self.event_created = QCheckBox("Created")
        self.event_created.setChecked(True)
        self.event_modified = QCheckBox("Modified")
        self.event_modified.setChecked(True)
        self.event_deleted = QCheckBox("Deleted")
        self.event_deleted.setChecked(True)
        self.event_moved = QCheckBox("Moved")
        self.event_moved.setChecked(True)
        
        events_layout.addWidget(self.event_created)
        events_layout.addWidget(self.event_modified)
        events_layout.addWidget(self.event_deleted)
        events_layout.addWidget(self.event_moved)
        events_layout.addStretch()
        
        config_layout.addWidget(events_widget, 1, 1, 1, 2)
        
        # Include subdirectories
        config_layout.addWidget(QLabel("Include Subdirectories:"), 2, 0)
        self.subdirs_check = QCheckBox()
        config_layout.addWidget(self.subdirs_check, 2, 1)
        
        # Action when detected section
        config_layout.addWidget(QLabel("Action on Detection:"), 3, 0)
        self.action_combo = QComboBox()
        self.action_combo.addItems(["Log Only", "Alert (Message Box)", "Run Command"])
        config_layout.addWidget(self.action_combo, 3, 1)
        
        # Command to run (if action is "Run Command")
        config_layout.addWidget(QLabel("Command:"), 4, 0)
        self.command_edit = QLineEdit()
        self.command_edit.setPlaceholderText("Command to run when event detected")
        config_layout.addWidget(self.command_edit, 4, 1, 1, 2)
        
        config_group.setLayout(config_layout)
        
        # Buttons for adding and managing honeypots
        button_layout = QHBoxLayout()
        
        self.add_button = QPushButton("Add Honeypot")
        self.add_button.clicked.connect(self.add_honeypot)
        
        self.remove_button = QPushButton("Remove Selected")
        self.remove_button.clicked.connect(self.remove_honeypot)
        self.remove_button.setEnabled(False)
        
        button_layout.addWidget(self.add_button)
        button_layout.addWidget(self.remove_button)
        
        left_layout.addWidget(config_group)
        left_layout.addLayout(button_layout)
        
        # Honeypot list
        list_group = QGroupBox("Active Honeypots")
        list_layout = QVBoxLayout()
        
        self.honeypot_list = QListWidget()
        self.honeypot_list.itemSelectionChanged.connect(self.on_honeypot_selected)
        list_layout.addWidget(self.honeypot_list)
        
        list_group.setLayout(list_layout)
        left_layout.addWidget(list_group)
        
        # Export deployable payload button
        self.export_button = QPushButton("Create Deployable Payload")
        self.export_button.clicked.connect(self.create_deployable_payload)
        left_layout.addWidget(self.export_button)
        
        # Right panel: Event log
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        
        log_group = QGroupBox("Event Log")
        log_layout = QVBoxLayout()
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        font = QFont("Courier New", 10)
        self.log_text.setFont(font)
        log_layout.addWidget(self.log_text)
        
        # Clear log button
        clear_button = QPushButton("Clear Log")
        clear_button.clicked.connect(self.clear_log)
        log_layout.addWidget(clear_button)
        
        log_group.setLayout(log_layout)
        right_layout.addWidget(log_group)
        
        # Add panels to splitter
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        
        # Set initial sizes
        splitter.setSizes([300, 500])
        
        # Add splitter to main layout
        main_layout.addWidget(splitter)
        
        # Status bar
        self.statusBar().showMessage("Ready")
        
        # Connect action combo to enable/disable command edit
        self.action_combo.currentTextChanged.connect(self.update_command_visibility)
        self.update_command_visibility(self.action_combo.currentText())
        
        # Show UI
        self.show()
    
    def update_command_visibility(self, text):
        """Enable or disable command edit based on action selection"""
        self.command_edit.setEnabled(text == "Run Command")
        if text != "Run Command":
            self.command_edit.setPlaceholderText("Command to run when event detected (disabled)")
        else:
            self.command_edit.setPlaceholderText("Command to run when event detected")
    
    def browse_path(self):
        """Open file dialog to select monitoring target"""
        path = QFileDialog.getExistingDirectory(self, "Select Directory") or \
               QFileDialog.getOpenFileName(self, "Select File")[0]
        
        if path:
            self.path_edit.setText(path)
    
    def add_honeypot(self):
        """Add a new honeypot configuration"""
        path = self.path_edit.text().strip()
        
        if not path:
            QMessageBox.warning(self, "Error", "Please specify a path to monitor.")
            return
            
        if not os.path.exists(path):
            QMessageBox.warning(self, "Error", f"The path '{path}' does not exist.")
            return
            
        if path in self.honeypots:
            QMessageBox.warning(self, "Error", f"Already monitoring '{path}'.")
            return
        
        # Collect selected events
        events = []
        if self.event_created.isChecked():
            events.append("created")
        if self.event_modified.isChecked():
            events.append("modified")
        if self.event_deleted.isChecked():
            events.append("deleted")
        if self.event_moved.isChecked():
            events.append("moved")
            
        if not events:
            QMessageBox.warning(self, "Error", "Please select at least one event to monitor.")
            return
        
        include_subdirs = self.subdirs_check.isChecked()
        action_type = self.action_combo.currentText()
        command = self.command_edit.text() if action_type == "Run Command" else ""
        
        # Save honeypot configuration
        self.honeypots[path] = {
            'events': events,
            'include_subdirs': include_subdirs,
            'action_type': action_type,
            'command': command
        }
        
        # Start monitoring
        if self.monitor.start_monitoring(path, events, include_subdirs):
            # Add to list view
            item = QListWidgetItem(f"{path} ({', '.join(events)})")
            item.setData(Qt.UserRole, path)  # Store path as user data
            self.honeypot_list.addItem(item)
            
            self.log_text.append(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Started monitoring {path}")
            self.statusBar().showMessage(f"Now monitoring {path}")
        else:
            QMessageBox.critical(self, "Error", f"Failed to start monitoring {path}.")
            del self.honeypots[path]
    
    def remove_honeypot(self):
        """Remove selected honeypot"""
        selected_items = self.honeypot_list.selectedItems()
        
        if not selected_items:
            return
            
        for item in selected_items:
            path = item.data(Qt.UserRole)
            self.monitor.stop_monitoring(path)
            del self.honeypots[path]
            self.honeypot_list.takeItem(self.honeypot_list.row(item))
            
            self.log_text.append(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Stopped monitoring {path}")
        
        self.statusBar().showMessage("Honeypot(s) removed")
        self.remove_button.setEnabled(False)
    
    def on_honeypot_selected(self):
        """Handle honeypot selection in list"""
        self.remove_button.setEnabled(len(self.honeypot_list.selectedItems()) > 0)
    
    def log_event(self, event_type, what, src_path, dest_path, timestamp):
        """Log a detected event"""
        # Format the event message
        if event_type == "moved":
            message = f"[{timestamp}] {what.capitalize()} {event_type}: {src_path} -> {dest_path}"
        else:
            message = f"[{timestamp}] {what.capitalize()} {event_type}: {src_path}"
        
        # Add to log
        self.log_text.append(message)
        
        # Get the honeypot configuration for this path
        honeypot_path = None
        for path in self.honeypots:
            if src_path.startswith(path):
                honeypot_path = path
                break
                
        if not honeypot_path:
            return
            
        # Perform the configured action
        action_type = self.honeypots[honeypot_path]['action_type']
        
        if action_type == "Alert (Message Box)":
            # Use a QTimer to show the message box after a short delay
            # This prevents blocking the UI thread during rapid events
            QTimer.singleShot(100, lambda: QMessageBox.information(
                self, "Honeypot Alert", message))
        elif action_type == "Run Command":
            command = self.honeypots[honeypot_path]['command']
            if command:
                try:
                    # Replace placeholders with actual values
                    command = command.replace("%path%", src_path)
                    command = command.replace("%type%", event_type)
                    command = command.replace("%what%", what)
                    if dest_path:
                        command = command.replace("%dest%", dest_path)
                    
                    # Execute the command
                    import subprocess
                    subprocess.Popen(command, shell=True)
                    
                    self.log_text.append(f"[{timestamp}] Executed command: {command}")
                except Exception as e:
                    self.log_text.append(f"[{timestamp}] Command execution error: {str(e)}")
    
    def clear_log(self):
        """Clear the event log"""
        self.log_text.clear()
    
    def create_deployable_payload(self):
        """Create a deployable payload script and auto-start configuration"""
        # Check if there are any honeypots configured
        if not self.honeypots:
            QMessageBox.warning(self, "Error", "No honeypots configured. Add at least one honeypot before creating a payload.")
            return
        
        # Open deployment configuration dialog
        dialog = DeploymentDialog(self)
        if dialog.exec_() != QDialog.Accepted:
            return
        
        # Get configuration
        output_dir = dialog.output_path.text().strip()
        if not output_dir:
            QMessageBox.warning(self, "Error", "Please specify an output directory.")
            return
            
        if not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to create output directory: {str(e)}")
                return
        
        log_file = dialog.log_path.text().strip()
        autostart = dialog.autostart_check.isChecked()
        
        try:
            # 1. Save honeypot configuration
            config_path = os.path.join(output_dir, "honeypot_config.json")
            with open(config_path, 'w') as f:
                json.dump(self.honeypots, f, indent=2)
            
            # 2. Create standalone runner script
            runner_path = os.path.join(output_dir, "honeypot_runner.py")
            self._create_runner_script(runner_path, config_path, log_file)
            
            # 3. Set up auto-start if requested
            if autostart:
                self._setup_autostart(output_dir, runner_path, log_file)
            
            # 4. Create README file
            readme_path = os.path.join(output_dir, "README.txt")
            self._create_readme(readme_path, runner_path, config_path, log_file, autostart)
            
            QMessageBox.information(self, "Success", 
                                    f"Deployable payload created in {output_dir}\n\n"
                                    f"You can now deploy this to the target system.")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to create deployable payload: {str(e)}")
    
    def _create_runner_script(self, script_path, config_path, log_file):
        """Create the standalone runner script"""
        # Get the current script path
        current_script = os.path.abspath(__file__)
        
        # Create a copy of the current script
        shutil.copy2(current_script, script_path)
        
        # Make the script executable
        os.chmod(script_path, os.stat(script_path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        
        # Add runner code at the bottom of the script
        with open(script_path, 'a') as f:
            f.write("\n\n# Auto-generated runner code\n")
            f.write("if __name__ == \"__main__\" and '--headless' in sys.argv:\n")
            f.write("    # Get the directory where this script is located\n")
            f.write("    script_dir = os.path.dirname(os.path.abspath(__file__))\n")
            f.write("    # Convert relative paths to absolute\n")
            f.write(f"    config_file = os.path.join(script_dir, '{os.path.basename(config_path)}')\n")
            f.write(f"    log_file = os.path.join(script_dir, '{log_file}')\n")
            f.write("    # Start headless honeypot\n")
            f.write("    honeypot = HeadlessHoneypot(config_file, log_file)\n")
            f.write("    # Keep the script running\n")
            f.write("    try:\n")
            f.write("        while True:\n")
            f.write("            time.sleep(1)\n")
            f.write("    except KeyboardInterrupt:\n")
            f.write("        print('Honeypot monitoring stopped')\n")
    
    def _setup_autostart(self, output_dir, runner_path, log_file):
        """Set up auto-start for the runner script based on the OS"""
        system = platform.system()
        
        if system == "Darwin":  # macOS
            # Create a macOS Launch Agent plist file
            plist_path = os.path.join(output_dir, "com.user.honeypot.plist")
            
            plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.user.honeypot</string>
    <key>ProgramArguments</key>
    <array>
        <string>{runner_path}</string>
        <string>--headless</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{os.path.join(output_dir, 'honeypot_stdout.log')}</string>
    <key>StandardErrorPath</key>
    <string>{os.path.join(output_dir, 'honeypot_stderr.log')}</string>
</dict>
</plist>
"""
            
            with open(plist_path, 'w') as f:
                f.write(plist_content)
                
        elif system == "Windows":  # Windows
            # Create a batch file for the startup folder
            batch_path = os.path.join(output_dir, "start_honeypot.bat")
            
            batch_content = f"""@echo off
cd /d "{output_dir}"
start pythonw "{runner_path}" --headless
"""
            
            with open(batch_path, 'w') as f:
                f.write(batch_content)
                
            # Create a registry script
            reg_path = os.path.join(output_dir, "register_honeypot.reg")
            
            # Use double backslashes for Windows paths in registry
            win_path = batch_path.replace('/', '\\').replace('\\', '\\\\')
            
            reg_content = f"""Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run]
"HoneypotMonitor"="{win_path}"
"""
            
            with open(reg_path, 'w') as f:
                f.write(reg_content)
                
        else:  # Linux
            # Create a systemd user service file
            service_path = os.path.join(output_dir, "honeypot.service")
            
            service_content = f"""[Unit]
Description=Honeypot File System Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 {runner_path} --headless
WorkingDirectory={output_dir}
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
"""
            
            with open(service_path, 'w') as f:
                f.write(service_content)
    
    def _create_readme(self, readme_path, runner_path, config_path, log_file, autostart):
        """Create a README file with deployment instructions"""
        system = platform.system()
        
        # Common instructions
        instructions = f"""Honeypot File Monitor - Deployment Package
===================================

This package contains a deployable version of the Honeypot File Monitor.

Files included:
- honeypot_runner.py: The main script that runs the monitoring service
- honeypot_config.json: Configuration file with honeypot definitions
- {log_file}: Log file where events will be recorded

Manual Start:
To manually start the monitoring, run:
python honeypot_runner.py --headless

"""
        
        # OS-specific auto-start instructions
        if autostart:
            if system == "Darwin":  # macOS
                instructions += """
Auto-start Setup (macOS):
1. Copy the com.user.honeypot.plist file to ~/Library/LaunchAgents/
   cp com.user.honeypot.plist ~/Library/LaunchAgents/
2. Load the launch agent:
   launchctl load ~/Library/LaunchAgents/com.user.honeypot.plist
3. To stop the service:
   launchctl unload ~/Library/LaunchAgents/com.user.honeypot.plist
"""
            elif system == "Windows":  # Windows
                instructions += """
Auto-start Setup (Windows):
Option 1 - Startup Folder:
1. Copy the start_honeypot.bat file to the Windows Startup folder
   (Press Win+R, type 'shell:startup' and press Enter)

Option 2 - Registry:
1. Double-click the register_honeypot.reg file and confirm the dialog
2. This will add the honeypot to your Windows startup programs
"""
            else:  # Linux
                instructions += """
Auto-start Setup (Linux):
1. Copy the honeypot.service file to your systemd user directory:
   mkdir -p ~/.config/systemd/user/
   cp honeypot.service ~/.config/systemd/user/
2. Reload systemd user configuration:
   systemctl --user daemon-reload
3. Enable and start the service:
   systemctl --user enable honeypot.service
   systemctl --user start honeypot.service
4. Check status with:
   systemctl --user status honeypot.service
"""
        
        # Save the README file
        with open(readme_path, 'w') as f:
            f.write(instructions)
    
    def closeEvent(self, event):
        """Handle window close event"""
        # Stop all monitoring
        self.monitor.stop_monitoring()
        event.accept()

def main():
    # Check for headless mode
    if HEADLESS_MODE:
        # Determine config and log file paths
        config_file = None
        log_file = None
        
        for i, arg in enumerate(sys.argv):
            if arg == "--config" and i + 1 < len(sys.argv):
                config_file = sys.argv[i + 1]
            elif arg == "--log" and i + 1 < len(sys.argv):
                log_file = sys.argv[i + 1]
        
        # Use default paths if not specified
        if not config_file:
            config_file = "honeypot_config.json"
        
        # Start headless mode
        honeypot = HeadlessHoneypot(config_file, log_file)
        
        # Keep the script running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("Honeypot monitoring stopped")
    else:
        # Start in GUI mode
        app = QApplication(sys.argv)
        app.setStyle('Fusion')  # Use Fusion style for a modern look
        ui = HoneypotUI()
        sys.exit(app.exec_())

if __name__ == "__main__":
    main() 