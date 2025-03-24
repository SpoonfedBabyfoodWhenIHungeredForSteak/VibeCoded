# Service Enumerator

A network service scanning tool with a user-friendly GUI that allows you to scan target IP addresses for open ports and identify running services.

## Features

- Scan target IP addresses for open ports and service information
- Flexible port selection (common ports, all ports, or custom ranges)
- Adjustable scan speed/intensity
- OS detection capability (requires admin/root privileges)
- Script scanning options for more detailed service information
- Service interaction capabilities for remote command execution
- Real-time scan progress with port information
- Comprehensive results display with sortable tables
- Save scan logs in text format
- Export scan results to CSV for further analysis
- Complete scan history management
- Cross-platform compatibility (Windows, macOS, Linux)

## Requirements

- Python 3.6 or higher
- PyQt5 (GUI framework)
- python-nmap (Nmap wrapper for Python)
- paramiko (for SSH connections in service interaction feature)
- Nmap (must be installed on your system)

## Installation

1. Clone or download this repository
2. Install the required Python dependencies:
```
pip install -r requirements.txt
```
3. Make sure Nmap is installed on your system:
   - **Windows**: Download and install from [nmap.org](https://nmap.org/download.html)
   - **macOS**: Install via Homebrew with `brew install nmap`
   - **Linux**: Install via package manager, e.g., `sudo apt install nmap`

## Usage

1. Run the application:
```
python serviceenumerator.py
```

2. **Scan Tab**:
   - Enter a target IP address or hostname
   - Select port range (Common Ports, All Ports, or Custom Range)
   - Choose scan speed/intensity
   - Enable additional options if desired (OS Detection, Script Scanning, Service Interaction)
   - Click "Start Scan" to begin

3. **History Tab**:
   - View all previous scans
   - Click on any scan to view its details
   - Export historical scan data as text or CSV
   - Clear history when no longer needed

## Scan Options

- **Port Selection**:
  - Common Ports: Scans the most commonly used ports (1-1000)
  - All Ports: Scans all possible ports (1-65535)
  - Custom Range: Specify your own port range

- **Scan Speed**:
  - Stealthy: Very slow, minimal footprint (nmap -T0)
  - Sneaky: Slower than normal (nmap -T1)
  - Polite: Slows down to consume less bandwidth (nmap -T2)
  - Normal: Default nmap timing (nmap -T3)
  - Aggressive: Faster scan, assumes a fast and reliable network (nmap -T4)

- **Additional Options**:
  - OS Detection: Attempts to determine the operating system (requires admin/root privileges)
  - Script Scanning: Runs default nmap scripts for additional service details
  - Service Interaction: Enables the ability to execute commands on remote services (requires authentication)

## Service Interaction

When Service Interaction is enabled, you can:
- Right-click on any service in the results table
- Choose "Execute Command on Service" from the context menu
- Select from predefined commands or enter a custom command
- Enter authentication credentials for the remote system
- View real-time command execution status and output

Available command types:
- Restart Service: Attempts to restart the selected service
- Check Service Status: Shows the current status of the service
- Custom Command: Execute any command with {service} placeholder for the service name

**Security Note**: Service interaction requires elevated privileges on the target system and should be used responsibly.

## CSV Export Format

The CSV export includes the following columns:
- Target
- Port
- Protocol
- State
- Service
- Product
- Version
- Extra Info
- Scan Time

This format facilitates easy import into spreadsheets or other analysis tools.

## Security and Legal Considerations

- Only scan networks you have permission to scan
- Some scan types (particularly aggressive ones) might trigger security systems
- Use this tool responsibly and ethically
- Running with administrator/root privileges is only required for OS detection
- Service interaction features should only be used on systems you are authorized to manage

## License

This project is licensed under the MIT License - see the LICENSE file for details. 