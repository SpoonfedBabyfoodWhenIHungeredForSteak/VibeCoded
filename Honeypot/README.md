# Honeypot File System Monitor

A powerful and flexible file system monitoring tool that allows you to create "honeypots" - monitored locations that alert you when specified file system activities occur.

![Honeypot Monitor](honeypot_screenshot.png)

## Features

- **Real-time Monitoring**: Track file system events (creation, modification, deletion, moves) in real-time
- **Multiple Honeypots**: Set up multiple monitoring locations with different configurations
- **Selective Event Monitoring**: Choose which events to track for each honeypot
- **Recursive Monitoring**: Option to monitor subdirectories
- **Customizable Actions**: Configure different responses to detected events:
  - Simple logging
  - Alert popups
  - Execute custom commands
- **Deployable Payload**: Create standalone deployable packages for persistent monitoring
- **Auto-startup**: Configure the monitoring to start automatically on system boot
- **Cross-platform**: Works on Windows, macOS, and Linux

## Installation

### Requirements

- Python 3.6 or higher
- PyQt5 (for GUI)
- watchdog (for filesystem monitoring)

### Installation Steps

1. Clone or download this repository
2. Install the required dependencies:
```
pip install -r requirements.txt
```

## Usage

### Starting the Application

Run the application with:
```
python honeypot.py
```

Or make it executable and run directly:
```
chmod +x honeypot.py
./honeypot.py
```

### Setting Up a Honeypot

1. **Select Target Path**: Choose a file or directory to monitor
2. **Select Events**: Choose which events to monitor (Created, Modified, Deleted, Moved)
3. **Configure Subdirectory Monitoring**: Enable to monitor all subdirectories
4. **Select Action**: Choose what happens when an event is detected:
   - Log Only: Just record the event
   - Alert: Show a popup message
   - Run Command: Execute a custom command
5. **Click "Add Honeypot"**

### Command Placeholders

When using the "Run Command" action, you can use the following placeholders:
- `%path%`: The path where the event occurred
- `%type%`: The type of event (created, modified, deleted, moved)
- `%what%`: Whether it was a file or directory
- `%dest%`: The destination path (for moved events only)

For example: `python notify.py "%type%" "%path%"`

## Creating Deployable Payloads

The Honeypot application can generate deployable packages that can run independently and start automatically on system boot:

1. Configure one or more honeypots
2. Click "Create Deployable Payload"
3. Select an output directory
4. Configure log file name and auto-start options
5. Click "Ok"

### Deployment Structure

The generated deployment package includes:
- `honeypot_runner.py`: The executable script
- `honeypot_config.json`: Configuration file
- `README.txt`: Installation instructions
- OS-specific auto-start files:
  - **Windows**: `.bat` and `.reg` files
  - **macOS**: LaunchAgent `.plist` file
  - **Linux**: systemd `.service` file

### Installing a Deployment Package

Detailed instructions are included in the generated `README.txt` file, which provides OS-specific guidance for:
- Manual execution
- Setting up auto-start
- Verifying installation

## Security Considerations

- The honeypot runs with the same permissions as the user who starts it
- For monitoring system directories, elevated privileges may be required
- The "Run Command" feature executes commands with the same privileges as the honeypot process
- Consider the security implications of auto-starting the honeypot in multi-user environments

## Use Cases

- **Security Monitoring**: Detect unauthorized file access or modifications
- **Change Tracking**: Monitor configuration files for changes
- **Debugging**: Identify which processes are modifying specific files
- **Forensics**: Collect information about file system activities during specific periods
- **Honeypot Trap**: Set up decoy files to detect intrusion attempts

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

- [watchdog](https://github.com/gorakhargosh/watchdog) for file system event monitoring
- [PyQt5](https://www.riverbankcomputing.com/software/pyqt/) for the user interface 