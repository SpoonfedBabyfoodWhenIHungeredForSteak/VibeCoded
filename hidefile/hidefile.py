#!/usr/bin/env python3
"""
HideFile GUI - A graphical user interface for embedding files inside PNG images
and extracting them back.

This GUI application implements a steganography tool that allows users to hide
files inside PNG images without visibly altering them. It uses a technique that
embeds data in the PNG file structure rather than altering pixel data.

The embedding works by appending the file data to the last IDAT chunk of 
the PNG, recalculating the CRC, and updating the chunk length. This technique
preserves the visual appearance of the PNG while secretly storing the data.
"""

import os
import sys
import json
import binascii
import struct
import zlib
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QFileDialog, QMessageBox, QProgressBar,
    QGroupBox, QFormLayout, QSpacerItem, QSizePolicy, QTextEdit, QToolBar, 
    QAction, QStatusBar, QStyle, QCheckBox, QInputDialog, QFrame
)
from PyQt5.QtGui import QPixmap, QIcon, QPalette, QColor, QDragEnterEvent, QDropEvent
from PyQt5.QtCore import Qt, QSize, QSettings, QMimeData, QUrl

# PNG magic bytes (header)
PNG_MAGIC = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])


def compute_crc(data):
    """Compute CRC32 of data (same algorithm used in PNG)"""
    return binascii.crc32(data) & 0xFFFFFFFF


def read_int_be(data, offset):
    """Read a 4-byte big-endian integer from data at the given offset"""
    return struct.unpack('>I', data[offset:offset+4])[0]


def write_int_be(value):
    """Convert an integer to 4-byte big-endian format"""
    return struct.pack('>I', value)


def parse_png_chunks(png_data):
    """Parse PNG data into a list of chunks"""
    if png_data[:8] != PNG_MAGIC:
        raise ValueError("Not a valid PNG file (bad magic bytes)")
    
    chunks = []
    pos = 8  # Start after PNG magic bytes
    
    while pos < len(png_data):
        # Check if we have enough bytes left
        if pos + 12 > len(png_data):
            break
            
        # Read chunk length (4 bytes)
        chunk_len = read_int_be(png_data, pos)
        pos += 4
        
        # Read chunk type (4 bytes)
        chunk_type = png_data[pos:pos+4].decode('ascii')
        pos += 4
        
        # Read chunk data
        chunk_data = png_data[pos:pos+chunk_len]
        pos += chunk_len
        
        # Read CRC (4 bytes)
        chunk_crc = png_data[pos:pos+4]
        pos += 4
        
        chunks.append({
            'length': chunk_len,
            'type': chunk_type,
            'data': chunk_data,
            'crc': chunk_crc
        })
        
        # Stop parsing if we hit the IEND chunk
        if chunk_type == 'IEND':
            break
    
    return chunks


def derive_key(password, salt=None):
    """Derive an encryption key from a password"""
    if salt is None:
        # Generate a random salt if not provided
        salt = os.urandom(16)
    
    # Use PBKDF2 to derive a key from the password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes for AES-256
        salt=salt,
        iterations=100000,  # High number of iterations for security
    )
    key = kdf.derive(password.encode('utf-8'))
    
    return key, salt


def encrypt_data(data, password):
    """Encrypt data using AES-GCM with a password-derived key"""
    # Generate a random 96-bit IV/nonce
    nonce = os.urandom(12)
    
    # Derive encryption key from password
    key, salt = derive_key(password)
    
    # Encrypt with AES-GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    
    # Combine salt + nonce + ciphertext for storage
    encrypted_data = salt + nonce + ciphertext
    
    return encrypted_data


def decrypt_data(encrypted_data, password):
    """Decrypt data that was encrypted with AES-GCM"""
    # Extract components
    salt = encrypted_data[:16]
    nonce = encrypted_data[16:28]
    ciphertext = encrypted_data[28:]
    
    # Derive the key using the stored salt
    key, _ = derive_key(password, salt)
    
    # Decrypt
    aesgcm = AESGCM(key)
    data = aesgcm.decrypt(nonce, ciphertext, None)
    
    return data


def embed_file_in_png(cover_png_path, input_file_path, output_png_path, encrypt=False, password=None):
    """Embed a file inside a PNG image with optional encryption"""
    # Read input files
    with open(cover_png_path, 'rb') as f:
        png_data = f.read()
    
    with open(input_file_path, 'rb') as f:
        file_data = f.read()
    
    # Encrypt file data if requested
    if encrypt and password:
        file_data = encrypt_data(file_data, password)
    
    # Parse PNG chunks
    chunks = parse_png_chunks(png_data)
    
    # Find the last IDAT chunk
    last_idat_index = -1
    for i, chunk in enumerate(chunks):
        if chunk['type'] == 'IDAT':
            last_idat_index = i
    
    if last_idat_index == -1:
        raise ValueError("No IDAT chunk found in the PNG file")
    
    # Get the last IDAT chunk
    idat_chunk = chunks[last_idat_index]
    
    # Create metadata about the file
    file_name = os.path.basename(input_file_path)
    file_size = len(file_data)
    file_time = int(os.path.getmtime(input_file_path))
    
    # Create a metadata dictionary
    metadata = {
        'name': file_name,
        'size': file_size,
        'time': file_time,
        'type': os.path.splitext(file_name)[1],
        'encrypted': encrypt  # Add encryption status to metadata
    }
    
    # Serialize metadata to JSON
    metadata_json = json.dumps(metadata).encode('utf-8')
    
    # Create a marker to identify where our data begins
    # Format: MAGIC_MARKER (8 bytes) + metadata_length (4 bytes) + metadata + file_data
    MAGIC_MARKER = b'HIDEFILE'
    
    # Prepare the complete payload
    metadata_length = len(metadata_json)
    payload = (
        MAGIC_MARKER +
        struct.pack('>I', metadata_length) +  # 4-byte big-endian length
        metadata_json +
        file_data
    )
    
    # Create a new data block with payload appended
    new_data = idat_chunk['data'] + payload
    
    # Create new chunk type plus data for CRC calculation
    type_plus_data = bytes(idat_chunk['type'], 'ascii') + new_data
    
    # Compute new CRC
    new_crc = compute_crc(type_plus_data)
    
    # Update the chunk
    chunks[last_idat_index]['data'] = new_data
    chunks[last_idat_index]['length'] = len(new_data)
    chunks[last_idat_index]['crc'] = write_int_be(new_crc)
    
    # Write the modified PNG
    with open(output_png_path, 'wb') as f:
        # Write PNG magic
        f.write(PNG_MAGIC)
        
        # Write all chunks
        for chunk in chunks:
            # Write chunk length
            f.write(write_int_be(chunk['length']))
            
            # Write chunk type
            f.write(bytes(chunk['type'], 'ascii'))
            
            # Write chunk data
            f.write(chunk['data'])
            
            # Write chunk CRC
            f.write(chunk['crc'])
    
    print(f"File successfully embedded in {output_png_path}")
    print(f"Original PNG: {os.path.getsize(cover_png_path)} bytes")
    print(f"File size: {os.path.getsize(input_file_path)} bytes")
    print(f"Output PNG: {os.path.getsize(output_png_path)} bytes")
    print(f"Embedded file info: {metadata}")
    if encrypt:
        print("File was encrypted before embedding")


def extract_file_from_png(steganographic_png_path, output_dir, password=None):
    """Extract a hidden file from a PNG image with optional decryption
    
    Args:
        steganographic_png_path: Path to PNG file containing hidden data
        output_dir: Directory where the extracted file will be saved
        password: Optional password for decryption
        
    Returns:
        The full path of the extracted file
    """
    # Read the PNG file
    with open(steganographic_png_path, 'rb') as f:
        png_data = f.read()
    
    # Parse PNG chunks
    chunks = parse_png_chunks(png_data)
    
    # Check each IDAT chunk (but focus on the last one which is most likely)
    idat_chunks = [chunk for chunk in chunks if chunk['type'] == 'IDAT']
    if not idat_chunks:
        raise ValueError("No IDAT chunks found in the PNG")
    
    # Start with the last IDAT as most likely location
    idat_chunks.reverse()
    
    # Define the magic marker we're looking for
    MAGIC_MARKER = b'HIDEFILE'
    
    # Search for the magic marker in each IDAT chunk
    for idat_chunk in idat_chunks:
        data = idat_chunk['data']
        marker_pos = data.find(MAGIC_MARKER)
        
        if marker_pos != -1:
            # Found the marker - now extract the metadata and file
            data_pos = marker_pos + len(MAGIC_MARKER)
            
            # Extract metadata length (4 bytes big-endian integer)
            metadata_length = struct.unpack('>I', data[data_pos:data_pos+4])[0]
            data_pos += 4
            
            # Extract metadata as JSON
            metadata_json = data[data_pos:data_pos+metadata_length]
            try:
                metadata = json.loads(metadata_json.decode('utf-8'))
                data_pos += metadata_length
                
                # Extract the actual file data
                file_data = data[data_pos:]
                
                # Check if file is encrypted and decrypt if needed
                if metadata.get('encrypted', False):
                    if not password:
                        raise ValueError("This file is encrypted and requires a password to decrypt")
                    
                    try:
                        file_data = decrypt_data(file_data, password)
                    except Exception as e:
                        raise ValueError(f"Decryption failed. The password may be incorrect: {str(e)}")
                
                # Use the original filename from metadata
                original_filename = metadata.get('name', 'extracted_file')
                output_file_path = os.path.join(output_dir, original_filename)
                
                # Write the data to the output file
                with open(output_file_path, 'wb') as f:
                    f.write(file_data)
                
                print(f"Extracted file data to {output_file_path} ({len(file_data)} bytes)")
                print(f"Original file info: {metadata}")
                print(f"Successfully restored original filename: {original_filename}")
                
                return output_file_path
                
            except json.JSONDecodeError:
                print("Warning: Found marker but metadata is corrupted. Trying alternative extraction...")
                # If metadata is corrupted, still try to extract the file data
                file_data = data[data_pos+metadata_length:]
                
                # Use a generic filename if metadata is corrupted
                output_file_path = os.path.join(output_dir, "extracted_file_unknown_type")
                with open(output_file_path, 'wb') as f:
                    f.write(file_data)
                print(f"Extracted file data to {output_file_path} (metadata corrupted)")
                return output_file_path
    
    # If we get here, we couldn't find the marker
    raise ValueError("Could not find hidden file data in the PNG image. This file may not contain hidden data, or it was created with a different version of this tool.")


class DropArea(QLabel):
    """Custom widget that accepts file drops and displays a preview or a message."""
    
    def __init__(self, parent=None, message="Drop files here", accept_png_only=False, on_drop=None):
        super().__init__(parent)
        self.setAlignment(Qt.AlignCenter)
        self.setMinimumHeight(200)
        self.setStyleSheet("border: 2px dashed #aaaaaa; border-radius: 5px; padding: 5px;")
        self.setText(message)
        self.setAcceptDrops(True)
        self.accept_png_only = accept_png_only
        self.on_drop = on_drop
        
    def dragEnterEvent(self, event: QDragEnterEvent):
        """Handle drag enter event - check if it contains URLs/files."""
        if event.mimeData().hasUrls():
            # If we only accept PNGs, check file extensions
            if self.accept_png_only:
                for url in event.mimeData().urls():
                    if url.toLocalFile().lower().endswith('.png'):
                        event.acceptProposedAction()
                        self.setStyleSheet("border: 2px dashed #55aa55; border-radius: 5px; padding: 5px;")
                        return
            else:
                event.acceptProposedAction()
                self.setStyleSheet("border: 2px dashed #55aa55; border-radius: 5px; padding: 5px;")
    
    def dragLeaveEvent(self, event):
        """Handle drag leave event - reset appearance."""
        self.setStyleSheet("border: 2px dashed #aaaaaa; border-radius: 5px; padding: 5px;")
        
    def dropEvent(self, event: QDropEvent):
        """Handle drop event - process the dropped files."""
        self.setStyleSheet("border: 2px dashed #aaaaaa; border-radius: 5px; padding: 5px;")
        
        urls = event.mimeData().urls()
        if not urls:
            return
            
        file_path = urls[0].toLocalFile()
        
        # Check if file is PNG when required
        if self.accept_png_only and not file_path.lower().endswith('.png'):
            QMessageBox.warning(self, "Invalid File", "Only PNG files are accepted here.")
            return
            
        # Call the provided callback function with the file path
        if self.on_drop:
            self.on_drop(file_path)


class HideFileGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("HideFile - Steganography Tool")
        self.setMinimumSize(800, 600)
        
        # Initialize settings
        self.settings = QSettings("HideFile", "HideFileGUI")
        self.dark_mode = self.settings.value("dark_mode", False, type=bool)
        
        # Initialize the UI
        self.init_ui()
        
        # Apply the appropriate theme
        self.apply_theme()
    
    def init_ui(self):
        # Create a toolbar
        toolbar = QToolBar("Main Toolbar")
        toolbar.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)  # Show text beside icons
        self.addToolBar(toolbar)
        
        # Add theme toggle button to toolbar with proper icons
        self.theme_action = QAction(self)
        self.update_theme_action_appearance()
        self.theme_action.triggered.connect(self.toggle_theme)
        toolbar.addAction(self.theme_action)
        
        # Create a status bar
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("Ready")
        
        # Create a tab widget
        self.tab_widget = QTabWidget()
        
        # Create tabs
        hide_tab = self.create_hide_tab()
        extract_tab = self.create_extract_tab()
        about_tab = self.create_about_tab()
        
        # Add tabs to the widget
        self.tab_widget.addTab(hide_tab, "Hide File in PNG")
        self.tab_widget.addTab(extract_tab, "Extract File from PNG")
        self.tab_widget.addTab(about_tab, "About")
        
        # Set the central widget
        self.setCentralWidget(self.tab_widget)
    
    def create_hide_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Image preview area with drag & drop support
        self.hide_preview_label = DropArea(
            message="Drop a PNG image here or use the Browse button below",
            accept_png_only=True,
            on_drop=self.on_drop_cover_png
        )
        layout.addWidget(self.hide_preview_label)
        
        # Input fields group
        input_group = QGroupBox("Input Files")
        input_layout = QFormLayout()
        
        # PNG file selection
        png_layout = QHBoxLayout()
        self.hide_png_path = QLineEdit()
        self.hide_png_path.setReadOnly(True)
        png_browse_btn = QPushButton("Browse...")
        png_browse_btn.clicked.connect(self.browse_cover_png)
        png_layout.addWidget(self.hide_png_path)
        png_layout.addWidget(png_browse_btn)
        input_layout.addRow("Cover PNG:", png_layout)
        
        # Input file selection with drag & drop support
        file_layout = QHBoxLayout()
        self.hide_file_path = QLineEdit()
        self.hide_file_path.setReadOnly(True)
        
        # Create a horizontal layout for the file drop area and input path
        file_drop_container = QWidget()
        file_drop_layout = QHBoxLayout(file_drop_container)
        file_drop_layout.setContentsMargins(0, 0, 0, 0)
        
        # Add a small drop area for input files
        self.hide_file_drop = DropArea(
            message="Drop file here",
            accept_png_only=False,
            on_drop=self.on_drop_input_file
        )
        self.hide_file_drop.setMinimumHeight(60)
        self.hide_file_drop.setMaximumWidth(100)
        
        file_drop_layout.addWidget(self.hide_file_drop)
        file_drop_layout.addWidget(self.hide_file_path)
        
        file_browse_btn = QPushButton("Browse...")
        file_browse_btn.clicked.connect(self.browse_input_file)
        
        file_layout.addWidget(file_drop_container)
        file_layout.addWidget(file_browse_btn)
        input_layout.addRow("Input File:", file_layout)
        
        # Output PNG selection
        output_layout = QHBoxLayout()
        self.hide_output_path = QLineEdit()
        self.hide_output_path.setReadOnly(True)
        output_browse_btn = QPushButton("Browse...")
        output_browse_btn.clicked.connect(self.browse_output_png)
        output_layout.addWidget(self.hide_output_path)
        output_layout.addWidget(output_browse_btn)
        input_layout.addRow("Output PNG:", output_layout)
        
        # Add encryption checkbox
        encryption_layout = QHBoxLayout()
        self.hide_encrypt_checkbox = QCheckBox("Encrypt file data")
        self.hide_encrypt_checkbox.setChecked(False)
        encryption_layout.addWidget(self.hide_encrypt_checkbox)
        input_layout.addRow("Encryption:", encryption_layout)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Status area
        status_group = QGroupBox("Status")
        status_layout = QVBoxLayout()
        
        self.hide_status_text = QTextEdit()
        self.hide_status_text.setReadOnly(True)
        self.hide_status_text.setMaximumHeight(100)
        status_layout.addWidget(self.hide_status_text)
        
        self.hide_progress = QProgressBar()
        self.hide_progress.setRange(0, 100)
        self.hide_progress.setValue(0)
        status_layout.addWidget(self.hide_progress)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Action button
        hide_button_layout = QHBoxLayout()
        hide_button_layout.addStretch()
        
        self.hide_button = QPushButton("Hide File in PNG")
        self.hide_button.setMinimumWidth(200)
        self.hide_button.setMinimumHeight(40)
        self.hide_button.clicked.connect(self.perform_hide)
        hide_button_layout.addWidget(self.hide_button)
        
        hide_button_layout.addStretch()
        layout.addLayout(hide_button_layout)
        
        # Add some spacing
        layout.addItem(QSpacerItem(20, 20, QSizePolicy.Minimum, QSizePolicy.Expanding))
        
        tab.setLayout(layout)
        return tab
    
    def create_extract_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Image preview area with drag & drop support
        self.extract_preview_label = DropArea(
            message="Drop a PNG image here or use the Browse button below",
            accept_png_only=True,
            on_drop=self.on_drop_input_png
        )
        layout.addWidget(self.extract_preview_label)
        
        # Input fields group
        input_group = QGroupBox("Input/Output Files")
        input_layout = QFormLayout()
        
        # PNG file selection
        png_layout = QHBoxLayout()
        self.extract_png_path = QLineEdit()
        self.extract_png_path.setReadOnly(True)
        png_browse_btn = QPushButton("Browse...")
        png_browse_btn.clicked.connect(self.browse_input_png)
        png_layout.addWidget(self.extract_png_path)
        png_layout.addWidget(png_browse_btn)
        input_layout.addRow("Input PNG:", png_layout)
        
        # Output directory selection
        file_layout = QHBoxLayout()
        self.extract_file_path = QLineEdit()
        self.extract_file_path.setReadOnly(True)
        file_browse_btn = QPushButton("Browse...")
        file_browse_btn.clicked.connect(self.browse_output_file)
        file_layout.addWidget(self.extract_file_path)
        file_layout.addWidget(file_browse_btn)
        input_layout.addRow("Output Directory:", file_layout)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Status area
        status_group = QGroupBox("Status")
        status_layout = QVBoxLayout()
        
        self.extract_status_text = QTextEdit()
        self.extract_status_text.setReadOnly(True)
        self.extract_status_text.setMaximumHeight(100)
        status_layout.addWidget(self.extract_status_text)
        
        self.extract_progress = QProgressBar()
        self.extract_progress.setRange(0, 100)
        self.extract_progress.setValue(0)
        status_layout.addWidget(self.extract_progress)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Action button
        extract_button_layout = QHBoxLayout()
        extract_button_layout.addStretch()
        
        self.extract_button = QPushButton("Extract File from PNG")
        self.extract_button.setMinimumWidth(200)
        self.extract_button.setMinimumHeight(40)
        self.extract_button.clicked.connect(self.perform_extract)
        extract_button_layout.addWidget(self.extract_button)
        
        extract_button_layout.addStretch()
        layout.addLayout(extract_button_layout)
        
        # Add some spacing
        layout.addItem(QSpacerItem(20, 20, QSizePolicy.Minimum, QSizePolicy.Expanding))
        
        tab.setLayout(layout)
        return tab
    
    def create_about_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        about_text = """
        <h1>HideFile - Steganography Tool</h1>
        <p>HideFile is a tool for hiding files inside PNG images using a technique known as steganography.</p>
        
        <h2>Usage</h2>
        
        <h3>Hiding a File in a PNG</h3>
        <ol>
            <li>Switch to the "Hide File in PNG" tab</li>
            <li>Select a PNG image using one of these methods:
                <ul>
                    <li>Drag and drop a PNG image onto the preview area</li>
                    <li>Click "Browse..." next to "Cover PNG" to select the PNG image</li>
                </ul>
            </li>
            <li>Select the file you want to hide using one of these methods:
                <ul>
                    <li>Drag and drop any file onto the file drop area</li>
                    <li>Click "Browse..." next to "Input File" to select the file</li>
                </ul>
            </li>
            <li>Click "Browse..." next to "Output PNG" to choose where to save the resulting PNG</li>
            <li>If you want to encrypt the data, check the "Encrypt file data" box and provide a password</li>
            <li>Click "Hide File in PNG" to start the process</li>
            <li>Wait for the success message</li>
        </ol>
        
        <h3>Extracting a File from a PNG</h3>
        <ol>
            <li>Switch to the "Extract File from PNG" tab</li>
            <li>Select the PNG image containing hidden data using one of these methods:
                <ul>
                    <li>Drag and drop a PNG image onto the preview area</li>
                    <li>Click "Browse..." next to "Input PNG" to select the PNG image</li>
                </ul>
            </li>
            <li>Click "Browse..." next to "Output Directory" to select where the extracted file should be saved</li>
            <li>Click "Extract File from PNG" to start the process</li>
            <li>If the file was encrypted, you'll be prompted for the password</li>
            <li>The file will be extracted with its original filename</li>
        </ol>
        
        <h2>Limitations</h2>
        <ul>
            <li>The PNG file size will increase by approximately the size of the hidden file</li>
            <li>Very large files may not be suitable for hiding in small PNG images</li>
            <li>The hidden file can only be extracted using this tool or similar ones that understand the format</li>
            <li>Some image processing or optimization tools might strip the hidden data if they rewrite the PNG</li>
        </ul>
        
        <h2>How it works</h2>
        <p>This tool embeds files by appending the data to the last IDAT chunk of a PNG file.</p>
        <p>It recalculates the CRC checksums and updates the chunk lengths, ensuring the PNG remains valid and visually identical.</p>
        
        <p><strong>Note:</strong> This tool is for educational purposes only. Be aware of legal restrictions 
        regarding steganography in your jurisdiction.</p>
        """
        
        # Replace QLabel with QTextBrowser for scrollable content
        self.about_text_browser = QTextEdit()
        self.about_text_browser.setReadOnly(True)
        self.about_text_browser.setHtml(about_text)
        self.about_text_browser.setTextColor(QColor(0, 0, 0))  # Black text
        
        # Set proper sizing
        self.about_text_browser.setMinimumHeight(400)
        
        layout.addWidget(self.about_text_browser)
        
        tab.setLayout(layout)
        return tab
    
    def update_theme_action_appearance(self):
        """Update the theme action with appropriate text and icon"""
        if self.dark_mode:
            self.theme_action.setText("Switch to Light Mode")
            # Use a standard style icon for light mode
            self.theme_action.setIcon(self.style().standardIcon(QStyle.SP_TitleBarNormalButton))
        else:
            self.theme_action.setText("Switch to Dark Mode")
            # Use a standard style icon for dark mode
            self.theme_action.setIcon(self.style().standardIcon(QStyle.SP_TitleBarShadeButton))
    
    def toggle_theme(self):
        # Toggle dark mode
        self.dark_mode = not self.dark_mode
        
        # Update settings
        self.settings.setValue("dark_mode", self.dark_mode)
        
        # Update theme action appearance
        self.update_theme_action_appearance()
        
        # Apply the theme
        self.apply_theme()
        
        # Show status message
        self.statusBar.showMessage(f"{'Dark' if self.dark_mode else 'Light'} mode enabled", 2000)
    
    def apply_theme(self):
        app = QApplication.instance()
        
        # Common styles that will be applied regardless of theme
        common_styles = """
            QGroupBox {
                margin-top: 1.1em;
                padding-top: 0.8em;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 3px 0 3px;
                color: #000000;  /* Always black text */
            }
            QPushButton {
                padding: 5px;
                min-height: 20px;
                color: #000000;  /* Always black text */
            }
            QLineEdit {
                padding: 3px;
                min-height: 20px;
                color: #000000;  /* Always black text */
            }
            QTabWidget::pane {
                padding: 2px;
            }
            QTabBar::tab {
                padding: 5px;
                min-width: 80px;
                color: #000000;  /* Always black text */
            }
            QToolBar {
                min-height: 32px;
                padding: 2px;
            }
            QLabel {
                color: #000000;  /* Always black text */
            }
            QTextEdit {
                color: #000000;  /* Always black text */
            }
            QToolButton {
                color: #000000;  /* Always black text */
            }
            QStatusBar {
                color: #000000;  /* Always black text */
            }
            QCheckBox {
                color: #ffffff;  /* Always white text for checkbox */
            }
            QCheckBox::indicator {
                width: 13px;
                height: 13px;
                border: 1px solid #999999;
            }
            QCheckBox::indicator:checked {
                background-color: #cccccc;
            }
        """
        
        if self.dark_mode:
            # More moderate dark mode palette (slightly lighter)
            palette = QPalette()
            palette.setColor(QPalette.Window, QColor(60, 63, 65))
            palette.setColor(QPalette.WindowText, QColor(0, 0, 0))  # Black text
            palette.setColor(QPalette.Base, QColor(43, 43, 43))
            palette.setColor(QPalette.AlternateBase, QColor(60, 63, 65))
            palette.setColor(QPalette.ToolTipBase, QColor(43, 43, 43))
            palette.setColor(QPalette.ToolTipText, QColor(0, 0, 0))  # Black text
            palette.setColor(QPalette.Text, QColor(0, 0, 0))  # Black text
            palette.setColor(QPalette.Button, QColor(60, 63, 65))
            palette.setColor(QPalette.ButtonText, QColor(0, 0, 0))  # Black text
            palette.setColor(QPalette.BrightText, QColor(255, 120, 120))
            palette.setColor(QPalette.Link, QColor(80, 160, 255))
            palette.setColor(QPalette.Highlight, QColor(80, 160, 255))
            palette.setColor(QPalette.HighlightedText, QColor(0, 0, 0))  # Black text
            
            # Dark mode specific styles
            dark_styles = common_styles + """
                QGroupBox {
                    border: 1px solid #555555;
                }
                QTextEdit {
                    background-color: #2d2d2d;
                    border: 1px solid #555555;
                }
                QPushButton {
                    background-color: #424242;
                    border: 1px solid #555555;
                }
                QPushButton:hover {
                    background-color: #4e4e4e;
                }
                QPushButton:pressed {
                    background-color: #606060;
                }
                QLineEdit {
                    background-color: #2d2d2d;
                    border: 1px solid #555555;
                }
                QTabWidget::pane {
                    border: 1px solid #555555;
                }
                QTabBar::tab {
                    background-color: #424242;
                    border: 1px solid #555555;
                }
                QTabBar::tab:selected {
                    background-color: #4e4e4e;
                }
                QTabBar::tab:hover {
                    background-color: #606060;
                }
                QToolBar {
                    background-color: #3c3f41;
                    border-bottom: 1px solid #555555;
                    spacing: 3px;
                }
                QToolButton {
                    background-color: #424242;
                    border: 1px solid #555555;
                    padding: 4px;
                }
                QToolButton:hover {
                    background-color: #4e4e4e;
                }
                QStatusBar {
                    background-color: #3c3f41;
                    border-top: 1px solid #555555;
                }
                QProgressBar {
                    background-color: #2d2d2d;
                    border: 1px solid #555555;
                    text-align: center;
                }
                QProgressBar::chunk {
                    background-color: #6b9eff;
                }
                QCheckBox {
                    background-color: transparent;
                    color: #ffffff;
                }
                QCheckBox::indicator {
                    width: 13px;
                    height: 13px;
                    border: 1px solid #aaaaaa;
                    background-color: #2d2d2d;
                }
                QCheckBox::indicator:checked {
                    background-color: #6b9eff;
                }
            """
            
            # Apply dark mode styles to components
            self.hide_preview_label.setStyleSheet("border: 1px solid #555555; background-color: #2d2d2d; color: #000000;")
            self.extract_preview_label.setStyleSheet("border: 1px solid #555555; background-color: #2d2d2d; color: #000000;")
            
            # Apply special styling to the drop areas
            if hasattr(self, 'hide_file_drop'):
                self.hide_file_drop.setStyleSheet("border: 2px dashed #555555; border-radius: 5px; background-color: #2d2d2d; color: #000000; padding: 5px;")
            
            # Apply stylesheet
            app.setStyleSheet(dark_styles)
            
            # Set specific styling for checkbox
            self.hide_encrypt_checkbox.setStyleSheet("color: #ffffff;")
            
            # Update about text color for better visibility in dark mode
            if hasattr(self, 'about_text_browser'):
                self.about_text_browser.setStyleSheet("color: #000000; background-color: #2d2d2d; border: 1px solid #555555;")
        else:
            # Medium-gray light mode palette (darker and less abrasive)
            palette = QPalette()
            palette.setColor(QPalette.Window, QColor(210, 210, 210))
            palette.setColor(QPalette.WindowText, QColor(0, 0, 0))  # Black text
            palette.setColor(QPalette.Base, QColor(220, 220, 220))
            palette.setColor(QPalette.AlternateBase, QColor(200, 200, 200))
            palette.setColor(QPalette.ToolTipBase, QColor(210, 210, 210))
            palette.setColor(QPalette.ToolTipText, QColor(0, 0, 0))  # Black text
            palette.setColor(QPalette.Text, QColor(0, 0, 0))  # Black text
            palette.setColor(QPalette.Button, QColor(210, 210, 210))
            palette.setColor(QPalette.ButtonText, QColor(0, 0, 0))  # Black text
            palette.setColor(QPalette.BrightText, QColor(200, 0, 0))
            palette.setColor(QPalette.Link, QColor(0, 100, 200))
            palette.setColor(QPalette.Highlight, QColor(0, 120, 215))
            palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
            
            # Medium-gray light mode specific styles
            light_styles = common_styles + """
                QGroupBox {
                    border: 1px solid #bbbbbb;
                }
                QTextEdit {
                    background-color: #dcdcdc;
                    border: 1px solid #bbbbbb;
                }
                QPushButton {
                    background-color: #c8c8c8;
                    border: 1px solid #bbbbbb;
                }
                QPushButton:hover {
                    background-color: #bebebe;
                }
                QPushButton:pressed {
                    background-color: #b0b0b0;
                }
                QLineEdit {
                    background-color: #dcdcdc;
                    border: 1px solid #bbbbbb;
                }
                QTabWidget::pane {
                    border: 1px solid #bbbbbb;
                }
                QTabBar::tab {
                    background-color: #c8c8c8;
                    border: 1px solid #bbbbbb;
                }
                QTabBar::tab:selected {
                    background-color: #bebebe;
                }
                QTabBar::tab:hover {
                    background-color: #b0b0b0;
                }
                QToolBar {
                    background-color: #d2d2d2;
                    border-bottom: 1px solid #bbbbbb;
                    spacing: 3px;
                }
                QToolButton {
                    background-color: #c8c8c8;
                    border: 1px solid #bbbbbb;
                    padding: 4px;
                }
                QToolButton:hover {
                    background-color: #bebebe;
                }
                QStatusBar {
                    background-color: #d2d2d2;
                    border-top: 1px solid #bbbbbb;
                }
                QProgressBar {
                    background-color: #c8c8c8;
                    border: 1px solid #bbbbbb;
                    text-align: center;
                }
                QProgressBar::chunk {
                    background-color: #6b9eff;
                }
                QCheckBox {
                    background-color: transparent;
                    color: #ffffff;
                }
                QCheckBox::indicator {
                    width: 13px;
                    height: 13px;
                    border: 1px solid #666666;
                    background-color: #dddddd;
                }
                QCheckBox::indicator:checked {
                    background-color: #6b9eff;
                }
            """
            
            # Apply light mode styles to components
            self.hide_preview_label.setStyleSheet("border: 1px solid #bbbbbb; background-color: #dcdcdc; color: #000000;")
            self.extract_preview_label.setStyleSheet("border: 1px solid #bbbbbb; background-color: #dcdcdc; color: #000000;")
            
            # Apply special styling to the drop areas
            if hasattr(self, 'hide_file_drop'):
                self.hide_file_drop.setStyleSheet("border: 2px dashed #bbbbbb; border-radius: 5px; background-color: #dcdcdc; color: #000000; padding: 5px;")
            
            # Apply stylesheet
            app.setStyleSheet(light_styles)
            
            # Set specific styling for checkbox
            self.hide_encrypt_checkbox.setStyleSheet("color: #ffffff;")
            
            # Update about text color
            if hasattr(self, 'about_text_browser'):
                self.about_text_browser.setStyleSheet("color: #000000; background-color: #dcdcdc; border: 1px solid #bbbbbb;")
        
        app.setPalette(palette)
    
    def browse_cover_png(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Cover PNG", "", "PNG Files (*.png)", options=options)
        if file_path:
            self.hide_png_path.setText(file_path)
            self.update_preview(file_path, self.hide_preview_label)
            
            # Auto-suggest output file name
            if not self.hide_output_path.text():
                directory = os.path.dirname(file_path)
                base_name = os.path.basename(file_path)
                name_parts = os.path.splitext(base_name)
                new_name = f"{name_parts[0]}_hidden{name_parts[1]}"
                self.hide_output_path.setText(os.path.join(directory, new_name))
    
    def browse_input_file(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Hide", "", "All Files (*)", options=options)
        if file_path:
            self.hide_file_path.setText(file_path)
            self.add_status_message("hide", f"Selected file: {file_path} ({os.path.getsize(file_path)} bytes)")
    
    def browse_output_png(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Output PNG", "", "PNG Files (*.png)", options=options)
        if file_path:
            if not file_path.lower().endswith(".png"):
                file_path += ".png"
            self.hide_output_path.setText(file_path)
    
    def browse_input_png(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Select PNG with hidden file", "", "PNG Files (*.png)", options=options)
        if file_path:
            self.extract_png_path.setText(file_path)
            self.update_preview(file_path, self.extract_preview_label)
            
            # Auto-suggest output directory (parent directory of PNG)
            if not self.extract_file_path.text():
                directory = os.path.dirname(file_path)
                self.extract_file_path.setText(directory)
    
    def browse_output_file(self):
        options = QFileDialog.Options()
        directory = QFileDialog.getExistingDirectory(self, "Select Directory for Extracted File")
        if directory:
            self.extract_file_path.setText(directory)
    
    def update_preview(self, image_path, label):
        try:
            pixmap = QPixmap(image_path)
            if not pixmap.isNull():
                pixmap = pixmap.scaled(300, 200, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                label.setPixmap(pixmap)
                file_size = os.path.getsize(image_path)
                label.setToolTip(f"Image size: {file_size} bytes ({file_size / 1024:.2f} KB)")
                
                # Ensure drag and drop is still enabled for DropArea
                if isinstance(label, DropArea):
                    label.setAcceptDrops(True)
            else:
                label.setText("Invalid image format")
        except Exception as e:
            label.setText(f"Error loading image: {str(e)}")
    
    def add_status_message(self, tab, message):
        if tab == "hide":
            self.hide_status_text.append(message)
            self.hide_status_text.ensureCursorVisible()
        else:
            self.extract_status_text.append(message)
            self.extract_status_text.ensureCursorVisible()
    
    def perform_hide(self):
        cover_png = self.hide_png_path.text()
        input_file = self.hide_file_path.text()
        output_png = self.hide_output_path.text()
        use_encryption = self.hide_encrypt_checkbox.isChecked()
        
        if not cover_png or not input_file or not output_png:
            QMessageBox.warning(self, "Missing Information", "Please select all required files.")
            return
        
        # Get password if encryption is enabled
        password = None
        if use_encryption:
            password, ok = QInputDialog.getText(
                self, "Encryption Password", 
                "Enter password for encryption:", 
                QLineEdit.Password
            )
            if not ok or not password:
                QMessageBox.warning(self, "Encryption Cancelled", "Encryption requires a password.")
                return
            
            # Confirm password
            confirm_password, ok = QInputDialog.getText(
                self, "Confirm Password", 
                "Confirm your password:", 
                QLineEdit.Password
            )
            if not ok or password != confirm_password:
                QMessageBox.warning(self, "Password Error", "Passwords do not match.")
                return
        
        try:
            # Update progress
            self.hide_progress.setValue(10)
            self.add_status_message("hide", "Starting to embed file...")
            if use_encryption:
                self.add_status_message("hide", "File will be encrypted before embedding")
            
            # Redirect stdout to capture the output
            original_stdout = sys.stdout
            from io import StringIO
            captured_output = StringIO()
            sys.stdout = captured_output
            
            # Perform the operation
            embed_file_in_png(cover_png, input_file, output_png, encrypt=use_encryption, password=password)
            
            # Restore stdout
            sys.stdout = original_stdout
            
            # Get captured output
            output_text = captured_output.getvalue()
            self.add_status_message("hide", output_text)
            
            # Update progress
            self.hide_progress.setValue(100)
            
            # Show success message
            msg = "File has been successfully hidden in the PNG image."
            if use_encryption:
                msg += "\nThe file was encrypted with your password. You will need this password to extract the file."
            QMessageBox.information(self, "Success", msg)
            
        except Exception as e:
            self.hide_progress.setValue(0)
            error_message = f"Error: {str(e)}"
            self.add_status_message("hide", error_message)
            QMessageBox.critical(self, "Error", error_message)
    
    def perform_extract(self):
        input_png = self.extract_png_path.text()
        output_dir = self.extract_file_path.text()
        
        if not input_png or not output_dir:
            QMessageBox.warning(self, "Missing Information", "Please select the PNG file and output directory.")
            return
        
        # Verify the output directory exists
        if not os.path.isdir(output_dir):
            QMessageBox.warning(self, "Invalid Directory", "Please select a valid output directory.")
            return
        
        try:
            # First check if the file is encrypted by examining the metadata
            is_encrypted = self.check_if_encrypted(input_png)
            password = None
            
            if is_encrypted:
                # Prompt for password
                password, ok = QInputDialog.getText(
                    self, "Decryption Password", 
                    "This file is encrypted. Enter the password to decrypt:", 
                    QLineEdit.Password
                )
                if not ok or not password:
                    QMessageBox.warning(self, "Decryption Cancelled", "Password is required to decrypt this file.")
                    return
            
            # Update progress
            self.extract_progress.setValue(10)
            self.add_status_message("extract", "Starting to extract file...")
            if is_encrypted:
                self.add_status_message("extract", "File is encrypted - will attempt to decrypt with provided password")
            
            # Redirect stdout to capture the output
            original_stdout = sys.stdout
            from io import StringIO
            captured_output = StringIO()
            sys.stdout = captured_output
            
            # Perform the operation - now returns the full path of the extracted file
            extracted_file_path = extract_file_from_png(input_png, output_dir, password=password)
            
            # Restore stdout
            sys.stdout = original_stdout
            
            # Get captured output
            output_text = captured_output.getvalue()
            self.add_status_message("extract", output_text)
            
            # Update progress
            self.extract_progress.setValue(100)
            
            # Show success message with the exact path where the file was saved
            msg = f"File has been successfully extracted to:\n{extracted_file_path}"
            if is_encrypted:
                msg += "\nThe file was decrypted successfully."
            QMessageBox.information(self, "Success", msg)
            
        except Exception as e:
            self.extract_progress.setValue(0)
            error_message = f"Error: {str(e)}"
            self.add_status_message("extract", error_message)
            QMessageBox.critical(self, "Error", error_message)
    
    def check_if_encrypted(self, png_path):
        """Check if a PNG file contains encrypted hidden data"""
        try:
            # Read the PNG file
            with open(png_path, 'rb') as f:
                png_data = f.read()
            
            # Parse PNG chunks
            chunks = parse_png_chunks(png_data)
            
            # Get IDAT chunks
            idat_chunks = [chunk for chunk in chunks if chunk['type'] == 'IDAT']
            if not idat_chunks:
                return False
            
            # Start with the last IDAT as most likely location
            idat_chunks.reverse()
            
            # Define the magic marker we're looking for
            MAGIC_MARKER = b'HIDEFILE'
            
            # Search for the magic marker in each IDAT chunk
            for idat_chunk in idat_chunks:
                data = idat_chunk['data']
                marker_pos = data.find(MAGIC_MARKER)
                
                if marker_pos != -1:
                    # Found the marker - now extract the metadata
                    data_pos = marker_pos + len(MAGIC_MARKER)
                    
                    # Extract metadata length (4 bytes big-endian integer)
                    metadata_length = struct.unpack('>I', data[data_pos:data_pos+4])[0]
                    data_pos += 4
                    
                    # Extract metadata as JSON
                    metadata_json = data[data_pos:data_pos+metadata_length]
                    try:
                        metadata = json.loads(metadata_json.decode('utf-8'))
                        return metadata.get('encrypted', False)
                    except:
                        # If we can't parse the metadata, assume it's not encrypted
                        return False
            
            return False
        except:
            # If anything goes wrong, assume it's not encrypted
            return False

    def on_drop_cover_png(self, file_path):
        """Handle file drop on the cover PNG drop area."""
        self.hide_png_path.setText(file_path)
        self.update_preview(file_path, self.hide_preview_label)
        
        # Auto-suggest output file name
        if not self.hide_output_path.text():
            directory = os.path.dirname(file_path)
            base_name = os.path.basename(file_path)
            name_parts = os.path.splitext(base_name)
            new_name = f"{name_parts[0]}_hidden{name_parts[1]}"
            self.hide_output_path.setText(os.path.join(directory, new_name))
        
        self.add_status_message("hide", f"Loaded PNG: {file_path}")

    def on_drop_input_file(self, file_path):
        """Handle file drop on the input file drop area."""
        self.hide_file_path.setText(file_path)
        self.add_status_message("hide", f"Selected file: {file_path} ({os.path.getsize(file_path)} bytes)")

    def on_drop_input_png(self, file_path):
        """Handle file drop on the extract PNG drop area."""
        self.extract_png_path.setText(file_path)
        self.update_preview(file_path, self.extract_preview_label)
        
        # Auto-suggest output directory (parent directory of PNG)
        if not self.extract_file_path.text():
            directory = os.path.dirname(file_path)
            self.extract_file_path.setText(directory)
        
        self.add_status_message("extract", f"Loaded PNG: {file_path}")
        
        # Check if the PNG has embedded encrypted data
        self.check_if_encrypted(file_path)


def main():
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle("Fusion")
    
    # Create and show the main window
    main_window = HideFileGUI()
    main_window.show()
    
    # Run the application
    sys.exit(app.exec_())


if __name__ == "__main__":
    main() 