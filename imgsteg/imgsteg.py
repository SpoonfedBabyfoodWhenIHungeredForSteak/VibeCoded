#!/usr/bin/env python3
"""
Cypher - A Steganography Tool

A GUI application for hiding text messages in images using 
least significant bit (LSB) steganography with optional encryption.
"""

import sys
import os
import math
import base64
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QSpinBox, QRadioButton, QButtonGroup,
    QTextEdit, QFileDialog, QMessageBox, QProgressBar, QGroupBox, QCheckBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QPixmap, QImage, QColor, QPalette
from PIL import Image
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os

def derive_key(password, salt=None):
    """Derive an encryption key from a password using PBKDF2"""
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = 256 bits for AES-256
        salt=salt,
        iterations=100000,
    )
    
    key = kdf.derive(password.encode())
    return key, salt

def encrypt_message(message, password):
    """Encrypt a message using AES-GCM with a password-derived key"""
    # Generate a random salt and derive key
    key, salt = derive_key(password)
    
    # Generate nonce
    nonce = os.urandom(12)
    
    # Create cipher
    aesgcm = AESGCM(key)
    
    # Encrypt
    ciphertext = aesgcm.encrypt(nonce, message.encode(), None)
    
    # Combine salt + nonce + ciphertext for storage
    encrypted_data = salt + nonce + ciphertext
    
    # Return as base64 string for easy handling
    return base64.b64encode(encrypted_data).decode('utf-8')

def decrypt_message(encrypted_message, password):
    """Decrypt a message using AES-GCM with a password-derived key"""
    # Decode from base64
    encrypted_data = base64.b64decode(encrypted_message)
    
    # Extract components
    salt = encrypted_data[:16]
    nonce = encrypted_data[16:28]
    ciphertext = encrypted_data[28:]
    
    # Derive the key using the stored salt
    key, _ = derive_key(password, salt)
    
    # Create cipher
    aesgcm = AESGCM(key)
    
    # Decrypt
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    
    return plaintext.decode('utf-8')

class EncodingThread(QThread):
    """Worker thread for encoding to avoid freezing the GUI"""
    progress_updated = pyqtSignal(int)
    encoding_finished = pyqtSignal(bool, str)

    def __init__(self, image_path, text, step_size, color_channel, output_path, encrypt=False, password=None):
        super().__init__()
        self.image_path = image_path
        self.text = text
        self.step_size = step_size
        self.color_channel = color_channel
        self.output_path = output_path
        self.encrypt = encrypt
        self.password = password

    def run(self):
        try:
            # If encryption is enabled, encrypt the message first
            message_to_encode = self.text
            if self.encrypt and self.password:
                try:
                    message_to_encode = encrypt_message(self.text, self.password)
                    # Add a prefix to indicate this is encrypted data
                    message_to_encode = "ENCRYPTED:" + message_to_encode
                except Exception as e:
                    self.encoding_finished.emit(False, f"Encryption error: {str(e)}")
                    return
            
            # Open the image
            img = Image.open(self.image_path)
            
            # If image is not RGB, convert it
            if img.mode != "RGB":
                img = img.convert("RGB")
            
            width, height = img.size
            pixels = img.load()
            
            # Convert text length to binary (32 bits)
            text_length_binary = format(len(message_to_encode), '032b')
            
            # Convert text to binary (8 bits per character)
            text_binary = ''.join(format(ord(char), '08b') for char in message_to_encode)
            
            # Combine length and text binary
            binary_data = text_length_binary + text_binary
            
            # Calculate capacity
            total_pixels = width * height
            selected_pixels = math.ceil(total_pixels / self.step_size)
            required_bits = len(binary_data)
            
            # Check if we have enough capacity
            if selected_pixels < required_bits:
                self.encoding_finished.emit(False, f"Image too small: Capacity {selected_pixels} bits, Required {required_bits} bits")
                return
            
            # Determine color channel index
            channel_idx = {"red": 0, "green": 1, "blue": 2}[self.color_channel]
            
            # Encoding process
            binary_index = 0
            for y in range(height):
                for x in range(width):
                    # Only process every Nth pixel based on step_size
                    if (y * width + x) % self.step_size == 0:
                        if binary_index < len(binary_data):
                            # Get current pixel
                            r, g, b = pixels[x, y]
                            
                            # Modify the LSB of the selected color channel
                            if channel_idx == 0:  # Red
                                r = (r & ~1) | int(binary_data[binary_index])
                            elif channel_idx == 1:  # Green
                                g = (g & ~1) | int(binary_data[binary_index])
                            else:  # Blue
                                b = (b & ~1) | int(binary_data[binary_index])
                            
                            # Update pixel
                            pixels[x, y] = (r, g, b)
                            
                            # Move to next bit
                            binary_index += 1
                            
                            # Update progress (to nearest percentage)
                            progress = int((binary_index / len(binary_data)) * 100)
                            self.progress_updated.emit(progress)
            
            # Save the modified image
            img.save(self.output_path)
            
            # Success message depends on whether encryption was used
            if self.encrypt and self.password:
                self.encoding_finished.emit(True, f"Encrypted message successfully encoded and saved to {self.output_path}")
            else:
                self.encoding_finished.emit(True, f"Message successfully encoded and saved to {self.output_path}")
        
        except Exception as e:
            self.encoding_finished.emit(False, f"Error: {str(e)}")

class DecodingThread(QThread):
    """Worker thread for decoding to avoid freezing the GUI"""
    progress_updated = pyqtSignal(int)
    decoding_finished = pyqtSignal(bool, str, str)

    def __init__(self, image_path, step_size, color_channel, password=None):
        super().__init__()
        self.image_path = image_path
        self.step_size = step_size
        self.color_channel = color_channel
        self.password = password

    def run(self):
        try:
            # Open the image
            img = Image.open(self.image_path)
            
            # If image is not RGB, convert it
            if img.mode != "RGB":
                img = img.convert("RGB")
            
            width, height = img.size
            pixels = img.load()
            
            # Determine color channel index
            channel_idx = {"red": 0, "green": 1, "blue": 2}[self.color_channel]
            
            # Extract binary data (first 32 bits for length)
            extracted_bits = ""
            total_pixels = width * height
            
            # First read 32 bits to get the length
            bits_read = 0
            pixel_idx = 0
            
            while bits_read < 32 and pixel_idx < total_pixels:
                if pixel_idx % self.step_size == 0:
                    x = pixel_idx % width
                    y = pixel_idx // width
                    
                    # Get the LSB of the selected color channel
                    r, g, b = pixels[x, y]
                    
                    if channel_idx == 0:  # Red
                        bit = r & 1
                    elif channel_idx == 1:  # Green
                        bit = g & 1
                    else:  # Blue
                        bit = b & 1
                    
                    extracted_bits += str(bit)
                    bits_read += 1
                    
                    # Update progress (to nearest percentage)
                    self.progress_updated.emit(int((bits_read / 32) * 50))  # First half of progress
                
                pixel_idx += 1
            
            # Convert the first 32 bits to get text length
            if len(extracted_bits) < 32:
                self.decoding_finished.emit(False, "Failed to read enough data from the image.", "")
                return
                
            text_length = int(extracted_bits[:32], 2)
            
            # Extract the actual text bits
            required_text_bits = text_length * 8
            extracted_text_bits = ""
            bits_read = 0
            
            while bits_read < required_text_bits and pixel_idx < total_pixels:
                if pixel_idx % self.step_size == 0:
                    x = pixel_idx % width
                    y = pixel_idx // width
                    
                    # Get the LSB of the selected color channel
                    r, g, b = pixels[x, y]
                    
                    if channel_idx == 0:  # Red
                        bit = r & 1
                    elif channel_idx == 1:  # Green
                        bit = g & 1
                    else:  # Blue
                        bit = b & 1
                    
                    extracted_text_bits += str(bit)
                    bits_read += 1
                    
                    # Update progress (to nearest percentage)
                    progress = 50 + int((bits_read / required_text_bits) * 50)  # Second half of progress
                    self.progress_updated.emit(min(progress, 100))
                
                pixel_idx += 1
            
            # Convert binary to text
            decoded_text = ""
            for i in range(0, len(extracted_text_bits), 8):
                if i + 8 <= len(extracted_text_bits):
                    byte = extracted_text_bits[i:i+8]
                    decoded_text += chr(int(byte, 2))
            
            # Check if the message is encrypted and try to decrypt it
            if decoded_text.startswith("ENCRYPTED:"):
                if not self.password:
                    self.decoding_finished.emit(False, "This message is encrypted. Please provide a password.", "")
                    return
                
                try:
                    # Extract the encrypted data (remove the "ENCRYPTED:" prefix)
                    encrypted_data = decoded_text[10:]
                    # Decrypt the message
                    decrypted_text = decrypt_message(encrypted_data, self.password)
                    self.decoding_finished.emit(True, "Encrypted message successfully decoded and decrypted.", decrypted_text)
                except Exception as e:
                    self.decoding_finished.emit(False, f"Decryption error: {str(e)}. The password may be incorrect.", "")
            else:
                # Not encrypted, just return the decoded text
                self.decoding_finished.emit(True, "Message successfully decoded.", decoded_text)
        
        except Exception as e:
            self.decoding_finished.emit(False, f"Error: {str(e)}", "")

class CypherApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        
    def initUI(self):
        # Set up the main window
        self.setWindowTitle('Cypher - Image Steganography Tool')
        self.setMinimumSize(800, 600)
        
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Image selection section
        image_group = QGroupBox("Image Selection")
        image_layout = QHBoxLayout()
        
        self.image_path_label = QLabel("No image selected")
        self.browse_button = QPushButton("Browse...")
        self.browse_button.clicked.connect(self.browse_image)
        
        image_layout.addWidget(self.image_path_label, 1)
        image_layout.addWidget(self.browse_button)
        image_group.setLayout(image_layout)
        main_layout.addWidget(image_group)
        
        # Configuration section
        config_group = QGroupBox("Encoding Configuration")
        config_layout = QHBoxLayout()
        
        # Step size selector
        step_layout = QVBoxLayout()
        step_label = QLabel("Encode every N pixels:")
        self.step_spin = QSpinBox()
        self.step_spin.setRange(1, 10)
        self.step_spin.setValue(1)
        step_layout.addWidget(step_label)
        step_layout.addWidget(self.step_spin)
        
        # Color channel selector
        channel_layout = QVBoxLayout()
        channel_label = QLabel("Modify channel:")
        self.red_radio = QRadioButton("Red")
        self.green_radio = QRadioButton("Green")
        self.blue_radio = QRadioButton("Blue")
        self.red_radio.setChecked(True)
        
        self.channel_group = QButtonGroup()
        self.channel_group.addButton(self.red_radio)
        self.channel_group.addButton(self.green_radio)
        self.channel_group.addButton(self.blue_radio)
        
        channel_layout.addWidget(channel_label)
        channel_layout.addWidget(self.red_radio)
        channel_layout.addWidget(self.green_radio)
        channel_layout.addWidget(self.blue_radio)
        
        # Encryption options
        encryption_layout = QVBoxLayout()
        encryption_label = QLabel("Encryption:")
        self.encrypt_checkbox = QCheckBox("Enable encryption")
        self.encrypt_checkbox.stateChanged.connect(self.toggle_password_field)
        
        self.password_label = QLabel("Password:")
        self.password_field = QLineEdit()
        self.password_field.setEchoMode(QLineEdit.Password)
        self.password_field.setEnabled(False)
        
        encryption_layout.addWidget(encryption_label)
        encryption_layout.addWidget(self.encrypt_checkbox)
        encryption_layout.addWidget(self.password_label)
        encryption_layout.addWidget(self.password_field)
        
        config_layout.addLayout(step_layout)
        config_layout.addLayout(channel_layout)
        config_layout.addLayout(encryption_layout)
        config_group.setLayout(config_layout)
        main_layout.addWidget(config_group)
        
        # Text input section
        text_group = QGroupBox("Message")
        text_layout = QVBoxLayout()
        
        self.text_edit = QTextEdit()
        text_layout.addWidget(self.text_edit)
        text_group.setLayout(text_layout)
        main_layout.addWidget(text_group)
        
        # Action buttons
        button_layout = QHBoxLayout()
        self.encode_button = QPushButton("Encode Message")
        self.encode_button.clicked.connect(self.encode_image)
        self.decode_button = QPushButton("Decode Message")
        self.decode_button.clicked.connect(self.decode_image)
        
        button_layout.addWidget(self.encode_button)
        button_layout.addWidget(self.decode_button)
        main_layout.addLayout(button_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        main_layout.addWidget(self.progress_bar)
        
        # Status message
        self.status_label = QLabel("Ready")
        main_layout.addWidget(self.status_label)
        
        # Set initial state
        self.image_path = None
        self.encode_button.setEnabled(False)
        self.decode_button.setEnabled(False)
        
        # Show the window
        self.show()
    
    def toggle_password_field(self, state):
        """Enable or disable the password field based on encryption checkbox"""
        self.password_field.setEnabled(state == Qt.Checked)
    
    def browse_image(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Image", "", 
            "Image Files (*.png *.jpg *.jpeg *.bmp *.gif);;All Files (*)", 
            options=options
        )
        
        if file_path:
            self.image_path = file_path
            self.image_path_label.setText(os.path.basename(file_path))
            self.encode_button.setEnabled(True)
            self.decode_button.setEnabled(True)
    
    def get_selected_channel(self):
        if self.red_radio.isChecked():
            return "red"
        elif self.green_radio.isChecked():
            return "green"
        else:
            return "blue"
    
    def encode_image(self):
        if not self.image_path:
            QMessageBox.warning(self, "Warning", "Please select an image first.")
            return
        
        text = self.text_edit.toPlainText()
        if not text:
            QMessageBox.warning(self, "Warning", "Please enter a message to encode.")
            return
        
        # Check if encryption is enabled but no password is provided
        if self.encrypt_checkbox.isChecked() and not self.password_field.text():
            QMessageBox.warning(self, "Warning", "Encryption is enabled but no password was provided.")
            return
        
        step_size = self.step_spin.value()
        color_channel = self.get_selected_channel()
        
        options = QFileDialog.Options()
        output_path, _ = QFileDialog.getSaveFileName(
            self, "Save Encoded Image", "", 
            "PNG Files (*.png);;All Files (*)", 
            options=options
        )
        
        if not output_path:
            return
            
        # Make sure the output file has a .png extension
        if not output_path.lower().endswith('.png'):
            output_path += '.png'
        
        # Disable UI during encoding
        self.encode_button.setEnabled(False)
        self.decode_button.setEnabled(False)
        self.browse_button.setEnabled(False)
        self.progress_bar.setValue(0)
        self.status_label.setText("Encoding...")
        
        # Start encoding in a separate thread
        self.encoding_thread = EncodingThread(
            self.image_path, text, step_size, color_channel, output_path,
            encrypt=self.encrypt_checkbox.isChecked(),
            password=self.password_field.text() if self.encrypt_checkbox.isChecked() else None
        )
        self.encoding_thread.progress_updated.connect(self.update_progress)
        self.encoding_thread.encoding_finished.connect(self.encoding_complete)
        self.encoding_thread.start()
    
    def decode_image(self):
        if not self.image_path:
            QMessageBox.warning(self, "Warning", "Please select an image first.")
            return
        
        step_size = self.step_spin.value()
        color_channel = self.get_selected_channel()
        
        # Disable UI during decoding
        self.encode_button.setEnabled(False)
        self.decode_button.setEnabled(False)
        self.browse_button.setEnabled(False)
        self.progress_bar.setValue(0)
        self.status_label.setText("Decoding...")
        
        # Start decoding in a separate thread
        self.decoding_thread = DecodingThread(
            self.image_path, step_size, color_channel,
            password=self.password_field.text() if self.password_field.text() else None
        )
        self.decoding_thread.progress_updated.connect(self.update_progress)
        self.decoding_thread.decoding_finished.connect(self.decoding_complete)
        self.decoding_thread.start()
    
    def update_progress(self, value):
        self.progress_bar.setValue(value)
    
    def encoding_complete(self, success, message):
        # Re-enable UI
        self.encode_button.setEnabled(True)
        self.decode_button.setEnabled(True)
        self.browse_button.setEnabled(True)
        
        if success:
            self.status_label.setText("Success")
            QMessageBox.information(self, "Success", message)
        else:
            self.status_label.setText("Error")
            QMessageBox.critical(self, "Error", message)
    
    def decoding_complete(self, success, message, decoded_text):
        # Re-enable UI
        self.encode_button.setEnabled(True)
        self.decode_button.setEnabled(True)
        self.browse_button.setEnabled(True)
        
        if success:
            self.status_label.setText("Success")
            self.text_edit.setText(decoded_text)
            QMessageBox.information(self, "Success", message)
        else:
            self.status_label.setText("Error")
            QMessageBox.critical(self, "Error", message)
            # If it's an encrypted message but no password provided, enable password field
            if "encrypted" in message.lower():
                self.encrypt_checkbox.setChecked(True)
                self.password_field.setEnabled(True)
                self.password_field.setFocus()

def main():
    app = QApplication(sys.argv)
    
    # Apply fusion style for a more modern look
    app.setStyle("Fusion")
    
    # Set dark theme palette
    dark_palette = QPalette()
    dark_palette.setColor(QPalette.Window, QColor(53, 53, 53))
    dark_palette.setColor(QPalette.WindowText, Qt.white)
    dark_palette.setColor(QPalette.Base, QColor(25, 25, 25))
    dark_palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
    dark_palette.setColor(QPalette.ToolTipBase, Qt.white)
    dark_palette.setColor(QPalette.ToolTipText, Qt.white)
    dark_palette.setColor(QPalette.Text, Qt.white)
    dark_palette.setColor(QPalette.Button, QColor(53, 53, 53))
    dark_palette.setColor(QPalette.ButtonText, Qt.white)
    dark_palette.setColor(QPalette.BrightText, Qt.red)
    dark_palette.setColor(QPalette.Link, QColor(42, 130, 218))
    dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
    dark_palette.setColor(QPalette.HighlightedText, Qt.black)
    app.setPalette(dark_palette)
    
    window = CypherApp()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main() 