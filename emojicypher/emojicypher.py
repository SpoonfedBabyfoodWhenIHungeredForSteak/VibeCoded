#!/usr/bin/env python3
"""
EmojiCypher - A Steganographic Emoji Encoder/Decoder

This application enables users to hide secret messages within emoji characters
by using Unicode variation selectors. Supports multi-emoji encoding for longer messages.
"""

import sys
import platform
import pyperclip
import re
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QTextEdit, QMessageBox,
    QGridLayout, QGroupBox, QProgressBar, QScrollArea, QFrame
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPalette, QColor, QFont, QFontDatabase

class EmojiCypher(QMainWindow):
    def __init__(self):
        super().__init__()
        self.selected_emojis = ["😀"]  # Start with default emoji
        self.current_emoji = "😀"  # Current emoji being selected
        self.max_bits_per_emoji = 160  # Maximum bits per emoji (40 variation selectors × 4 bits)
        self.encoded_emoji_result = []  # Store the most recent encoded emojis
        self.current_draft_emoji_index = 0  # Index for cycling through emojis in draft tab
        self.setupFonts()
        self.initUI()
        
    def setupFonts(self):
        """Setup platform-specific emoji fonts"""
        # Get the best emoji font for the current OS
        self.system_font = QFont()
        
        if platform.system() == "Darwin":  # macOS
            self.emoji_font = QFont("Apple Color Emoji", 22)
        elif platform.system() == "Windows":
            self.emoji_font = QFont("Segoe UI Emoji", 22)
        else:  # Linux and others
            self.emoji_font = QFont("Noto Color Emoji", 22)
            
        # Fallback font for emoji compatibility
        self.emoji_font.setFamilies(["Apple Color Emoji", "Segoe UI Emoji", "Noto Color Emoji", "Symbola", "DejaVu Sans"])
        
    def initUI(self):
        # Set up the main window
        self.setWindowTitle('EmojiCypher - Emoji Steganography Tool')
        self.setMinimumSize(800, 600)
        
        # Create central widget and tabs
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        tab_widget = QTabWidget()
        encode_tab = QWidget()
        decode_tab = QWidget()
        draft_tab = QWidget()  # New tab for letter drafting
        
        tab_widget.addTab(encode_tab, "Encode")
        tab_widget.addTab(decode_tab, "Decode")
        tab_widget.addTab(draft_tab, "Letter Draft")
        
        # Store reference to the draft tab
        self.draft_tab_index = 2  # Index of the draft tab
        # Disable draft tab initially until encoding is done
        tab_widget.setTabEnabled(self.draft_tab_index, False)
        
        # List of 16 emoji options to choose from (added 🎨 to make even rows)
        self.emoji_list = [
            "😀", "😎", "🔥", "🚀", "🌈", 
            "🦄", "🍕", "🎮", "💡", "🎯", 
            "🌵", "🐉", "🦊", "🎸", "🧠", "🎨"
        ]
        
        # Setup Encode Tab
        encode_layout = QVBoxLayout(encode_tab)
        
        # Emoji Selection Group
        emoji_group = QGroupBox("Select Emoji")
        emoji_grid = QGridLayout()
        
        # Create a 2x8 grid of emoji buttons (changed from 3x5)
        self.emoji_buttons = []
        row, col = 0, 0
        for emoji in self.emoji_list:
            button = QPushButton(emoji)
            button.setFont(self.emoji_font)
            button.setFixedSize(50, 50)
            button.clicked.connect(lambda checked, e=emoji: self.selectEmoji(e))
            emoji_grid.addWidget(button, row, col)
            self.emoji_buttons.append(button)
            
            col += 1
            if col > 7:  # 8 columns (changed from 5)
                col = 0
                row += 1
        
        emoji_group.setLayout(emoji_grid)
        
        # Selected emoji display
        selected_emoji_layout = QHBoxLayout()
        selected_emoji_layout.addWidget(QLabel("Selected Emoji:"))
        self.selected_emoji_label = QLabel("😀")  # Default emoji
        self.selected_emoji_label.setFont(self.emoji_font)
        selected_emoji_layout.addWidget(self.selected_emoji_label)
        
        # Add button for adding emoji to sequence
        add_emoji_button = QPushButton("Add to Sequence")
        add_emoji_button.clicked.connect(self.addEmojiToSequence)
        selected_emoji_layout.addWidget(add_emoji_button)
        selected_emoji_layout.addStretch()
        
        # Selected emoji sequence - horizontal display
        sequence_group = QGroupBox("Emoji Sequence")
        sequence_layout = QVBoxLayout()
        
        # Create a scroll area for the emoji sequence to handle many emojis
        sequence_scroll = QScrollArea()
        sequence_scroll.setWidgetResizable(True)
        sequence_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        sequence_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        sequence_widget = QWidget()
        sequence_scroll.setWidget(sequence_widget)
        
        # Create a horizontal layout for the emoji sequence
        self.emoji_sequence_layout = QHBoxLayout(sequence_widget)
        self.emoji_sequence_layout.setAlignment(Qt.AlignLeft)
        self.emoji_sequence_layout.setContentsMargins(5, 5, 5, 5)
        
        # Add initial emoji
        initial_emoji_label = QLabel(self.selected_emojis[0])
        initial_emoji_label.setFont(self.emoji_font)
        initial_emoji_label.setStyleSheet("padding: 5px; margin: 2px;")
        self.emoji_sequence_layout.addWidget(initial_emoji_label)
        self.emoji_sequence_layout.addStretch()
        
        sequence_buttons_layout = QHBoxLayout()
        remove_last_button = QPushButton("Remove Last")
        remove_last_button.clicked.connect(self.removeLastEmoji)
        clear_sequence_button = QPushButton("Clear Sequence")
        clear_sequence_button.clicked.connect(self.clearEmojiSequence)
        
        sequence_buttons_layout.addWidget(remove_last_button)
        sequence_buttons_layout.addWidget(clear_sequence_button)
        
        sequence_layout.addWidget(sequence_scroll)
        sequence_layout.addLayout(sequence_buttons_layout)
        sequence_group.setLayout(sequence_layout)
        
        # Message input for encode
        encode_message_label = QLabel("Message to encode:")
        self.encode_message = QTextEdit()
        self.encode_message.textChanged.connect(self.updateCapacityIndicator)
        
        # Capacity indicator
        capacity_group = QGroupBox("Message Capacity")
        capacity_layout = QVBoxLayout()
        
        self.capacity_indicator = QProgressBar()
        self.capacity_indicator.setTextVisible(True)
        
        capacity_info = QLabel("Capacity shows how much of your message fits into the current emoji sequence.")
        capacity_info.setWordWrap(True)
        
        capacity_layout.addWidget(self.capacity_indicator)
        capacity_layout.addWidget(capacity_info)
        capacity_group.setLayout(capacity_layout)
        
        # Encode button and copy button
        encode_buttons_layout = QHBoxLayout()
        encode_button = QPushButton("Encode")
        encode_button.clicked.connect(self.encodeMessage)
        copy_button = QPushButton("Copy to Clipboard")
        copy_button.clicked.connect(lambda: self.copyToClipboard(self.encoded_emoji_label.text()))
        
        encode_buttons_layout.addWidget(encode_button)
        encode_buttons_layout.addWidget(copy_button)
        
        # Encoded result display - using QLabel for better emoji support
        encode_result_label = QLabel("Encoded Emoji:")
        
        # Use a frame with a label for the encoded emoji display
        encoded_frame = QFrame()
        encoded_frame.setFrameShape(QFrame.StyledPanel)
        encoded_frame.setFrameShadow(QFrame.Sunken)
        encoded_frame.setLineWidth(1)
        encoded_frame.setStyleSheet("background-color: #1A1A1A; padding: 10px;")
        
        encoded_frame_layout = QVBoxLayout(encoded_frame)
        self.encoded_emoji_label = QLabel()
        self.encoded_emoji_label.setFont(self.emoji_font)
        self.encoded_emoji_label.setMinimumHeight(70)
        self.encoded_emoji_label.setTextInteractionFlags(Qt.TextSelectableByMouse | Qt.TextSelectableByKeyboard)
        self.encoded_emoji_label.setWordWrap(True)
        self.encoded_emoji_label.setStyleSheet("background-color: transparent;")
        encoded_frame_layout.addWidget(self.encoded_emoji_label)
        
        # Add all widgets to encode layout
        encode_layout.addWidget(emoji_group)
        encode_layout.addLayout(selected_emoji_layout)
        encode_layout.addWidget(sequence_group)
        encode_layout.addWidget(encode_message_label)
        encode_layout.addWidget(self.encode_message)
        encode_layout.addWidget(capacity_group)
        encode_layout.addLayout(encode_buttons_layout)
        encode_layout.addWidget(encode_result_label)
        encode_layout.addWidget(encoded_frame)
        
        # Setup Decode Tab
        decode_layout = QVBoxLayout(decode_tab)
        
        # Input area for encoded emoji - using an editable QTextEdit for better interaction
        decode_input_label = QLabel("Enter or paste encoded emoji sequence:")
        decode_input_info = QLabel("You can edit, add text, or mix emojis with regular text. Only emojis will be decoded.")
        decode_input_info.setWordWrap(True)
        
        # Create a frame for the editable text area
        decode_frame = QFrame()
        decode_frame.setFrameShape(QFrame.StyledPanel)
        decode_frame.setFrameShadow(QFrame.Sunken)
        decode_frame.setLineWidth(1)
        decode_frame.setStyleSheet("background-color: #1A1A1A; padding: 10px;")
        
        decode_frame_layout = QVBoxLayout(decode_frame)
        self.decode_input_text = QTextEdit()
        self.decode_input_text.setFont(self.emoji_font)
        self.decode_input_text.setMinimumHeight(90)
        self.decode_input_text.setStyleSheet("background-color: transparent; border: none;")
        self.decode_input_text.setPlaceholderText("Enter or paste encoded emojis here...")
        decode_frame_layout.addWidget(self.decode_input_text)
        
        # Add paste button for convenience
        paste_button = QPushButton("Paste from Clipboard")
        paste_button.clicked.connect(self.pasteFromClipboard)
        
        # Decode button
        decode_button = QPushButton("Decode")
        decode_button.clicked.connect(self.decodeMessage)
        
        # Decoded message output
        decode_message_label = QLabel("Decoded message:")
        self.decode_message = QTextEdit()
        self.decode_message.setReadOnly(True)
        
        # Copy decoded button
        copy_decoded_button = QPushButton("Copy Decoded Message")
        copy_decoded_button.clicked.connect(lambda: self.copyToClipboard(self.decode_message.toPlainText()))
        
        # Add all widgets to decode layout
        decode_layout.addWidget(decode_input_label)
        decode_layout.addWidget(decode_input_info)
        decode_layout.addWidget(decode_frame)
        decode_layout.addWidget(paste_button)
        decode_layout.addWidget(decode_button)
        decode_layout.addWidget(decode_message_label)
        decode_layout.addWidget(self.decode_message)
        decode_layout.addWidget(copy_decoded_button)
        
        # Setup Draft Tab
        self.setupDraftTab(draft_tab)
        
        # Add tabs to main layout
        main_layout.addWidget(tab_widget)
        
        # Status bar
        self.statusBar().showMessage('Ready')
        
        # Initialize capacity indicator
        self.updateCapacityIndicator()
        
        # Show window
        self.show()
    
    def selectEmoji(self, emoji):
        """Update the currently selected emoji"""
        self.current_emoji = emoji
        self.selected_emoji_label.setText(emoji)
        self.statusBar().showMessage(f'Selected emoji: {emoji}')
    
    def addEmojiToSequence(self):
        """Add current emoji to the sequence"""
        self.selected_emojis.append(self.current_emoji)
        self.updateEmojiSequenceDisplay()
        self.updateCapacityIndicator()
        self.statusBar().showMessage(f'Added {self.current_emoji} to sequence (total: {len(self.selected_emojis)})')
    
    def updateEmojiSequenceDisplay(self):
        """Update the horizontal display of selected emojis"""
        # Clear existing widgets from the layout
        for i in reversed(range(self.emoji_sequence_layout.count())):
            item = self.emoji_sequence_layout.itemAt(i)
            if item and item.widget():
                item.widget().deleteLater()
            elif item and item.spacerItem():
                self.emoji_sequence_layout.removeItem(item)
        
        # Add each emoji as a label
        for emoji in self.selected_emojis:
            emoji_label = QLabel(emoji)
            emoji_label.setFont(self.emoji_font)
            emoji_label.setStyleSheet("padding: 5px; margin: 2px;")
            emoji_label.setAlignment(Qt.AlignLeft)
            self.emoji_sequence_layout.addWidget(emoji_label)
        
        # Add stretch at the end to push everything to the left
        self.emoji_sequence_layout.addStretch(1)
    
    def removeLastEmoji(self):
        """Remove the last emoji from sequence"""
        # Don't remove the last emoji
        if len(self.selected_emojis) <= 1:
            QMessageBox.warning(self, "Warning", "Cannot remove the last emoji from sequence.")
            return
            
        # Remove the last emoji
        removed = self.selected_emojis.pop()
        self.updateEmojiSequenceDisplay()
        self.updateCapacityIndicator()
        self.statusBar().showMessage(f'Removed {removed} from sequence')
    
    def clearEmojiSequence(self):
        """Reset emoji sequence to just the first emoji"""
        if len(self.selected_emojis) <= 1:
            return
            
        first_emoji = self.selected_emojis[0]
        self.selected_emojis = [first_emoji]  # Keep the first emoji
        self.updateEmojiSequenceDisplay()
        self.updateCapacityIndicator()
        self.statusBar().showMessage('Emoji sequence cleared')
    
    def updateCapacityIndicator(self):
        """Update the capacity indicator based on message length and emoji count"""
        message = self.encode_message.toPlainText()
        
        if not message:
            self.capacity_indicator.setValue(0)
            self.capacity_indicator.setFormat("0%")
            return
            
        # Calculate total bits needed for the message
        message_bytes = message.encode('utf-8')
        
        # Each emoji can hold approximately 40 variation selectors × 4 bits = 160 bits = 20 bytes
        max_bytes_per_emoji = self.max_bits_per_emoji // 8
        
        # Estimate how many emojis we need by counting UTF-8 character boundaries
        byte_pos = 0
        emoji_count_needed = 0
        
        # This is a simplified version of what we do in encodeMessage() for estimation
        while byte_pos < len(message_bytes):
            # Each emoji can hold up to max_bytes_per_emoji bytes
            remaining_bytes = len(message_bytes) - byte_pos
            chunk_size = min(max_bytes_per_emoji, remaining_bytes)
            
            # Adjust chunk size to not break UTF-8 characters
            test_pos = byte_pos + chunk_size
            while test_pos > byte_pos:
                try:
                    message_bytes[byte_pos:test_pos].decode('utf-8')
                    break  # Found a valid UTF-8 boundary
                except UnicodeDecodeError:
                    test_pos -= 1
                    
            if test_pos > byte_pos:
                byte_pos = test_pos
                emoji_count_needed += 1
            else:
                # Should never happen with valid UTF-8
                byte_pos += 1
                emoji_count_needed += 1
        
        # Calculate percentage of capacity used
        total_capacity = len(self.selected_emojis) * max_bytes_per_emoji
        used_capacity = len(message_bytes)
        percentage = min(100, (used_capacity / total_capacity) * 100)
        
        # Update progress bar
        self.capacity_indicator.setValue(int(percentage))
        
        # Format the text to show bits/bytes info
        bytes_per_emoji = self.max_bits_per_emoji // 8
        
        # Check if we need more emojis than we have selected
        if emoji_count_needed > len(self.selected_emojis):
            self.capacity_indicator.setFormat(
                f"Need {emoji_count_needed} emojis (have {len(self.selected_emojis)}). Click to auto-fill."
            )
            self.capacity_indicator.setStyleSheet("QProgressBar::chunk { background-color: red; }")
            self.capacity_indicator.setCursor(Qt.PointingHandCursor)
            
            # Make capacity indicator clickable if not already
            if not hasattr(self, 'capacity_indicator_clickable'):
                self.capacity_indicator.mousePressEvent = self.capacityIndicatorClicked
                self.capacity_indicator_clickable = True
                
            self.statusBar().showMessage('Message requires more emojis. Click the capacity bar to auto-fill.')
        else:
            self.capacity_indicator.setFormat(
                f"{percentage:.1f}% ({len(message_bytes)} bytes / {emoji_count_needed} emojis needed)"
            )
            
            # Update color based on capacity
            if percentage > 90:
                self.capacity_indicator.setStyleSheet("QProgressBar::chunk { background-color: orange; }")
            else:
                self.capacity_indicator.setStyleSheet("QProgressBar::chunk { background-color: green; }")
                
            self.statusBar().showMessage('Ready to encode')
    
    def capacityIndicatorClicked(self, event):
        """Handle click on capacity indicator to auto-fill emojis"""
        # Only respond if we need more emojis
        message = self.encode_message.toPlainText()
        if not message:
            return
        
        # Calculate how many emojis we need (simplified version from updateCapacityIndicator)
        message_bytes = message.encode('utf-8')
        max_bytes_per_emoji = self.max_bits_per_emoji // 8
        byte_pos = 0
        emoji_count_needed = 0
        
        while byte_pos < len(message_bytes):
            remaining_bytes = len(message_bytes) - byte_pos
            chunk_size = min(max_bytes_per_emoji, remaining_bytes)
            
            test_pos = byte_pos + chunk_size
            while test_pos > byte_pos:
                try:
                    message_bytes[byte_pos:test_pos].decode('utf-8')
                    break
                except UnicodeDecodeError:
                    test_pos -= 1
                    
            if test_pos > byte_pos:
                byte_pos = test_pos
                emoji_count_needed += 1
            else:
                byte_pos += 1
                emoji_count_needed += 1
        
        # If we need more emojis, ask to add them
        if emoji_count_needed > len(self.selected_emojis):
            self.autoFillEmojis(emoji_count_needed)
    
    def autoFillEmojis(self, emoji_count_needed):
        """Add more emojis to reach the required count"""
        if emoji_count_needed <= len(self.selected_emojis):
            return
            
        reply = QMessageBox.question(
            self, "Auto-Fill Emojis",
            f"Your message requires {emoji_count_needed} emojis, but you've only selected {len(self.selected_emojis)}.\n"
            f"Would you like to automatically add {emoji_count_needed - len(self.selected_emojis)} more emoji(s)?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
        )
        
        if reply == QMessageBox.Yes:
            # Add more emojis from the list
            current_count = len(self.selected_emojis)
            for i in range(emoji_count_needed - current_count):
                emoji_index = (current_count + i) % len(self.emoji_list)
                self.selected_emojis.append(self.emoji_list[emoji_index])
            self.updateEmojiSequenceDisplay()
            self.updateCapacityIndicator()
            self.statusBar().showMessage(f'Added {emoji_count_needed - current_count} emoji(s) to sequence')
            
    def copyToClipboard(self, text):
        """Copy the provided text to clipboard"""
        pyperclip.copy(text)
        self.statusBar().showMessage('Copied to clipboard')
    
    def pasteFromClipboard(self):
        """Paste from clipboard into the decode input field"""
        text = pyperclip.paste()
        self.decode_input_text.setText(text)
        self.statusBar().showMessage('Pasted from clipboard')
    
    def encodeMessage(self):
        """Encode a message into a sequence of emojis using Unicode variation selectors"""
        # Validate inputs
        message = self.encode_message.toPlainText()
        if not message:
            QMessageBox.warning(self, "Warning", "Please enter a message to encode.")
            return
        
        try:
            # Each emoji can hold approximately 40 variation selectors × 4 bits = 160 bits = 20 bytes
            max_bytes_per_emoji = self.max_bits_per_emoji // 8
            
            # Calculate message length and determine how to split it
            message_bytes = message.encode('utf-8')
            
            # Split message into chunks of complete UTF-8 characters
            message_chunks = []
            byte_pos = 0
            
            for i, emoji in enumerate(self.selected_emojis):
                if byte_pos >= len(message_bytes):
                    break
                
                # Determine maximum chunk size for this emoji
                remaining_bytes = len(message_bytes) - byte_pos
                chunk_size = min(max_bytes_per_emoji, remaining_bytes)
                
                # Ensure we're not splitting in the middle of a UTF-8 character
                # UTF-8 characters can be 1-4 bytes
                test_pos = byte_pos + chunk_size
                while test_pos > byte_pos:
                    try:
                        # Try to decode the chunk to ensure it contains complete UTF-8 characters
                        chunk = message_bytes[byte_pos:test_pos]
                        chunk.decode('utf-8')
                        break  # If successful, we've found a valid chunk size
                    except UnicodeDecodeError:
                        # If it fails, we've likely cut in the middle of a character
                        test_pos -= 1
                
                # If we couldn't find a valid UTF-8 boundary, use at least one complete character
                if test_pos == byte_pos:
                    # Find the next character boundary (may exceed max_bytes_per_emoji)
                    for test_size in range(1, 5):  # UTF-8 is max 4 bytes per character
                        if byte_pos + test_size <= len(message_bytes):
                            try:
                                message_bytes[byte_pos:byte_pos + test_size].decode('utf-8')
                                test_pos = byte_pos + test_size
                                break
                            except UnicodeDecodeError:
                                continue
                
                # Get the chunk
                if test_pos > byte_pos:
                    chunk = message_bytes[byte_pos:test_pos]
                    message_chunks.append(chunk)
                    byte_pos = test_pos
                else:
                    # Should never happen with valid UTF-8, but just in case
                    break
            
            # Check if we have enough emojis for all chunks
            if len(message_chunks) > len(self.selected_emojis):
                # Use our dedicated method for auto-fill
                self.autoFillEmojis(len(message_chunks))
                
                # Check again after possible auto-fill
                if len(message_chunks) > len(self.selected_emojis):
                    # User declined auto-fill, so we need to cancel
                    QMessageBox.warning(
                        self, "Encoding Canceled",
                        "Message encoding canceled. Please add more emojis or shorten your message."
                    )
                    return
            
            # Encode each chunk into an emoji
            selectors = [chr(code) for code in range(0xFE00, 0xFE10)]
            encoded_emojis = []
            
            # Add a header to each chunk - first 8 bits represent the chunk length in bytes
            for i, chunk in enumerate(message_chunks):
                if i >= len(self.selected_emojis):
                    break
                
                # Start with the base emoji
                emoji = self.selected_emojis[i]
                encoded = emoji
                
                # First, encode the chunk length (8 bits = 2 nibbles)
                chunk_length = len(chunk)
                length_binary = format(chunk_length, '08b')
                
                # Add length as first byte (using 2 selectors)
                for j in range(0, 8, 4):
                    nibble = int(length_binary[j:j+4], 2)
                    encoded += selectors[nibble]
                
                # Convert the chunk to binary
                chunk_binary = ''.join(format(byte, '08b') for byte in chunk)
                
                # Add selectors for the data
                for j in range(0, len(chunk_binary), 4):
                    if j + 4 <= len(chunk_binary):
                        nibble = int(chunk_binary[j:j+4], 2)
                        encoded += selectors[nibble]
                
                encoded_emojis.append(encoded)
            
            # Store the encoded emojis for the draft tab
            self.encoded_emoji_result = encoded_emojis
            
            # Enable draft tab and update its emoji button
            tab_widget = self.centralWidget().layout().itemAt(0).widget()
            tab_widget.setTabEnabled(self.draft_tab_index, True)
            
            # Reset the emoji index for the draft tab
            self.current_draft_emoji_index = 0
            if self.encoded_emoji_result:
                self.next_emoji_button.setText(self.encoded_emoji_result[0])
                self.next_emoji_button.setEnabled(True)
            
            # Join all encoded emojis into a single string
            result = ''.join(encoded_emojis)
            
            # Display the result
            self.encoded_emoji_label.setText(result)
            self.statusBar().showMessage(f'Message encoded successfully using {len(encoded_emojis)} emojis. Letter Draft tab is now available.')
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred during encoding: {str(e)}")
            self.statusBar().showMessage('Encoding failed')
    
    def is_emoji(self, character):
        """Check if a character is likely an emoji (very basic check)"""
        # This is a very naive check, but works for most common emoji
        # A more comprehensive solution would use the Unicode emoji database
        if len(character) == 0:
            return False
            
        # Get the first character's code point
        code_point = ord(character[0])
        
        # Most emoji are in these ranges
        emoji_ranges = [
            (0x1F000, 0x1FFFF),  # Emoticons, transport & map symbols, etc.
            (0x2600, 0x27BF),    # Misc symbols and dingbats
            (0x2300, 0x23FF),    # Misc technical
            (0x2700, 0x27BF),    # Dingbats
            (0x3000, 0x303F),    # CJK symbols
            (0x1F1E6, 0x1F1FF)   # Regional indicators (flags)
        ]
        
        for start, end in emoji_ranges:
            if start <= code_point <= end:
                return True
                
        # Some common emoji outside these ranges
        common_emoji = [0x231A, 0x231B, 0x263A, 0x2639, 0x270A, 0x270B, 0x270C]
        if code_point in common_emoji:
            return True
            
        return False

    def find_emojis_with_data(self, text):
        """
        Find encoded emoji sequences in the text
        
        Returns a list of tuples (start_pos, emoji_with_data)
        """
        result = []
        i = 0
        
        while i < len(text):
            # If we find a potential emoji character
            if self.is_emoji(text[i]):
                # Find where this emoji data ends
                start_pos = i
                i += 1
                
                # Collect all variation selectors following this emoji
                while i < len(text) and 0xFE00 <= ord(text[i]) <= 0xFE0F:
                    i += 1
                
                # Get the entire emoji with its variation selectors
                emoji_data = text[start_pos:i]
                
                # Only include if it has variation selectors (i.e., it's encoded)
                if len(emoji_data) > 1:
                    result.append((start_pos, emoji_data))
            else:
                i += 1
                
        return result
    
    def decodeMessage(self):
        """Decode a message from a sequence of emojis with Unicode variation selectors"""
        # Validate input
        encoded_text = self.decode_input_text.toPlainText()
        if not encoded_text:
            QMessageBox.warning(self, "Warning", "Please enter or paste text containing encoded emojis.")
            return
        
        try:
            # Find all potential encoded emojis in the text
            emoji_sequences = self.find_emojis_with_data(encoded_text)
            
            if not emoji_sequences:
                QMessageBox.warning(self, "Warning", "No encoded emojis found in the input.")
                return
            
            # Extract and decode data from each emoji separately
            decoded_chunks = []
            decoded_emojis = []
            
            for _, emoji_data in emoji_sequences:
                # Skip if it's just an emoji with no selectors
                if len(emoji_data) <= 1:
                    continue
                
                decoded_emojis.append(emoji_data)
                
                # Extract binary data from this emoji
                selector_values = []
                selector_start = 0xFE00
                
                for char in emoji_data[1:]:  # Skip the emoji itself
                    code_point = ord(char)
                    if 0xFE00 <= code_point <= 0xFE0F:
                        # Get 4 bits from this selector
                        nibble = code_point - selector_start
                        selector_values.append(nibble)
                
                # Need at least 2 selectors (1 byte for length)
                if len(selector_values) < 2:
                    continue
                
                # First byte (2 nibbles) is the length
                chunk_length = (selector_values[0] << 4) | selector_values[1]
                
                # Convert remaining selectors to binary data
                binary_data = ""
                for nibble in selector_values[2:]:
                    binary_data += format(nibble, '04b')
                
                # Convert binary to bytes
                byte_data = bytearray()
                for i in range(0, len(binary_data), 8):
                    if i + 8 <= len(binary_data):
                        byte = int(binary_data[i:i+8], 2)
                        byte_data.append(byte)
                
                # Only use the specified length of data
                byte_data = byte_data[:chunk_length]
                
                # Try to decode as UTF-8
                try:
                    decoded_text = byte_data.decode('utf-8')
                    decoded_chunks.append(decoded_text)
                except UnicodeDecodeError:
                    # If a single emoji can't be decoded, skip it but continue with others
                    continue
            
            if not decoded_chunks:
                QMessageBox.warning(self, "Warning", "No valid data could be decoded from the emojis.")
                return
                
            # Join all decoded chunks
            result = ''.join(decoded_chunks)
            
            # Display decoded text
            self.decode_message.setText(result)
            self.statusBar().showMessage(
                f'Message decoded successfully from {len(decoded_emojis)} emojis'
            )
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred during decoding: {str(e)}")
            self.statusBar().showMessage('Decoding failed')

    def setupDraftTab(self, draft_tab):
        """Setup the Letter Draft tab"""
        draft_layout = QVBoxLayout(draft_tab)
        
        # Add title and instructions
        title_label = QLabel("Draft a Message with Hidden Emojis")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("font-size: 16px; font-weight: bold; margin-bottom: 10px;")
        
        instructions = QLabel("Type your message here. Use the emoji button to insert encoded emojis at the cursor position.")
        instructions.setWordWrap(True)
        
        # Create main content area with text editor and emoji button
        content_layout = QHBoxLayout()
        
        # Letter text editor
        self.draft_text = QTextEdit()
        self.draft_text.setPlaceholderText("Type your letter here...")
        self.draft_text.setMinimumHeight(300)
        self.draft_text.setFont(self.emoji_font)  # Apply emoji font to the text editor
        
        # Emoji insertion panel (right side)
        emoji_panel = QVBoxLayout()
        
        # Create a frame for the emoji button to make it more visible
        emoji_button_frame = QFrame()
        emoji_button_frame.setFrameShape(QFrame.StyledPanel)
        emoji_button_frame.setFrameShadow(QFrame.Raised)
        emoji_button_frame.setStyleSheet("background-color: #2A2A2A;")
        emoji_button_layout = QVBoxLayout(emoji_button_frame)
        
        self.next_emoji_button = QPushButton()
        self.next_emoji_button.setFont(self.emoji_font)
        self.next_emoji_button.setText("😀")  # Default emoji
        self.next_emoji_button.setMinimumSize(80, 80)
        self.next_emoji_button.setMaximumSize(80, 80)
        self.next_emoji_button.clicked.connect(self.insertNextEmoji)
        self.next_emoji_button.setStyleSheet("font-size: 28px;")  # Larger font for emoji
        
        emoji_button_layout.addWidget(self.next_emoji_button)
        
        emoji_label = QLabel("Insert Emoji")
        emoji_label.setAlignment(Qt.AlignCenter)
        
        emoji_panel.addWidget(emoji_button_frame, alignment=Qt.AlignCenter)
        emoji_panel.addWidget(emoji_label, alignment=Qt.AlignCenter)
        emoji_panel.addStretch()
        
        # Add components to layout
        content_layout.addWidget(self.draft_text, stretch=4)
        content_layout.addLayout(emoji_panel, stretch=1)
        
        # Action buttons
        action_layout = QHBoxLayout()
        clear_button = QPushButton("Clear")
        clear_button.clicked.connect(self.clearDraft)
        copy_button = QPushButton("Copy to Clipboard")
        copy_button.clicked.connect(lambda: self.copyToClipboard(self.draft_text.toPlainText()))
        
        action_layout.addWidget(clear_button)
        action_layout.addWidget(copy_button)
        
        # Add all components to the main layout
        draft_layout.addWidget(title_label)
        draft_layout.addWidget(instructions)
        draft_layout.addLayout(content_layout)
        draft_layout.addLayout(action_layout)
        
        # Initially the button should be disabled until encoding happens
        self.next_emoji_button.setEnabled(False)
    
    def insertNextEmoji(self):
        """Insert the next emoji at cursor position in the draft text"""
        if not self.encoded_emoji_result:
            return
            
        # Get the current emoji to insert
        emoji_to_insert = self.encoded_emoji_result[self.current_draft_emoji_index]
        
        # Save current cursor
        cursor = self.draft_text.textCursor()
        
        # Insert at cursor position without overwriting
        cursor.insertText(emoji_to_insert)
        
        # Update to next emoji index (cycle through available emojis)
        self.current_draft_emoji_index = (self.current_draft_emoji_index + 1) % len(self.encoded_emoji_result)
        
        # Update button with next emoji
        self.next_emoji_button.setText(self.encoded_emoji_result[self.current_draft_emoji_index])
        
        # Focus back on the text editor and restore cursor position
        self.draft_text.setFocus()
    
    def clearDraft(self):
        """Clear the draft text area"""
        reply = QMessageBox.question(
            self, "Clear Draft", 
            "Are you sure you want to clear your draft?",
            QMessageBox.Yes | QMessageBox.No, 
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.draft_text.clear()

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
    
    window = EmojiCypher()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main() 