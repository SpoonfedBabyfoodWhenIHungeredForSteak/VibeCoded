# Cypher - Image Steganography Tool

Cypher is a graphical steganography application that allows you to hide text messages within images using the Least Significant Bit (LSB) technique. It includes optional AES-256 encryption for enhanced security.

![Cypher Image Steganography](https://example.com/screenshot.png)

## Features

- **LSB Steganography**: Hide messages by modifying the least significant bits of image pixels
- **Channel Selection**: Choose between red, green, or blue color channels for encoding
- **Adjustable Density**: Control encoding density by setting step size between modified pixels
- **Strong Encryption**: Optional AES-256 encryption with password protection
- **User-friendly Interface**: Easy-to-use graphical interface with progress indicators
- **Lossless Format Support**: Compatible with PNG and other lossless image formats
- **Multi-platform**: Works on Windows, macOS, and Linux

## Installation

### Requirements

- Python 3.6 or higher
- Dependencies listed in `requirements.txt`

### Setup

1. Clone or download this repository
2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

3. Make the script executable (Unix-based systems):

```bash
chmod +x imgsteg.py
```

## Usage

### Running the Application

```bash
./imgsteg.py
```

Or alternatively:

```bash
python3 imgsteg.py
```

### Encoding a Message

1. Click the **Browse** button to select an input image
2. Configure encoding settings:
   - **Encode every N pixels**: Higher values reduce detection risk but lower capacity
   - **Modify channel**: Select which color channel to modify (red, green, or blue)
   - **Enable encryption**: Optional password protection with AES-256
3. Enter your message in the text area
4. Click **Encode Message**
5. Choose where to save the output image (PNG format recommended)
6. Wait for the encoding process to complete

### Decoding a Message

1. Click the **Browse** button to select an image containing a hidden message
2. Set the same configuration parameters used during encoding:
   - Same step size (N pixels)
   - Same color channel
   - Password (if encryption was used)
3. Click **Decode Message**
4. The hidden message will appear in the text area

## How It Works

### Steganography Technique

Cypher uses the Least Significant Bit (LSB) steganography technique, which works by replacing the least significant bit of selected pixel color values with bits from the message. This causes imperceptible changes to the image while storing the message data.

The first 32 bits encode the message length, followed by the actual message data (8 bits per character).

### Encryption Details

When encryption is enabled:
- Password is processed through PBKDF2 key derivation with 100,000 iterations
- AES-256-GCM authenticated encryption is used
- A random salt and nonce ensure security
- The encrypted message is prefixed with "ENCRYPTED:" in the encoded data

## Security Considerations

- **Image Format**: Always use lossless formats like PNG. JPEG and other lossy formats will destroy hidden data.
- **Password Strength**: If using encryption, choose a strong, unique password.
- **Metadata**: The tool doesn't modify image metadata, which could reveal steganographic intent.
- **Statistical Analysis**: Large messages may create detectable patterns in the image.

## Capacity Calculator

Maximum message capacity can be estimated with:

```
(Image width × height) ÷ (Step size × 8) - 4 = Maximum characters
```

## License

This software is distributed under the MIT License. See the LICENSE file for more information.

## Acknowledgements

- Steganography implementation based on LSB principles
- Encryption utilizing Python's cryptography library
- UI built with PyQt5

---

**Disclaimer**: This tool is provided for educational and legitimate purposes only. Always respect privacy, copyright, and applicable laws when using steganography. 