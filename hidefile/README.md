# HideFile - Steganography Tool

HideFile is a desktop application that allows you to hide any file inside PNG images using steganography techniques. It provides a simple and intuitive graphical user interface for embedding and extracting files with optional encryption.

![HideFile Screenshot](screenshot.png)

## Features

- **Hide Any File**: Embed any type of file inside a PNG image without visibly altering the image
- **Extract Hidden Files**: Retrieve embedded files with their original filenames and extensions
- **Optional Encryption**: Secure your hidden files with AES-256 encryption
- **Visual Preview**: See the PNG images you're working with
- **Dark/Light Mode**: Choose between dark and light themes for comfortable use
- **File Metadata**: Preserves original filename, size, and modification time
- **Drag and Drop Support**: Easily drag PNG images and files directly into the application

## How It Works

HideFile uses a technique called steganography to hide files inside PNG images. Unlike other methods that alter the pixel data (potentially degrading the image), HideFile embeds data by appending it to the last IDAT chunk of the PNG file structure. It then recalculates the CRC checksums and updates the chunk lengths to maintain a valid PNG format.

The embedded data includes:
- A magic marker for reliable detection
- Metadata about the hidden file (name, size, modification time)
- The actual file content (optionally encrypted)

This approach preserves the visual appearance of the PNG while allowing you to hide substantial amounts of data.

## Installation

### Prerequisites
- Python 3.6 or higher

### Steps

1. Obtain the source code by downloading or cloning this repository
   
2. Install the required dependencies using the provided requirements.txt file:
   ```
   pip install -r requirements.txt
   ```

3. Run the application
   ```
   python hidefile.py
   ```

## Usage

### Hiding a File in a PNG

1. Switch to the "Hide File in PNG" tab
2. Select a PNG image using one of these methods:
   - Drag and drop a PNG image onto the preview area
   - Click "Browse..." next to "Cover PNG" to select the PNG image
3. Select the file you want to hide using one of these methods:
   - Drag and drop any file onto the file drop area
   - Click "Browse..." next to "Input File" to select the file
4. Click "Browse..." next to "Output PNG" to choose where to save the resulting PNG
5. If you want to encrypt the data, check the "Encrypt file data" box and provide a password
6. Click "Hide File in PNG" to start the process
7. Wait for the success message

### Extracting a File from a PNG

1. Switch to the "Extract File from PNG" tab
2. Select the PNG image containing hidden data using one of these methods:
   - Drag and drop a PNG image onto the preview area
   - Click "Browse..." next to "Input PNG" to select the PNG image
3. Click "Browse..." next to "Output Directory" to select where the extracted file should be saved
4. Click "Extract File from PNG" to start the process
5. If the file was encrypted, you'll be prompted for the password
6. The file will be extracted with its original filename

## Security Considerations

- The hidden data is not visible to casual inspection, but its presence can be detected by examining the file structure
- If encryption is enabled, the data is secured with AES-256-GCM and a key derived from your password using PBKDF2
- Choose a strong password if encrypting sensitive data
- Remember that the presence of steganography itself is not hidden (someone could detect that the PNG has hidden data)

## Limitations

- The PNG file size will increase by approximately the size of the hidden file
- Very large files may not be suitable for hiding in small PNG images
- The hidden file can only be extracted using this tool or similar ones that understand the format
- Some image processing or optimization tools might strip the hidden data if they rewrite the PNG

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is intended for educational purposes and legitimate uses such as watermarking, privacy-enhancing communication, or digital rights management. Be aware of legal restrictions regarding steganography in your jurisdiction. 