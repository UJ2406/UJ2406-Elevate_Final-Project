# Secure File Storage System

A local file encryption tool built with Python and PyQt5. It uses AES encryption (via the `cryptography` library) to securely store files.

## Features
- **AES Encryption**: Securely encrypt files using Fernet (symmetric encryption).
- **Integrity Checks**: Verifies file integrity upon decryption using SHA256 hashes.
- **GUI**: User-friendly interface built with PyQt5.
- **Metadata Management**: Keeps track of original filenames and encryption details locally.
- **PDF Reports**: Generate a downloadable PDF report of all your encrypted files.

## Installation

1.  **Clone the repository** (or download the source code).
2.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1.  **Run the Application**:
    ```bash
    python secure_gui.py
    ```
2.  **Encrypt a File**:
    - Go to the "Encrypt" tab.
    - Browse and select a file.
    - Click "Encrypt & Store File".
3.  **Decrypt a File**:
    - Go to the "Decrypt & Retrieve" tab.
    - Select a file from the list.
    - Click "Decrypt Selected File".
    - The file will be saved in the `decrypted_files` directory.
4.  **Download Report**:
    - Go to the "Decrypt & Retrieve" tab.
    - Click "Download PDF Report" to save a summary of your files.

## Security Note
This tool generates a `master.key` file on the first run. **DO NOT LOSE THIS KEY.** If you lose it, you cannot decrypt your files. **DO NOT SHARE THIS KEY.** Anyone with this key can decrypt your files.
