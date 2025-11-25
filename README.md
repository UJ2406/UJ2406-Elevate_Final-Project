# 🔐 Secure File Storage System (with GUI & CLI)

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![PyQt5](https://img.shields.io/badge/GUI-PyQt5-green)
![Cryptography](https://img.shields.io/badge/Security-AES--256-red)
![License](https://img.shields.io/badge/License-MIT-yellow)

A robust, local file encryption tool built with **Python**. It uses **AES-256** encryption to secure your files and includes a modern GUI for easy interaction. Perfect for learning about cybersecurity concepts, file handling, and GUI development in Python.

---

## 📸 Project Gallery

| GUI | CLI |
| :---: | :---: |
| ![GUI Screenshot](https://i.ibb.co/xtK3WqXb/xtK3WqXb.png) | ![CLI Screenshot](https://i.ibb.co/ymTWbsLm/ymTWbsLm.png) |

## 🌟 Features

*   **🔒 AES Encryption**: Uses the `cryptography` library (Fernet) to encrypt files with symmetric keys.
*   **🛡️ Integrity Checks**: Verifies file integrity upon decryption using **SHA256 hashing** to detect tampering.
*   **🖥️ User-Friendly GUI**: Built with **PyQt5**, featuring a tabbed interface for easy navigation.
*   **📂 Metadata Management**: Locally stores original filenames, timestamps, and hashes in a secure, encrypted JSON file.
*   **📄 PDF Reports**: Generates a downloadable PDF report listing all your encrypted files using `reportlab`.
*   **🔑 Key Management**: Automatically generates and manages a `master.key` for encryption.

---

## 🛠️ How It Works
* User selects (CLI or GUI) to encrypt a file; program generates/loads a master key (master.key) and stores it safely.

* File is read, encrypted with AES-256, and saved with a secure, encoded filename.

* SHA256 hash of the encrypted file is calculated and stored in encrypted metadata (metadata.json.enc), along with file details.

* Files can be decrypted (via GUI or CLI) only if the master key matches and tampering checks pass.

* Users can list all encrypted files, retrieve audit details, and generate a PDF report for record-keeping.

---

## 🚀 Getting Started

### Prerequisites
*   Python 3.x installed.

### Installation

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/YOUR_USERNAME/UJ2406-Elevate_Final-Project.git
    cd UJ2406-Elevate_Final-Project
    ```

2.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

### Usage

1.  **Run the App**:

    * **CLI Mode**
    ```bash
    python secure_storage.py
    ```

    * **GUI Mode (PyQt5)**
    ```bash
    python secure_gui.py
    ```
    
3.  **Encrypt**: Select a file in the "Encrypt" tab and click "Encrypt & Store".
4.  **Decrypt**: Go to the "Decrypt" tab, select a file, and click "Decrypt".
5.  **Report**: Click "Download PDF Report" to get a summary of your vault.

---

## 🧠 Concepts Learned

Building this project involves mastering several key software engineering and security concepts:

### 1. Symmetric Encryption (AES)
*   **Concept**: Using the same key for both encryption and decryption.
*   **Implementation**: We use `Fernet` from the `cryptography` library, which implements AES (Advanced Encryption Standard) in CBC mode with a 128-bit key, HMAC for authentication, and PKCS7 padding.

### 2. Hashing & Integrity
*   **Concept**: Ensuring data hasn't been altered.
*   **Implementation**: We calculate the **SHA256** hash of the file *before* encryption and store it. When decrypting, we recalculate the hash of the encrypted file to ensure no one tampered with the bytes on the disk.

### 3. File I/O & Binary Handling
*   **Concept**: Reading and writing files in binary mode (`rb`, `wb`) to handle any file type (images, PDFs, executables), not just text.

### 4. GUI Development (Event-Driven Programming)
*   **Concept**: Creating responsive applications where actions are triggered by user events (clicks, inputs).
*   **Implementation**: Using **PyQt5** signals and slots to connect buttons to Python functions.

### 5. Security automation
*   **Concept**: PDF reporting and safe file listing for compliance/audit needs

---

## 🙋‍♀️ Interview Questions & Answers

If you put this project on your resume, be ready to answer these!

**Q1: Why did you use Symmetric Encryption (AES) instead of Asymmetric (RSA)?**
> **A:** Symmetric encryption is significantly faster and more efficient for large data (like files). Asymmetric encryption is computationally expensive and usually limited to small data sizes (like exchanging keys).

**Q2: How do you ensure the file wasn't tampered with?**
> **A:** I use SHA256 hashing. When a file is encrypted, I calculate its hash and store it securely. Before decrypting, I calculate the hash of the file on disk again. If the hashes don't match, the system rejects the decryption, alerting the user of potential tampering.

**Q3: Where do you store the metadata? Is it safe?**
> **A:** Metadata (original filenames, hashes) is stored in a JSON file. Crucially, this JSON file is *also* encrypted using the same master key, so an attacker cannot read the file structure or see what files are stored.

**Q4: What happens if you lose the `master.key`?**
> **A:** The data is permanently lost. Since AES is a secure algorithm, there is no "backdoor" to recover the data without the key. This highlights the importance of secure key management in real-world apps.

**Q5: What are the advantages of GUI for security tools?**
> **A:** A GUI lowers the technical barrier, making security accessible for non-coders and reducing user error compared to the command line.
---

## 📂 Repository Structure

```text
📦 Secure-File-Storage
 ┣ 📂 encrypted_files      # Stores the actual encrypted .enc files
 ┣ 📂 decrypted_files      # Destination for files you decrypt
 ┣ 📜 secure_gui.py        # 🖥️ Main application entry point (GUI)
 ┣ 📜 secure_storage.py    # ⚙️ Core logic (Encryption, Decryption, PDF Gen)
 ┣ 📜 requirements.txt     # 📦 List of python dependencies
 ┣ 📜 .gitignore           # 🙈 Files to ignore (keys, temp files)
 ┗ 📜 README.md            # 📖 This documentation
```
---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
