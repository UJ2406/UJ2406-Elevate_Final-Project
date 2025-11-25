import sys
import os
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, 
    QPushButton, QLineEdit, QLabel, QListWidget, QFileDialog, 
    QMessageBox, QTabWidget
)
from PyQt5.QtCore import QSize

# Import the core functions from the CLI script
try:
    from secure_storage import get_fernet_instance, load_metadata, encrypt_file, decrypt_file, generate_pdf_report
except ImportError:
    print("Error: secure_storage.py not found. Make sure it's in the same directory.")
    sys.exit(1)


class SecureFileStorageApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔐 AES Secure File Storage (PyQt5)")
        self.setGeometry(100, 100, 600, 400)
        self.tabs = QTabWidget()
        self.setMinimumSize(QSize(600, 400))
        self.init_ui()

    def init_ui(self):
        # Main layout
        main_layout = QVBoxLayout()
        
        # 1. Encryption Tab
        encrypt_tab = QWidget()
        encrypt_layout = QVBoxLayout()
        
        self.encrypt_path_input = QLineEdit()
        self.encrypt_path_input.setPlaceholderText("Select file to encrypt...")
        
        encrypt_browse_btn = QPushButton("Browse File")
        encrypt_browse_btn.clicked.connect(self.browse_file_for_encryption)
        
        encrypt_btn = QPushButton("Encrypt & Store File")
        encrypt_btn.setStyleSheet("background-color: #4CAF50; color: white;")
        encrypt_btn.clicked.connect(self.run_encryption)
        
        encrypt_layout.addWidget(QLabel("File Path to Encrypt:"))
        
        h_layout_encrypt = QHBoxLayout()
        h_layout_encrypt.addWidget(self.encrypt_path_input)
        h_layout_encrypt.addWidget(encrypt_browse_btn)
        encrypt_layout.addLayout(h_layout_encrypt)
        
        encrypt_layout.addStretch()
        encrypt_layout.addWidget(encrypt_btn)
        
        encrypt_tab.setLayout(encrypt_layout)
        self.tabs.addTab(encrypt_tab, "Encrypt")

        # 2. Decryption & Listing Tab
        decrypt_tab = QWidget()
        decrypt_layout = QVBoxLayout()
        
        # File List
        decrypt_layout.addWidget(QLabel("Available Encrypted Files (Select one for decryption):"))
        self.file_list_widget = QListWidget()
        self.file_list_widget.setMinimumHeight(150)
        decrypt_layout.addWidget(self.file_list_widget)
        
        # Decrypt Button
        decrypt_btn = QPushButton("Decrypt Selected File")
        decrypt_btn.setStyleSheet("background-color: #2196F3; color: white;")
        decrypt_btn.clicked.connect(self.run_decryption)
        
        # Refresh Button
        refresh_btn = QPushButton("Refresh List")
        refresh_btn.clicked.connect(self.refresh_file_list)
        
        h_layout_decrypt = QHBoxLayout()
        h_layout_decrypt.addWidget(refresh_btn)
        h_layout_decrypt.addWidget(decrypt_btn)
        decrypt_layout.addLayout(h_layout_decrypt)
        
        # PDF Report Button
        report_btn = QPushButton("Download PDF Report")
        report_btn.setStyleSheet("background-color: #FF9800; color: white;")
        report_btn.clicked.connect(self.download_report)
        decrypt_layout.addWidget(report_btn)
        
        decrypt_tab.setLayout(decrypt_layout)
        self.tabs.addTab(decrypt_tab, "Decrypt & Retrieve")

        # Final setup
        main_layout.addWidget(self.tabs)
        self.setLayout(main_layout)
        
        # Load list initially
        self.refresh_file_list()

    # --- Slots (Functions called by button clicks) ---
    
    def browse_file_for_encryption(self):
        """Opens a file dialog to select a file."""
        filename, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt")
        if filename:
            self.encrypt_path_input.setText(filename)
            
    def refresh_file_list(self):
        """Loads metadata and populates the list widget."""
        self.file_list_widget.clear()
        try:
            f = get_fernet_instance()
            metadata = load_metadata(f)
            if not metadata:
                self.file_list_widget.addItem("No encrypted files found.")
                return
            
            for enc_name, data in metadata.items():
                list_item_text = f"{enc_name} (Original: {data['original_name']})"
                self.file_list_widget.addItem(list_item_text)
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load metadata: {e}")

    def run_encryption(self):
        """Calls the core encrypt function and displays result."""
        filepath = self.encrypt_path_input.text()
        if not os.path.exists(filepath):
            QMessageBox.warning(self, "Input Error", "Please select a valid file path.")
            return

        # Simple call to the core function
        encrypt_file(filepath) 
        
        QMessageBox.information(self, "Success", f"File '{os.path.basename(filepath)}' encrypted and stored.")
        self.encrypt_path_input.clear()
        self.refresh_file_list()
        self.tabs.setCurrentIndex(1) # Switch to Decrypt tab

    def run_decryption(self):
        """Calls the core decrypt function for the selected file."""
        selected_items = self.file_list_widget.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Selection Error", "Please select an encrypted file from the list.")
            return

        # Extract the encrypted filename (it's the first part of the text)
        full_text = selected_items[0].text()
        encrypted_filename = full_text.split(" (Original:")[0].strip()

        # Simple call to the core function
        # NOTE: The decrypt_file function handles hash verification and disk I/O
        try:
            decrypt_file(encrypted_filename)
            QMessageBox.information(
                self, 
                "Success", 
                f"File '{encrypted_filename}' decrypted successfully and saved in 'decrypted_files/'."
            )
        except Exception as e:
            QMessageBox.critical(self, "Decryption Error", f"A serious error occurred during decryption: {e}")

    def download_report(self):
        """Generates and saves the PDF report."""
        filename, _ = QFileDialog.getSaveFileName(self, "Save Report", "Encrypted_Files_Report.pdf", "PDF Files (*.pdf)")
        if filename:
            try:
                generate_pdf_report(filename)
                QMessageBox.information(self, "Success", f"Report saved to:\n{filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to generate report: {e}")
        
# --- Application Startup ---
if __name__ == '__main__':
    app = QApplication(sys.argv)
    
    # Check for master.key existence early
    try:
        # This will load or generate the key before the GUI starts
        get_fernet_instance() 
    except Exception as e:
        QMessageBox.critical(None, "Fatal Error", f"Could not initialize security key: {e}")
        sys.exit(1)

    ex = SecureFileStorageApp()
    ex.show()
    sys.exit(app.exec_())