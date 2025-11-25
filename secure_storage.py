import os
import json
import hashlib
from base64 import urlsafe_b64encode
from datetime import datetime
from cryptography.fernet import Fernet
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# --- Configuration ---
KEY_FILE = "master.key"
METADATA_FILE = "metadata.json.enc"
STORAGE_DIR = "encrypted_files"

# --- Core Functions ---

def load_or_generate_key(key_file=KEY_FILE):
    """Loads the Fernet key or generates a new one if it doesn't exist."""
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            key = f.read()
        print(f"Key loaded from {key_file}")
    else:
        key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(key)
        print(f"New key generated and saved to {key_file}. KEEP IT SAFE!")
    return key

def get_fernet_instance():
    """Returns a Fernet instance using the master key."""
    key = load_or_generate_key()
    return Fernet(key)

def calculate_hash(filepath):
    """Calculates the SHA256 hash of a file."""
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as file:
        while chunk := file.read(4096):
            hasher.update(chunk)
    return hasher.hexdigest()

# --- Metadata Management (Self-Encrypted) ---

def load_metadata(f):
    """Loads and decrypts the metadata file."""
    if not os.path.exists(METADATA_FILE):
        return {}
    
    with open(METADATA_FILE, 'rb') as f_in:
        encrypted_data = f_in.read()
    
    try:
        decrypted_data = f.decrypt(encrypted_data)
        return json.loads(decrypted_data)
    except Exception as e:
        print(f"Error decrypting metadata: {e}")
        return {}

def save_metadata(f, metadata):
    """Encrypts and saves the metadata file."""
    metadata_json = json.dumps(metadata).encode()
    encrypted_data = f.encrypt(metadata_json)
    
    with open(METADATA_FILE, 'wb') as f_out:
        f_out.write(encrypted_data)
    print(f"Metadata saved and encrypted to {METADATA_FILE}")

# --- Main Operations ---

def encrypt_file(input_filepath):
    """Encrypts the file, calculates its hash, and stores metadata."""
    if not os.path.exists(input_filepath):
        print(f"Error: File not found at {input_filepath}")
        return

    f = get_fernet_instance()
    
    # 1. Encryption
    with open(input_filepath, 'rb') as file_in:
        file_data = file_in.read()
    
    encrypted_data = f.encrypt(file_data)
    
    # 2. Save encrypted file
    filename = os.path.basename(input_filepath)
    encrypted_filename = f"{urlsafe_b64encode(filename.encode()).decode()}.enc"
    output_filepath = os.path.join(STORAGE_DIR, encrypted_filename)

    os.makedirs(STORAGE_DIR, exist_ok=True)
    with open(output_filepath, 'wb') as file_out:
        file_out.write(encrypted_data)
        
    # 3. Calculate and Store Metadata
    file_hash = calculate_hash(output_filepath)
    
    metadata = load_metadata(f)
    metadata[encrypted_filename] = {
        "original_name": filename,
        "hash_sha256": file_hash,
        "encrypted_path": output_filepath,
        "timestamp": os.path.getmtime(input_filepath)
    }
    save_metadata(f, metadata)
    
    print(f"\n✅ File '{filename}' encrypted successfully.")
    print(f"   Stored as: {output_filepath}")

def decrypt_file(encrypted_filename, output_dir="decrypted_files"):
    """Decrypts a file and verifies its integrity using the stored hash."""
    f = get_fernet_instance()
    metadata = load_metadata(f)

    if encrypted_filename not in metadata:
        print(f"Error: Encrypted file '{encrypted_filename}' not found in metadata.")
        return
        
    entry = metadata[encrypted_filename]
    encrypted_filepath = entry["encrypted_path"]
    original_name = entry["original_name"]
    stored_hash = entry["hash_sha256"]

    if not os.path.exists(encrypted_filepath):
        print(f"Error: Encrypted file not found on disk at {encrypted_filepath}")
        return

    # 1. Integrity Check (Pre-decryption)
    current_hash = calculate_hash(encrypted_filepath)
    if current_hash != stored_hash:
        print("\n❌ INTEGRITY FAILURE: The file has been TAMPERED with!")
        print("   Stored Hash: ", stored_hash)
        print("   Current Hash:", current_hash)
        return
    print("✅ Integrity check passed (SHA256 hash verified).")

    # 2. Decryption
    with open(encrypted_filepath, 'rb') as file_in:
        encrypted_data = file_in.read()
        
    try:
        decrypted_data = f.decrypt(encrypted_data)
    except Exception as e:
        print(f"❌ Decryption failed. Key mismatch or corrupted data: {e}")
        return

    # 3. Save decrypted file
    os.makedirs(output_dir, exist_ok=True)
    output_filepath = os.path.join(output_dir, original_name)
    
    with open(output_filepath, 'wb') as file_out:
        file_out.write(decrypted_data)

    print(f"\n✅ File decrypted successfully.")
    print(f"   Saved as: {output_filepath}")

def list_files():
    """Lists all files available for decryption."""
    f = get_fernet_instance()
    metadata = load_metadata(f)
    
    if not metadata:
        print("No files currently stored.")
        return

    print("\n--- Stored Encrypted Files ---")
    print("{:<35} | {:<25} | {:<10}".format("Encrypted Filename", "Original Filename", "Path"))
    print("-" * 75)
    for enc_name, data in metadata.items():
        print("{:<35} | {:<25} | {:<10}".format(enc_name, data["original_name"], data["encrypted_path"]))
    print("-" * 75)

def generate_pdf_report(output_path):
    """Generates a PDF report of all encrypted files."""
    f = get_fernet_instance()
    metadata = load_metadata(f)
    
    c = canvas.Canvas(output_path, pagesize=letter)
    width, height = letter
    
    # Title
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, height - 50, "Secure File Storage - Encrypted Files Report")
    
    c.setFont("Helvetica", 10)
    c.drawString(50, height - 70, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    y = height - 100
    c.setFont("Helvetica-Bold", 10)
    # Headers
    c.drawString(50, y, "Original Filename")
    c.drawString(250, y, "Encrypted Filename")
    c.drawString(450, y, "Timestamp")
    
    y -= 20
    c.line(50, y + 15, 550, y + 15)
    
    c.setFont("Helvetica", 9)
    if not metadata:
        c.drawString(50, y, "No encrypted files found.")
    else:
        for enc_name, data in metadata.items():
            original_name = data.get("original_name", "Unknown")
            # Truncate long names
            if len(original_name) > 35:
                original_name = original_name[:32] + "..."
            
            timestamp = data.get("timestamp", 0)
            date_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M')
            
            c.drawString(50, y, original_name)
            c.drawString(250, y, enc_name)
            c.drawString(450, y, date_str)
            
            y -= 20
            if y < 50: # New page if out of space
                c.showPage()
                y = height - 50
                
    c.save()
    print(f"PDF Report generated at: {output_path}")

def cli():
    """The main command-line interface."""
    while True:
        print("\n--- Secure Storage System ---")
        print("1. Encrypt & Store File")
        print("2. Decrypt & Retrieve File")
        print("3. List Stored Files")
        print("4. Exit")
        
        choice = input("Enter your choice (1-4): ")
        
        if choice == '1':
            filepath = input("Enter the full path of the file to encrypt: ")
            encrypt_file(filepath)
            
        elif choice == '2':
            list_files()
            filename = input("Enter the ENCRYPTED FILENAME to decrypt (e.g., UmpfMT...Ync.enc): ")
            decrypt_file(filename)
            
        elif choice == '3':
            list_files()
            
        elif choice == '4':
            print("Exiting application. Goodbye!")
            break
            
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    cli()