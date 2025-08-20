File Protector: Universal File Encryption Tool
A fast, secure, and versatile command-line tool for encrypting and decrypting any file or directory using ChaCha20Poly1305, with features like extension preservation, password backup, and keyring integration. Built for cybersecurity warriors, this tool is perfect for protecting sensitive data, whether you're on a blue team (defending), red team (attacking), or purple team (testing).
Features

Universal Encryption: Encrypt/decrypt any file type (.txt, .jpg, .pdf, etc.) or entire directories.
Extension Preservation: Automatically restores original file extensions (e.g., file.txt.enc → file.txt) during decryption.
Secure Encryption: Uses ChaCha20Poly1305 for authenticated encryption and PBKDF2 with 100,000 iterations for key derivation.
HMAC Integrity: Ensures files can't be tampered with using SHA256-based HMAC.
Password Management: Stores passwords securely in the system keyring (Windows Credential Manager, macOS Keychain, or Linux SecretService).
Encrypted Password Backup: Option to back up passwords in an encrypted file, tied to the machine's hostname for security.
File Expiry: Set expiration dates for encrypted files to limit access after a specified period.
Optimized for Speed: Processes large files with chunked I/O (1MB chunks) and parallelizes directory operations with ThreadPoolExecutor.
Cross-Platform: Works on Windows, macOS, and Linux without requiring admin privileges.

Installation

Install Python 3.8+:Ensure Python is installed:
python3 --version

If not, install it:

Ubuntu/Debian: sudo apt install python3 python3-pip
Fedora: sudo dnf install python3 python3-pip
macOS: brew install python3


Install Dependencies:
pip install -r requirements.txt

Or directly:
pip install cryptography typer keyring


Clone the Repository:
git clone https://github.com/yourusername/file-protector.git
cd file-protector



Usage
Protect a File
Encrypt a file (e.g., secret.txt) with a password and optional backup:
python3 EncDec.py protect secret.txt secret.enc --username alkane --backup-file bak.enc


Enter a strong password when prompted.
Output: secret.enc (encrypted file) and bak.enc (encrypted password backup).
The original extension (.txt) is preserved in metadata.

Decrypt a File
Decrypt the file back to its original form:
python3 EncDec.py decrypt secret.enc decrypted --username alkane


Output: decrypted.txt with the original content and extension.

Protect a Directory
Encrypt all files in a directory:
python3 EncDec.py protect my_folder protected_folder --username alkane --backup-file folder_bak.enc


Output: protected_folder with all files encrypted as .enc.

Decrypt a Directory
Decrypt all .enc files in a directory:
python3 EncDec.py decrypt protected_folder decrypted_folder --username alkane


Output: decrypted_folder with files restored to their original extensions.

Restore Password Backup
If the keyring is cleared, restore the password from the backup file:
python3 EncDec.py restore_backup bak.enc --username alkane


Restores the password to the system keyring for the specified username.

Example
# Create a test file
echo "This is my secret text!" > secret.txt

# Encrypt
python3 EncDec.py protect secret.txt secret.enc --username alkane --backup-file bak.enc

# Decrypt
python3 EncDec.py decrypt secret.enc decrypted --username alkane

# Verify
cat decrypted.txt
# Output: This is my secret text!

Security Considerations
Strengths

ChaCha20Poly1305: Fast and secure authenticated encryption, resistant to side-channel attacks.
HMAC-SHA256: Ensures file integrity, preventing tampering.
Keyring: Passwords are stored securely in the system's credential manager.
Password Backup: Encrypted with a machine-specific key (derived from hostname).
Expiry: Files expire after a set period, adding an extra layer of security.

Potential Weaknesses

Weak passwords reduce PBKDF2 effectiveness. Always use strong passwords.
If the backup file (bak.enc) and hostname are compromised, the password can be recovered.
Without admin checks, keyring access depends on user-level permissions.

