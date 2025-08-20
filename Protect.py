import typer
import os
import sys
import time
import logging
import keyring
import socket
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Tuple

app = typer.Typer(help="Optimized universal file protector with extension preservation and password backup")
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
CHUNK_SIZE = 1024 * 1024  # 1MB chunks for efficient I/O

def generate_key(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
    """Generate key using PBKDF2 with optimized iterations."""
    if not salt:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,  # Reduced for speed, still secure
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key, salt

def save_password(service: str, username: str, password: str):
    """Store password securely using keyring."""
    keyring.set_password(service, username, password)
    logging.debug(f"Password stored for {username}")

def load_password(service: str, username: str) -> str:
    """Load password from keyring."""
    password = keyring.get_password(service, username)
    if not password:
        raise ValueError(f"No password for {username} in keyring")
    return password

def backup_password(password: str, backup_file: str, hostname: str):
    """Backup password to an encrypted file."""
    backup_key, backup_salt = generate_key(hostname)
    nonce = os.urandom(12)
    chacha = ChaCha20Poly1305(backup_key)
    encrypted_pass = chacha.encrypt(nonce, password.encode(), None)
    
    with open(backup_file, 'wb') as f:
        f.write(backup_salt + nonce + encrypted_pass)
    logging.warning(f"Password backed up to {backup_file}. Keep secure!")

def restore_backup_password(backup_file: str, hostname: str) -> str:
    """Restore password from backup file."""
    with open(backup_file, 'rb') as f:
        data = f.read()
    backup_salt = data[:16]
    nonce = data[16:28]
    encrypted_pass = data[28:]
    
    backup_key, _ = generate_key(hostname, backup_salt)
    chacha = ChaCha20Poly1305(backup_key)
    return chacha.decrypt(nonce, encrypted_pass, None).decode()

def process_file_protect(input_file: str, output_file: str, key: bytes, expiry: int):
    """Process a single file for encryption with chunking."""
    # Read file in chunks
    ext = os.path.splitext(input_file)[1].encode()
    ext_len = len(ext).to_bytes(1, 'big')
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    hmac_salt = os.urandom(16)
    
    with open(output_file, 'wb') as f_out:
        f_out.write(key[16:32])  # Use part of key as salt for simplicity
        f_out.write(nonce)
        f_out.write(hmac_salt)
        
        # Initialize HMAC
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(hmac_salt)
        
        # Write metadata
        encrypted_metadata = chacha.encrypt(nonce, ext_len + ext, None)
        f_out.write(encrypted_metadata)
        h.update(encrypted_metadata)
        
        # Process file in chunks
        with open(input_file, 'rb') as f_in:
            while chunk := f_in.read(CHUNK_SIZE):
                encrypted_chunk = chacha.encrypt(nonce, chunk, None)
                f_out.write(encrypted_chunk)
                h.update(encrypted_chunk)
        
        # Write expiry
        expiry_bytes = str(expiry).encode()
        encrypted_expiry = chacha.encrypt(nonce, expiry_bytes, None)
        f_out.write(encrypted_expiry)
        h.update(encrypted_expiry)
        
        # Write HMAC tag
        f_out.write(h.finalize())
    
    logging.debug(f"Protected {input_file} -> {output_file}")

def process_file_decrypt(protected_file: str, output_file: str, key: bytes):
    """Process a single file for decryption with chunking."""
    with open(protected_file, 'rb') as f_in:
        salt = f_in.read(16)
        nonce = f_in.read(12)
        hmac_salt = f_in.read(16)
        data = f_in.read()
    
    # Verify HMAC
    tag = data[-32:]
    encrypted_data = data[:-32]
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(hmac_salt + encrypted_data)
    h.verify(tag)
    
    chacha = ChaCha20Poly1305(key)
    
    # Decrypt metadata
    metadata_end = 128  # Max size for encrypted metadata (1 byte len + ext)
    encrypted_metadata = encrypted_data[:metadata_end]
    decrypted_metadata = chacha.decrypt(nonce, encrypted_metadata, None)
    ext_len = int.from_bytes(decrypted_metadata[:1], 'big')
    ext = decrypted_metadata[1:1+ext_len].decode()
    
    # Decrypt expiry
    expiry_start = len(encrypted_data) - 128  # Max size for encrypted expiry
    encrypted_expiry = encrypted_data[expiry_start:]
    expiry = int(chacha.decrypt(nonce, encrypted_expiry, None).decode())
    if time.time() > expiry:
        raise ValueError(f"File {protected_file} has expired!")
    
    # Decrypt file content
    encrypted_content = encrypted_data[metadata_end:expiry_start]
    if not output_file.endswith(ext):
        output_file += ext
    
    with open(output_file, 'wb') as f_out:
        for i in range(0, len(encrypted_content), 128):  # ChaCha20Poly1305 max chunk size
            chunk = encrypted_content[i:i+128]
            if chunk:
                f_out.write(chacha.decrypt(nonce, chunk, None))
    
    logging.debug(f"Decrypted {protected_file} -> {output_file}")

@app.command()
def protect(
    input_path: str,
    output_path: str,
    username: str = "default_user",
    password: str = typer.Option(None, prompt=True, hide_input=True),
    expiry_days: int = typer.Option(30, help="Days until file expires"),
    backup_file: str = typer.Option(None, help="File to backup password (encrypted)")
):
    """Protect any file or directory with ChaCha20Poly1305 encryption, preserving extensions."""
    hostname = socket.gethostname()
    save_password("file_protector", username, password)
    if backup_file:
        backup_password(password, backup_file, hostname)
    
    key, _ = generate_key(password)
    expiry = int(time.time() + expiry_days * 86400)
    
    if os.path.isfile(input_path):
        process_file_protect(input_path, output_path, key, expiry)
    elif os.path.isdir(input_path):
        os.makedirs(output_path, exist_ok=True)
        files_to_process = [
            (os.path.join(root, file), os.path.join(output_path, os.path.relpath(root, input_path), file + '.enc'))
            for root, _, files in os.walk(input_path)
            for file in files
        ]
        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(process_file_protect, in_file, out_file, key, expiry)
                       for in_file, out_file in files_to_process]
            for future in as_completed(futures):
                future.result()  # Raise any exceptions
    else:
        raise ValueError("Input path must be a file or directory")
    typer.echo("Protection completed!")

@app.command()
def decrypt(
    protected_path: str,
    output_path: str,
    username: str = "default_user"
):
    """Decrypt protected file or directory, restoring original extensions."""
    password = load_password("file_protector", username)
    key, _ = generate_key(password)
    
    if os.path.isfile(protected_path):
        process_file_decrypt(protected_path, output_path, key)
    elif os.path.isdir(protected_path):
        os.makedirs(output_path, exist_ok=True)
        files_to_process = [
            (os.path.join(root, file), os.path.join(output_path, os.path.relpath(root, protected_path), file[:-4]))
            for root, _, files in os.walk(protected_path)
            for file in files if file.endswith('.enc')
        ]
        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(process_file_decrypt, in_file, out_file, key)
                       for in_file, out_file in files_to_process]
            for future in as_completed(futures):
                future.result()
    else:
        raise ValueError("Protected path must be a file or directory")
    typer.echo("Decryption completed!")

@app.command()
def restore_backup(
    backup_file: str,
    username: str = "default_user"
):
    """Restore password from backup file to keyring."""
    hostname = socket.gethostname()
    password = restore_backup_password(backup_file, hostname)
    save_password("file_protector", username, password)
    typer.echo(f"Password restored to keyring for {username}!")

if __name__ == "__main__":
    app()