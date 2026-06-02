"""
CH512 Core - Python bindings for C library
"""

import ctypes
import os
import sys
import secrets
from pathlib import Path
from typing import Union, Tuple

class CH512:
    """Main interface for CH512"""
    
    def __init__(self):
        """Load native library"""
        self._lib = None
        self._load_library()
    
    def _load_library(self):
        """Load appropriate shared library for the platform"""
        lib_dir = Path(__file__).parent / 'bin'
        
        if sys.platform == 'win32':
            lib_name = 'ch512.dll'
        elif sys.platform == 'darwin':
            lib_name = 'libch512.dylib'
        else:
            lib_name = 'libch512.so'
        
        lib_path = lib_dir / lib_name
        
        # If not found, look in current directory
        if not lib_path.exists():
            lib_path = Path.cwd() / 'bin' / lib_name
        
        if not lib_path.exists():
            raise FileNotFoundError(
                f"CH512 library not found. "
                f"Searched in: {lib_path}\n"
                f"Install with: pip install ch512-crypto --no-binary :all:"
            )
        
        self._lib = ctypes.CDLL(str(lib_path))
        self._setup_functions()
    
    def _setup_functions(self):
        """Configure C function prototypes"""
        
        # PBKDF2
        self._lib.kdf_pbkdf2.argtypes = [
            ctypes.c_char_p,   # password
            ctypes.c_size_t,   # pass_len
            ctypes.c_char_p,   # salt
            ctypes.c_size_t,   # salt_len
            ctypes.c_char_p,   # output
            ctypes.c_size_t    # output_len
        ]
        self._lib.kdf_pbkdf2.restype = None
        
        # GCM Encrypt
        self._lib.ch512_gcm_encrypt.argtypes = [
            ctypes.c_void_p,   # ctx (not used directly here)
            ctypes.c_char_p,   # iv
            ctypes.c_size_t,   # iv_len
            ctypes.c_char_p,   # plain
            ctypes.c_size_t,   # plain_len
            ctypes.c_char_p,   # cipher
            ctypes.c_char_p    # tag
        ]
        self._lib.ch512_gcm_encrypt.restype = None
        
        # GCM Decrypt
        self._lib.ch512_gcm_decrypt.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_char_p
        ]
        self._lib.ch512_gcm_decrypt.restype = ctypes.c_int
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive 512-bit key from password"""
        key = ctypes.create_string_buffer(64)
        self._lib.kdf_pbkdf2(
            password.encode('utf-8'),
            len(password),
            salt,
            len(salt),
            key,
            64
        )
        return key.raw
    
    def encrypt(self, plaintext: Union[str, bytes], password: str) -> bytes:
        """
        Encrypt data with password
        
        Args:
            plaintext: Data to encrypt (string or bytes)
            password: Password to derive key from
        
        Returns:
            bytes: Salt (16) + IV (12) + Tag (16) + Ciphertext
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Generate random salt and IV
        salt = secrets.token_bytes(16)
        iv = secrets.token_bytes(12)
        
        # Derive key
        key = self._derive_key(password, salt)
        
        # Initialize context (simplified - for real use use CLI)
        # Note: Full implementation requires C context
        # Working version: use CLI binary via subprocess
        
        return self._encrypt_via_cli(plaintext, password)
    
    def decrypt(self, ciphertext: bytes, password: str) -> bytes:
        """
        Decrypt data with password
        
        Args:
            ciphertext: Encrypted data (salt + IV + tag + ciphertext)
            password: Password to derive key from
        
        Returns:
            bytes: Decrypted plaintext
        """
        return self._decrypt_via_cli(ciphertext, password)
    
    def _encrypt_via_cli(self, plaintext: bytes, password: str) -> bytes:
        """Safe wrapper via CLI (most reliable method)"""
        import tempfile
        import subprocess
        
        with tempfile.NamedTemporaryFile(delete=False) as fin:
            fin.write(plaintext)
            fin_path = fin.name
        
        with tempfile.NamedTemporaryFile(delete=False) as fout:
            out_path = fout.name
        
        try:
            # Find binary
            bin_dir = Path(__file__).parent / 'bin'
            enc_bin = bin_dir / 'ch512_enc'
            if not enc_bin.exists():
                enc_bin = Path.cwd() / 'bin' / 'ch512_enc'
            
            if sys.platform == 'win32':
                enc_bin = str(enc_bin) + '.exe'
            
            # Execute
            result = subprocess.run(
                [str(enc_bin), fin_path, out_path, password],
                capture_output=True,
                check=True
            )
            
            with open(out_path, 'rb') as f:
                ciphertext = f.read()
            
            return ciphertext
            
        finally:
            os.unlink(fin_path)
            if os.path.exists(out_path):
                os.unlink(out_path)
    
    def _decrypt_via_cli(self, ciphertext: bytes, password: str) -> bytes:
        """Decrypt via CLI"""
        import tempfile
        import subprocess
        
        with tempfile.NamedTemporaryFile(delete=False) as fin:
            fin.write(ciphertext)
            fin_path = fin.name
        
        with tempfile.NamedTemporaryFile(delete=False) as fout:
            out_path = fout.name
        
        try:
            bin_dir = Path(__file__).parent / 'bin'
            dec_bin = bin_dir / 'ch512_dec'
            if not dec_bin.exists():
                dec_bin = Path.cwd() / 'bin' / 'ch512_dec'
            
            if sys.platform == 'win32':
                dec_bin = str(dec_bin) + '.exe'
            
            result = subprocess.run(
                [str(dec_bin), fin_path, out_path, password],
                capture_output=True,
                check=True
            )
            
            with open(out_path, 'rb') as f:
                plaintext = f.read()
            
            return plaintext
            
        except subprocess.CalledProcessError as e:
            raise ValueError("Decryption failed: wrong password or corrupted data") from e
        finally:
            os.unlink(fin_path)
            if os.path.exists(out_path):
                os.unlink(out_path)
    
    def encrypt_file(self, input_path: str, output_path: str, password: str):
        """Encrypt a file directly"""
        import subprocess
        
        bin_dir = Path(__file__).parent / 'bin'
        enc_bin = bin_dir / 'ch512_enc'
        if sys.platform == 'win32':
            enc_bin = str(enc_bin) + '.exe'
        
        subprocess.run([str(enc_bin), input_path, output_path, password], check=True)
    
    def decrypt_file(self, input_path: str, output_path: str, password: str):
        """Decrypt a file directly"""
        import subprocess
        
        bin_dir = Path(__file__).parent / 'bin'
        dec_bin = bin_dir / 'ch512_dec'
        if sys.platform == 'win32':
            dec_bin = str(dec_bin) + '.exe'
        
        subprocess.run([str(dec_bin), input_path, output_path, password], check=True)