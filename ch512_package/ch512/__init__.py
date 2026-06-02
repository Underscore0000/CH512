"""
CH512 - CrashHybrid Cipher
Block cipher with 512-bit key, GCM authentication, PBKDF2

Usage examples:
    
    >>> from ch512 import CH512
    >>> cipher = CH512()
    >>> 
    >>> # Encrypt with password
    >>> ciphertext = cipher.encrypt(b"Secret message", "my_password")
    >>> 
    >>> # Decrypt
    >>> plaintext = cipher.decrypt(ciphertext, "my_password")
    >>> 
    >>> # Encrypt file
    >>> cipher.encrypt_file("document.txt", "document.enc", "password")
    >>> 
    >>> # Decrypt file
    >>> cipher.decrypt_file("document.enc", "document.txt", "password")
"""

from .core import CH512

__version__ = '2.0.0'
__author__ = 'Survival Team'
__license__ = 'MIT'

__all__ = ['CH512']