"""
Advanced cryptographic utilities for banking application security.

This module provides:
1. AES-256-GCM authenticated encryption for sensitive data
2. ECC-based asymmetric encryption for secure key exchange
3. Digital signatures (ECDSA and RSA-PSS) for non-repudiation
4. HMAC-SHA3 for data integrity verification
5. Secure key management utilities
"""

import os
import base64
import hmac
import logging
import json
from typing import Dict, Optional, Tuple, Union, Any
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidSignature, InvalidTag

from django.conf import settings

# Configure logger
logger = logging.getLogger(__name__)

# Constants
KEY_BYTES = 32  # 256 bits for AES-256
IV_BYTES = 12   # 96 bits for GCM
SALT_BYTES = 16  # 128 bits for key derivation
TAG_BYTES = 16  # 128 bits for GCM authentication tag

class CryptoError(Exception):
    """Base exception for cryptographic operations."""
    pass

# Key derivation functions

def generate_salt() -> bytes:
    """Generate a cryptographically secure random salt."""
    return os.urandom(SALT_BYTES)

def derive_key(passphrase: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    Derive a cryptographic key from a passphrase using PBKDF2.
    
    Args:
        passphrase: The passphrase to derive the key from
        salt: Optional salt, generates a new one if not provided
    
    Returns:
        Tuple of (derived key, salt)
    """
    if not salt:
        salt = generate_salt()
    
    try:
        # Use PBKDF2 with SHA-256 and 100,000 iterations (adjust as needed)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_BYTES,
            salt=salt,
            iterations=100000,
        )
        
        # Derive the key from the passphrase
        key = kdf.derive(passphrase.encode('utf-8'))
        return key, salt
    except Exception as e:
        logger.error(f"Key derivation error: {str(e)}", exc_info=True)
        raise CryptoError(f"Key derivation failed: {str(e)}")

# AES-256-GCM encryption functions

def generate_aes_key() -> bytes:
    """Generate a random AES-256 key."""
    return os.urandom(KEY_BYTES)

def aes_gcm_encrypt(data: Union[str, bytes], key: Optional[bytes] = None) -> Dict[str, str]:
    """
    Encrypt data using AES-256-GCM with authentication.
    
    Args:
        data: The data to encrypt (string or bytes)
        key: Optional encryption key (uses a derived key from settings if not provided)
    
    Returns:
        Dictionary with base64-encoded ciphertext, nonce, and metadata
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
        
    if key is None:
        # In production, key should come from a secure vault
        # Here we derive it from a secret for demo purposes
        master_key, salt = derive_key(settings.SECRET_KEY)
        key_id = "master-" + base64.b64encode(salt).decode('utf-8')[:8]
    else:
        master_key = key
        # Generate a key ID based on a hash of the key
        key_hash = hashes.Hash(hashes.SHA256())
        key_hash.update(master_key)
        key_id = base64.b64encode(key_hash.finalize()).decode('utf-8')[:8]
    
    try:
        # Generate a random nonce (IV)
        nonce = os.urandom(IV_BYTES)
        
        # Create the cipher with AES-GCM mode
        cipher = Cipher(algorithms.AES(master_key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        
        # Encrypt the data
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        # Get the authentication tag
        tag = encryptor.tag
        
        # Return the encrypted data and metadata as base64-encoded strings
        return {
            'ciphertext': base64.b64encode(ciphertext + tag).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'algorithm': 'AES-256-GCM',
            'key_id': key_id,
            'created_at': datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Encryption error: {str(e)}", exc_info=True)
        raise CryptoError(f"Encryption failed: {str(e)}")

def aes_gcm_decrypt(encrypted_data: Dict[str, str], key: Optional[bytes] = None) -> bytes:
    """
    Decrypt data that was encrypted with AES-256-GCM.
    
    Args:
        encrypted_data: Dictionary with base64-encoded ciphertext and nonce
        key: Optional decryption key (uses a derived key from settings if not provided)
    
    Returns:
        Decrypted data as bytes
    """
    try:
        # Decode the ciphertext and nonce
        ciphertext_with_tag = base64.b64decode(encrypted_data['ciphertext'])
        nonce = base64.b64decode(encrypted_data['nonce'])
        
        # The last 16 bytes of the ciphertext is the authentication tag
        if len(ciphertext_with_tag) < TAG_BYTES:
            raise CryptoError("Ciphertext is too short")
        
        ciphertext = ciphertext_with_tag[:-TAG_BYTES]
        tag = ciphertext_with_tag[-TAG_BYTES:]
        
        if key is None:
            # In production, key should come from a secure vault
            # Here we derive it from a secret for demo purposes
            master_key, _ = derive_key(settings.SECRET_KEY)
        else:
            master_key = key
        
        # Create the cipher with AES-GCM mode
        cipher = Cipher(algorithms.AES(master_key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        
        # Decrypt the data
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext
    except InvalidTag:
        logger.warning("Authentication tag verification failed during decryption")
        raise CryptoError("Authentication failed: data may have been tampered with")
    except Exception as e:
        logger.error(f"Decryption error: {str(e)}", exc_info=True)
        raise CryptoError(f"Decryption failed: {str(e)}")

def encrypt_json(data: Dict[str, Any]) -> Dict[str, str]:
    """
    Encrypt a dictionary/JSON object.
    
    Args:
        data: Dictionary to encrypt
    
    Returns:
        Dictionary with encrypted data and metadata
    """
    try:
        # Convert the dictionary to a JSON string
        json_string = json.dumps(data)
        
        # Encrypt the JSON string
        return aes_gcm_encrypt(json_string)
    except Exception as e:
        logger.error(f"JSON encryption error: {str(e)}", exc_info=True)
        raise CryptoError(f"JSON encryption failed: {str(e)}")

def decrypt_json(encrypted_data: Dict[str, str]) -> Dict[str, Any]:
    """
    Decrypt a dictionary/JSON object.
    
    Args:
        encrypted_data: Dictionary with encrypted data and metadata
    
    Returns:
        Decrypted dictionary
    """
    try:
        # Decrypt the data
        decrypted_bytes = aes_gcm_decrypt(encrypted_data)
        
        # Convert the decrypted bytes to a JSON string
        json_string = decrypted_bytes.decode('utf-8')
        
        # Parse the JSON string back to a dictionary
        return json.loads(json_string)
    except Exception as e:
        logger.error(f"JSON decryption error: {str(e)}", exc_info=True)
        raise CryptoError(f"JSON decryption failed: {str(e)}")

# ECC and Hybrid Encryption for secure key exchange

def generate_ecc_key_pair() -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """
    Generate an Elliptic Curve key pair (NIST P-256).
    
    Returns:
        Tuple of (private key, public key)
    """
    try:
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        return private_key, public_key
    except Exception as e:
        logger.error(f"ECC key generation error: {str(e)}", exc_info=True)
        raise CryptoError(f"ECC key generation failed: {str(e)}")

def serialize_public_key(public_key: ec.EllipticCurvePublicKey) -> str:
    """
    Serialize a public key to PEM format.
    
    Args:
        public_key: ECC public key
    
    Returns:
        PEM-encoded public key as string
    """
    try:
        pem_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem_key.decode('utf-8')
    except Exception as e:
        logger.error(f"Public key serialization error: {str(e)}", exc_info=True)
        raise CryptoError(f"Public key serialization failed: {str(e)}")

def deserialize_public_key(pem_key: str) -> ec.EllipticCurvePublicKey:
    """
    Deserialize a public key from PEM format.
    
    Args:
        pem_key: PEM-encoded public key
    
    Returns:
        ECC public key object
    """
    try:
        public_key = serialization.load_pem_public_key(pem_key.encode('utf-8'))
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise CryptoError("The provided key is not an ECC public key")
        return public_key
    except Exception as e:
        logger.error(f"Public key deserialization error: {str(e)}", exc_info=True)
        raise CryptoError(f"Public key deserialization failed: {str(e)}")

def serialize_private_key(private_key: ec.EllipticCurvePrivateKey, passphrase: Optional[str] = None) -> str:
    """
    Serialize a private key to PEM format, optionally encrypted.
    
    Args:
        private_key: ECC private key
        passphrase: Optional passphrase to encrypt the key
    
    Returns:
        PEM-encoded private key as string
    """
    try:
        if passphrase:
            encryption_algorithm = serialization.BestAvailableEncryption(passphrase.encode('utf-8'))
        else:
            encryption_algorithm = serialization.NoEncryption()
            
        pem_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        return pem_key.decode('utf-8')
    except Exception as e:
        logger.error(f"Private key serialization error: {str(e)}", exc_info=True)
        raise CryptoError(f"Private key serialization failed: {str(e)}")

def deserialize_private_key(pem_key: str, passphrase: Optional[str] = None) -> ec.EllipticCurvePrivateKey:
    """
    Deserialize a private key from PEM format.
    
    Args:
        pem_key: PEM-encoded private key
        passphrase: Optional passphrase to decrypt the key
    
    Returns:
        ECC private key object
    """
    try:
        password = passphrase.encode('utf-8') if passphrase else None
        private_key = serialization.load_pem_private_key(
            pem_key.encode('utf-8'),
            password=password
        )
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise CryptoError("The provided key is not an ECC private key")
        return private_key
    except Exception as e:
        logger.error(f"Private key deserialization error: {str(e)}", exc_info=True)
        raise CryptoError(f"Private key deserialization failed: {str(e)}")

def hybrid_encrypt(data: Union[str, bytes], recipient_public_key: ec.EllipticCurvePublicKey) -> Dict[str, str]:
    """
    Encrypt data using hybrid encryption (ECDH + AES-GCM).
    
    Args:
        data: The data to encrypt
        recipient_public_key: Recipient's ECC public key
    
    Returns:
        Dictionary with encrypted data and metadata
    """
    try:
        # Generate an ephemeral key pair
        ephemeral_private_key, ephemeral_public_key = generate_ecc_key_pair()
        
        # Perform ECDH to derive a shared key
        shared_key = ephemeral_private_key.exchange(
            ec.ECDH(),
            recipient_public_key
        )
        
        # Derive an encryption key from the shared secret
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_BYTES,
            salt=os.urandom(SALT_BYTES),
            iterations=10000,
        )
        aes_key = kdf.derive(shared_key)
        
        # Encrypt the data with AES-GCM
        encrypted_data = aes_gcm_encrypt(data, aes_key)
        
        # Add the ephemeral public key for recipient to derive the same shared key
        encrypted_data['ephemeral_public_key'] = serialize_public_key(ephemeral_public_key)
        encrypted_data['encryption_type'] = 'hybrid_ecc_aes_gcm'
        
        return encrypted_data
    except Exception as e:
        logger.error(f"Hybrid encryption error: {str(e)}", exc_info=True)
        raise CryptoError(f"Hybrid encryption failed: {str(e)}")

def hybrid_decrypt(encrypted_data: Dict[str, str], recipient_private_key: ec.EllipticCurvePrivateKey) -> bytes:
    """
    Decrypt data that was encrypted with hybrid encryption.
    
    Args:
        encrypted_data: Dictionary with encrypted data and metadata
        recipient_private_key: Recipient's ECC private key
    
    Returns:
        Decrypted data as bytes
    """
    try:
        # Deserialize the ephemeral public key
        ephemeral_public_key = deserialize_public_key(encrypted_data['ephemeral_public_key'])
        
        # Perform ECDH to derive the same shared key as during encryption
        shared_key = recipient_private_key.exchange(
            ec.ECDH(),
            ephemeral_public_key
        )
        
        # Derive the same encryption key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_BYTES,
            salt=os.urandom(SALT_BYTES),
            iterations=10000,
        )
        aes_key = kdf.derive(shared_key)
        
        # Decrypt the data with AES-GCM
        return aes_gcm_decrypt(encrypted_data, aes_key)
    except Exception as e:
        logger.error(f"Hybrid decryption error: {str(e)}", exc_info=True)
        raise CryptoError(f"Hybrid decryption failed: {str(e)}")

# Digital signature functions (ECDSA and RSA-PSS)

def generate_rsa_key_pair(key_size: int = 3072) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Generate an RSA key pair with the specified key size.
    
    Args:
        key_size: RSA key size in bits (default: 3072 for good security)
    
    Returns:
        Tuple of (private key, public key)
    """
    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,  # Standard public exponent value
            key_size=key_size,
        )
        public_key = private_key.public_key()
        return private_key, public_key
    except Exception as e:
        logger.error(f"RSA key generation error: {str(e)}", exc_info=True)
        raise CryptoError(f"RSA key generation failed: {str(e)}")

def ecdsa_sign(data: Union[str, bytes], private_key: ec.EllipticCurvePrivateKey) -> str:
    """
    Sign data using ECDSA.
    
    Args:
        data: The data to sign
        private_key: ECC private key for signing
    
    Returns:
        Base64-encoded signature
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
        
    try:
        # Sign the data
        signature = private_key.sign(
            data,
            ec.ECDSA(hashes.SHA256())
        )
        
        return base64.b64encode(signature).decode('utf-8')
    except Exception as e:
        logger.error(f"ECDSA signing error: {str(e)}", exc_info=True)
        raise CryptoError(f"ECDSA signing failed: {str(e)}")

def ecdsa_verify(data: Union[str, bytes], signature: str, public_key: ec.EllipticCurvePublicKey) -> bool:
    """
    Verify an ECDSA signature.
    
    Args:
        data: The original data
        signature: Base64-encoded signature
        public_key: ECC public key for verification
    
    Returns:
        True if signature is valid, False otherwise
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
        
    try:
        # Decode the signature
        signature_bytes = base64.b64decode(signature)
        
        # Verify the signature
        public_key.verify(
            signature_bytes,
            data,
            ec.ECDSA(hashes.SHA256())
        )
        
        return True
    except InvalidSignature:
        logger.warning("ECDSA signature verification failed")
        return False
    except Exception as e:
        logger.error(f"ECDSA verification error: {str(e)}", exc_info=True)
        return False

def rsa_pss_sign(data: Union[str, bytes], private_key: rsa.RSAPrivateKey) -> str:
    """
    Sign data using RSA-PSS.
    
    Args:
        data: The data to sign
        private_key: RSA private key for signing
    
    Returns:
        Base64-encoded signature
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
        
    try:
        # Create the signature using PSS padding
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return base64.b64encode(signature).decode('utf-8')
    except Exception as e:
        logger.error(f"RSA-PSS signing error: {str(e)}", exc_info=True)
        raise CryptoError(f"RSA-PSS signing failed: {str(e)}")

def rsa_pss_verify(data: Union[str, bytes], signature: str, public_key: rsa.RSAPublicKey) -> bool:
    """
    Verify an RSA-PSS signature.
    
    Args:
        data: The original data
        signature: Base64-encoded signature
        public_key: RSA public key for verification
    
    Returns:
        True if signature is valid, False otherwise
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
        
    try:
        # Decode the signature
        signature_bytes = base64.b64decode(signature)
        
        # Verify the signature using PSS padding
        public_key.verify(
            signature_bytes,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return True
    except InvalidSignature:
        logger.warning("RSA-PSS signature verification failed")
        return False
    except Exception as e:
        logger.error(f"RSA-PSS verification error: {str(e)}", exc_info=True)
        return False

# HMAC-SHA3 for data integrity
def create_hmac_sha3(data: Union[str, bytes], key: Optional[Union[str, bytes]] = None) -> str:
    """
    Create an HMAC using SHA3-256 for data integrity verification.
    
    Args:
        data: The data to create an HMAC for
        key: The secret key (uses a derived key from settings if not provided)
    
    Returns:
        Base64-encoded HMAC
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
        
    if key is None:
        # Use derived key from settings in production
        # In production, use a separate key from a vault
        master_key, _ = derive_key(settings.SECRET_KEY + "_hmac")
    else:
        if isinstance(key, str):
            key = key.encode('utf-8')
        master_key = key
        
    try:
        # Create the HMAC
        h = hmac.HMAC(master_key, hashes.SHA3_256())
        h.update(data)
        tag = h.finalize()
        
        return base64.b64encode(tag).decode('utf-8')
    except Exception as e:
        logger.error(f"HMAC-SHA3 error: {str(e)}", exc_info=True)
        raise CryptoError(f"HMAC-SHA3 creation failed: {str(e)}")
        

def verify_hmac_sha3(data: Union[str, bytes], hmac_value: str, key: Optional[Union[str, bytes]] = None) -> bool:
    """
    Verify an HMAC using SHA3-256.
    
    Args:
        data: The original data
        hmac_value: Base64-encoded HMAC to verify
        key: The same secret key used to create the HMAC
    
    Returns:
        True if HMAC is valid, False otherwise
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
        
    if key is None:
        # Use the same derived key as in create_hmac_sha3
        master_key, _ = derive_key(settings.SECRET_KEY + "_hmac")
    else:
        if isinstance(key, str):
            key = key.encode('utf-8')
        master_key = key
        
    try:
        # Decode the provided HMAC
        hmac_bytes = base64.b64decode(hmac_value)
        
        # Create a new HMAC
        h = hmac.HMAC(master_key, hashes.SHA3_256())
        h.update(data)
        
        # Verify by comparing the provided HMAC with a newly calculated one
        h.verify(hmac_bytes)
        return True
    except InvalidSignature:
        logger.warning("HMAC-SHA3 verification failed")
        return False
    except Exception as e:
        logger.error(f"HMAC-SHA3 verification error: {str(e)}", exc_info=True)
        return False


# Secure hash functions using SHA-3
def secure_hash_sha3_256(data: Union[str, bytes]) -> str:
    """
    Create a secure hash using SHA3-256.
    
    Args:
        data: The data to hash
    
    Returns:
        Hexadecimal string representation of the hash
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
        
    try:
        digest = hashes.Hash(hashes.SHA3_256())
        digest.update(data)
        hash_value = digest.finalize()
        
        return hash_value.hex()
    except Exception as e:
        logger.error(f"SHA3-256 hash error: {str(e)}", exc_info=True)
        raise CryptoError(f"SHA3-256 hash creation failed: {str(e)}")
        

def secure_hash_sha3_512(data: Union[str, bytes]) -> str:
    """
    Create a secure hash using SHA3-512 for more sensitive data.
    
    Args:
        data: The data to hash
    
    Returns:
        Hexadecimal string representation of the hash
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
        
    try:
        digest = hashes.Hash(hashes.SHA3_512())
        digest.update(data)
        hash_value = digest.finalize()
        
        return hash_value.hex()
    except Exception as e:
        logger.error(f"SHA3-512 hash error: {str(e)}", exc_info=True)
        raise CryptoError(f"SHA3-512 hash creation failed: {str(e)}")


# Key management utilities
class KeyManager:
    """
    Utility for managing cryptographic keys.
    In production, this would interface with a secure key vault like AWS KMS or HashiCorp Vault.
    """
    
    @staticmethod
    def generate_data_encryption_key() -> Dict[str, str]:
        """
        Generate a new data encryption key (DEK).
        
        Returns:
            Dictionary with the key and metadata
        """
        try:
            # Generate a random encryption key
            key = os.urandom(KEY_BYTES)
            key_id = secure_hash_sha3_256(key)[:16]  # Use part of the hash as ID
            
            return {
                'key': base64.b64encode(key).decode('utf-8'),
                'key_id': key_id,
                'created_at': datetime.now().isoformat(),
                'algorithm': 'AES-256-GCM'
            }
        except Exception as e:
            logger.error(f"Key generation error: {str(e)}", exc_info=True)
            raise CryptoError(f"DEK generation failed: {str(e)}")
    
    @staticmethod
    def encrypt_dek_for_storage(dek: Dict[str, str]) -> Dict[str, str]:
        """
        Encrypt a data encryption key (DEK) for secure storage.
        In production, this would use a KMS key encryption key (KEK).
        
        Args:
            dek: A data encryption key dictionary with 'key' in base64
            
        Returns:
            Dictionary with encrypted key and metadata
        """
        try:
            # Get the raw key
            key_bytes = base64.b64decode(dek['key'])
            
            # Encrypt the key with our master key (in production, use a KEK from a vault)
            encrypted = aes_gcm_encrypt(key_bytes)
            
            # Return the encrypted key with metadata
            return {
                'encrypted_key': encrypted['ciphertext'],
                'nonce': encrypted['nonce'],
                'key_id': dek['key_id'],
                'created_at': dek['created_at'],
                'algorithm': dek['algorithm'],
                'kek_id': encrypted['key_id']  # Reference to the key that encrypted this DEK
            }
        except Exception as e:
            logger.error(f"DEK encryption error: {str(e)}", exc_info=True)
            raise CryptoError(f"DEK encryption failed: {str(e)}")
    
    @staticmethod
    def decrypt_dek(encrypted_dek: Dict[str, str]) -> Dict[str, str]:
        """
        Decrypt a data encryption key (DEK) for use.
        
        Args:
            encrypted_dek: Dictionary with encrypted key and metadata
            
        Returns:
            Dictionary with decrypted key and metadata
        """
        try:
            # Decrypt the key
            decrypted_key = aes_gcm_decrypt({
                'ciphertext': encrypted_dek['encrypted_key'],
                'nonce': encrypted_dek['nonce']
            })
            
            # Return the decrypted key with metadata
            return {
                'key': base64.b64encode(decrypted_key).decode('utf-8'),
                'key_id': encrypted_dek['key_id'],
                'created_at': encrypted_dek['created_at'],
                'algorithm': encrypted_dek['algorithm']
            }
        except Exception as e:
            logger.error(f"DEK decryption error: {str(e)}", exc_info=True)
            raise CryptoError(f"DEK decryption failed: {str(e)}")