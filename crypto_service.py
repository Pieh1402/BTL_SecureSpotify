import os
import hashlib
import base64
import time
import json
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Random import get_random_bytes
import logging

class CryptoService:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def generate_rsa_keys(self, key_size=1024):
        """Generate RSA key pair"""
        try:
            key = RSA.generate(key_size)
            private_key = key
            public_key = key.publickey()
            
            self.logger.debug(f"Generated RSA {key_size}-bit key pair")
            
            return {
                'private_key': private_key,
                'public_key': public_key,
                'private_pem': private_key.export_key().decode('utf-8'),
                'public_pem': public_key.export_key().decode('utf-8')
            }
        except Exception as e:
            self.logger.error(f"RSA key generation failed: {str(e)}")
            raise
    
    def generate_session_key(self):
        """Generate AES session key (256-bit)"""
        try:
            session_key = get_random_bytes(32)  # 256-bit key
            self.logger.debug("Generated AES-256 session key")
            return session_key
        except Exception as e:
            self.logger.error(f"Session key generation failed: {str(e)}")
            raise
    
    def sign_metadata(self, metadata, private_key):
        """Sign metadata using RSA with SHA-512"""
        try:
            # Convert metadata to JSON string
            metadata_json = json.dumps(metadata, sort_keys=True)
            
            # Create SHA-512 hash
            hash_obj = SHA512.new(metadata_json.encode('utf-8'))
            
            # Sign with RSA private key
            signature = pkcs1_15.new(private_key).sign(hash_obj)
            
            # Encode signature to base64
            signature_b64 = base64.b64encode(signature).decode('utf-8')
            
            self.logger.debug("Metadata signed successfully")
            return signature_b64
            
        except Exception as e:
            self.logger.error(f"Metadata signing failed: {str(e)}")
            raise
    
    def verify_signature(self, metadata, signature_b64, public_key):
        """Verify metadata signature"""
        try:
            # Convert metadata to JSON string
            metadata_json = json.dumps(metadata, sort_keys=True)
            
            # Create SHA-512 hash
            hash_obj = SHA512.new(metadata_json.encode('utf-8'))
            
            # Decode signature from base64
            signature = base64.b64decode(signature_b64)
            
            # Verify signature
            pkcs1_15.new(public_key).verify(hash_obj, signature)
            
            self.logger.debug("Signature verification successful")
            return True
            
        except Exception as e:
            self.logger.error(f"Signature verification failed: {str(e)}")
            return False
    
    def encrypt_session_key(self, session_key, public_key):
        """Encrypt session key with RSA public key using PKCS#1 v1.5 (Topic 14 requirement)"""
        try:
            cipher = PKCS1_v1_5.new(public_key)
            encrypted_key = cipher.encrypt(session_key)
            encrypted_key_b64 = base64.b64encode(encrypted_key).decode('utf-8')
            
            self.logger.debug("Session key encrypted successfully with RSA 1024-bit PKCS#1 v1.5")
            return encrypted_key_b64
            
        except Exception as e:
            self.logger.error(f"Session key encryption failed: {str(e)}")
            raise
    
    def decrypt_session_key(self, encrypted_key_b64, private_key):
        """Decrypt session key with RSA private key"""
        try:
            encrypted_key = base64.b64decode(encrypted_key_b64)
            cipher = PKCS1_v1_5.new(private_key)
            session_key = cipher.decrypt(encrypted_key, None)
            
            if session_key is None:
                raise ValueError("Failed to decrypt session key")
            
            self.logger.debug("Session key decrypted successfully")
            return session_key
            
        except Exception as e:
            self.logger.error(f"Session key decryption failed: {str(e)}")
            raise
    
    def encrypt_file(self, file_content, session_key):
        """Encrypt file using AES-GCM"""
        try:
            # Generate random nonce (12 bytes for GCM)
            nonce = get_random_bytes(12)
            
            # Create AES-GCM cipher
            cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
            
            # Encrypt file content
            ciphertext, tag = cipher.encrypt_and_digest(file_content)
            
            # Encode to base64
            nonce_b64 = base64.b64encode(nonce).decode('utf-8')
            ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
            tag_b64 = base64.b64encode(tag).decode('utf-8')
            
            # Calculate SHA-512 hash of nonce || ciphertext || tag
            hash_input = nonce + ciphertext + tag
            hash_obj = SHA512.new(hash_input)
            hash_hex = hash_obj.hexdigest()
            
            self.logger.debug(f"File encrypted successfully (size: {len(file_content)} bytes)")
            
            return {
                'nonce': nonce,
                'ciphertext': ciphertext,
                'tag': tag,
                'nonce_b64': nonce_b64,
                'ciphertext_b64': ciphertext_b64,
                'tag_b64': tag_b64,
                'hash_hex': hash_hex
            }
            
        except Exception as e:
            self.logger.error(f"File encryption failed: {str(e)}")
            raise
    
    def decrypt_file(self, ciphertext, tag, session_key, nonce=None):
        """Decrypt file using AES-GCM"""
        try:
            # If nonce is not provided, assume it's the first 12 bytes of ciphertext
            if nonce is None:
                nonce = ciphertext[:12]
                ciphertext = ciphertext[12:]
            
            # Create AES-GCM cipher
            cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
            
            # Decrypt and verify
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            
            self.logger.debug(f"File decrypted successfully (size: {len(plaintext)} bytes)")
            return plaintext
            
        except Exception as e:
            self.logger.error(f"File decryption failed: {str(e)}")
            raise ValueError("File decryption/verification failed - file may be corrupted or tampered with")
    
    def verify_file_integrity(self, nonce, ciphertext, tag):
        """Verify file integrity using SHA-512 hash"""
        try:
            # Reconstruct hash
            hash_input = nonce + ciphertext + tag
            hash_obj = SHA512.new(hash_input)
            calculated_hash = hash_obj.hexdigest()
            
            self.logger.debug("File integrity hash calculated")
            return calculated_hash
            
        except Exception as e:
            self.logger.error(f"Integrity verification failed: {str(e)}")
            raise
    
    def simulate_tampering(self, data, tamper_type="modify"):
        """Simulate data tampering for testing"""
        try:
            if tamper_type == "modify" and len(data) > 0:
                # Modify a random byte
                data_list = list(data)
                data_list[0] = (data_list[0] + 1) % 256
                return bytes(data_list)
            elif tamper_type == "truncate" and len(data) > 1:
                # Truncate data
                return data[:-1]
            else:
                return data
                
        except Exception as e:
            self.logger.error(f"Tampering simulation failed: {str(e)}")
            return data
