import time
import random
import logging
import json

class SocketService:
    """Simulated socket service for cryptographic protocol demonstration"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.connection_established = False
        self.authenticated = False
        self.session_data = {}
        
    def handshake(self):
        """Simulate socket handshake protocol"""
        try:
            self.logger.info("Initiating handshake...")
            
            # Simulate network delay
            time.sleep(0.1)
            
            # Step 1: Send "Hello!" to Spotify cloud simulation (Topic 14)
            self.logger.info("Client: Sending 'Hello!' to Spotify cloud simulation")
            
            # Simulate potential network issues (5% failure rate)
            if random.random() < 0.05:
                self.logger.error("Network error during handshake with Spotify cloud")
                return {
                    'success': False,
                    'message': 'Kết nối mạng thất bại trong quá trình handshake với Spotify cloud'
                }
            
            # Step 2: Receive "Ready!" from Spotify cloud
            self.logger.info("Spotify Cloud: Responding 'Ready!'")
            
            self.connection_established = True
            self.logger.info("Handshake completed successfully")
            
            return {
                'success': True,
                'message': 'Handshake completed successfully',
                'server_response': 'Ready!'
            }
            
        except Exception as e:
            self.logger.error(f"Handshake failed: {str(e)}")
            return {
                'success': False,
                'message': f'Handshake error: {str(e)}'
            }
    
    def send_authentication(self, auth_data):
        """Simulate sending authentication data"""
        try:
            if not self.connection_established:
                return {
                    'success': False,
                    'message': 'Connection not established'
                }
            
            self.logger.info("Sending authentication data...")
            
            # Simulate authentication processing
            time.sleep(0.2)
            
            # Store authentication data
            self.session_data['auth'] = auth_data
            
            # Simulate authentication verification (95% success rate)
            if random.random() < 0.95:
                self.authenticated = True
                self.logger.info("Authentication successful")
                return {
                    'success': True,
                    'message': 'Authentication successful'
                }
            else:
                self.logger.error("Authentication failed")
                return {
                    'success': False,
                    'message': 'Authentication failed - invalid signature'
                }
                
        except Exception as e:
            self.logger.error(f"Authentication error: {str(e)}")
            return {
                'success': False,
                'message': f'Authentication error: {str(e)}'
            }
    
    def upload_file(self, data_packet, filename):
        """Simulate file upload with integrity checking"""
        try:
            if not self.authenticated:
                return {
                    'success': False,
                    'message': 'Not authenticated'
                }
            
            self.logger.info(f"Uploading file: {filename}")
            
            # Simulate upload processing
            time.sleep(0.3)
            
            # Simulate integrity checking
            self.logger.info("Verifying file integrity...")
            
            # Check if all required fields are present
            required_fields = ['nonce', 'cipher', 'tag', 'hash', 'sig']
            for field in required_fields:
                if field not in data_packet:
                    return {
                        'success': False,
                        'message': f'Missing required field: {field}',
                        'response': 'NACK'
                    }
            
            # Simulate tampering detection with AES-GCM tags (Topic 14 requirement)
            # 85% success rate to simulate potential tampering detection
            if random.random() < 0.85:
                self.logger.info("Hash, signature, and AES-GCM tag verification successful")
                self.logger.info("Cloud tái tạo tag từ nonce, ciphertext, và SessionKey - Tag verification passed")
                
                # Simulate successful upload to Spotify cloud
                self.session_data['uploaded_files'] = self.session_data.get('uploaded_files', [])
                self.session_data['uploaded_files'].append({
                    'filename': filename,
                    'upload_time': time.time(),
                    'data_packet': data_packet
                })
                
                self.logger.info(f"File podcast.mp3 saved on Spotify cloud as {filename}")
                return {
                    'success': True,
                    'message': 'File uploaded successfully to Spotify cloud',
                    'response': 'ACK',
                    'file_id': filename
                }
            else:
                self.logger.error("Tampering detected: AES-GCM tag mismatch - ciphertext or nonce modified")
                return {
                    'success': False,
                    'message': 'Phát hiện sửa đổi: Tag AES-GCM không khớp (ciphertext hoặc nonce bị thay đổi)',
                    'response': 'NACK'
                }
                
        except Exception as e:
            self.logger.error(f"Upload error: {str(e)}")
            return {
                'success': False,
                'message': f'Upload error: {str(e)}',
                'response': 'NACK'
            }
    
    def request_download(self, download_request):
        """Simulate download request authentication"""
        try:
            if not self.connection_established:
                return {
                    'success': False,
                    'message': 'Connection not established'
                }
            
            self.logger.info("Processing download request...")
            
            # Simulate authentication processing
            time.sleep(0.2)
            
            # Simulate signature verification (95% success rate)
            if random.random() < 0.95:
                self.logger.info("Download request authenticated")
                return {
                    'success': True,
                    'message': 'Download request authenticated'
                }
            else:
                self.logger.error("Download authentication failed")
                return {
                    'success': False,
                    'message': 'Download authentication failed - invalid signature',
                    'response': 'NACK'
                }
                
        except Exception as e:
            self.logger.error(f"Download request error: {str(e)}")
            return {
                'success': False,
                'message': f'Download request error: {str(e)}'
            }
    
    def send_ack(self, message="Operation successful"):
        """Send ACK response"""
        try:
            self.logger.info(f"Sending ACK: {message}")
            return {
                'success': True,
                'response': 'ACK',
                'message': message
            }
        except Exception as e:
            self.logger.error(f"ACK send error: {str(e)}")
            return {
                'success': False,
                'message': f'ACK send error: {str(e)}'
            }
    
    def send_nack(self, message="Operation failed"):
        """Send NACK response"""
        try:
            self.logger.info(f"Sending NACK: {message}")
            return {
                'success': False,
                'response': 'NACK',
                'message': message
            }
        except Exception as e:
            self.logger.error(f"NACK send error: {str(e)}")
            return {
                'success': False,
                'message': f'NACK send error: {str(e)}'
            }
    
    def disconnect(self):
        """Simulate connection disconnection"""
        try:
            self.logger.info("Disconnecting...")
            self.connection_established = False
            self.authenticated = False
            self.session_data = {}
            
            return {
                'success': True,
                'message': 'Disconnected successfully'
            }
        except Exception as e:
            self.logger.error(f"Disconnect error: {str(e)}")
            return {
                'success': False,
                'message': f'Disconnect error: {str(e)}'
            }
    
    def get_connection_status(self):
        """Get current connection status"""
        return {
            'connected': self.connection_established,
            'authenticated': self.authenticated,
            'session_data': self.session_data
        }
