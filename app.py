import os
import logging
import base64
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
import time
import json
from crypto_service import CryptoService
from socket_service import SocketService

# Configure logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "spotify-secure-file-sharing-2024")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configuration
UPLOAD_FOLDER = 'uploads'
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
ALLOWED_EXTENSIONS = {'mp3', 'wav', 'flac', 'txt', 'pdf', 'doc', 'docx', 'jpg', 'png', 'mp4', 'avi'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize services
crypto_service = CryptoService()
socket_service = SocketService()



def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'GET':
        return render_template('upload.html')
    
    try:
        # Check if file was uploaded
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        
        # Validate filename first
        if not file.filename:
            flash('Tên file không hợp lệ', 'error')
            return redirect(request.url)
            
        if not allowed_file(file.filename):
            flash('File type not allowed', 'error')
            return redirect(request.url)
        
        # Secure the filename
        filename = secure_filename(file.filename)
        timestamp = int(time.time())
        unique_filename = f"{timestamp}_{filename}"
        
        # Read file content
        file_content = file.read()
        file_size = len(file_content)
        
        app.logger.info(f"Starting upload process for file: {filename} ({file_size} bytes)")
        
        # Step 1: Handshake
        app.logger.info("Step 1: Performing handshake...")
        handshake_result = socket_service.handshake()
        if not handshake_result['success']:
            flash(f'Handshake failed: {handshake_result["message"]}', 'error')
            return redirect(request.url)
        
        # Step 2: Authentication & Key Exchange
        app.logger.info("Step 2: Performing authentication and key exchange...")
        
        # Generate RSA keys and session key
        rsa_keys = crypto_service.generate_rsa_keys()
        session_key = crypto_service.generate_session_key()
        
        # Create metadata
        metadata = {
            'filename': filename,
            'timestamp': timestamp,
            'file_size': file_size
        }
        
        # Sign metadata
        metadata_signature = crypto_service.sign_metadata(metadata, rsa_keys['private_key'])
        
        # Encrypt session key with RSA
        encrypted_session_key = crypto_service.encrypt_session_key(session_key, rsa_keys['public_key'])
        
        # Send authentication data
        auth_result = socket_service.send_authentication({
            'metadata': metadata,
            'signature': metadata_signature,
            'encrypted_session_key': encrypted_session_key,
            'public_key': rsa_keys['public_key']
        })
        
        if not auth_result['success']:
            flash(f'Authentication failed: {auth_result["message"]}', 'error')
            return redirect(request.url)
        
        # Step 3: Encryption & Integrity Check
        app.logger.info("Step 3: Encrypting file and checking integrity...")
        
        # Encrypt file with AES-GCM
        encryption_result = crypto_service.encrypt_file(file_content, session_key)
        
        # Create data packet (Topic 14 format)
        data_packet = {
            'nonce': encryption_result['nonce_b64'],
            'cipher': encryption_result['ciphertext_b64'],
            'tag': encryption_result['tag_b64'],
            'hash': encryption_result['hash_hex'],
            'sig': metadata_signature
        }
        
        # Optional: Simulate tampering for testing (Topic 14 demonstration)
        if request.form.get('simulate_tampering') == 'true':
            app.logger.info("Simulating data tampering for testing...")
            # Tamper with ciphertext to test detection
            import base64 as b64
            original_cipher = data_packet['cipher']
            tampered_data = crypto_service.simulate_tampering(
                b64.b64decode(original_cipher), 
                "modify"
            )
            data_packet['cipher'] = b64.b64encode(tampered_data).decode('utf-8')
            app.logger.warning("Data packet tampered for testing - should trigger NACK")
        
        # Save packet info to JSON file for documentation
        packet_info = {
            "upload_info": {
                "file_id": unique_filename,
                "original_filename": filename,
                "upload_time": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))
            },
            "socket_packet": {
                "nonce": data_packet['nonce'],
                "cipher": data_packet['cipher'],
                "tag": data_packet['tag'],
                "hash": data_packet['hash'],
                "sig": data_packet['sig']
            },
            "protocol_details": {
                "encryption": "AES-GCM với 16-byte authentication tag",
                "key_exchange": "RSA 1024-bit PKCS#1 v1.5",
                "hash_algorithm": "SHA-512(nonce || ciphertext || tag)",
                "signature": "RSA signature with SHA-512",
                "description": "Gói tin được upload qua socket, mô phỏng khả năng sửa đổi dữ liệu"
            }
        }
        
        # Save packet to packets folder
        packets_folder = os.path.join(UPLOAD_FOLDER, 'packets')
        os.makedirs(packets_folder, exist_ok=True)
        packet_file = os.path.join(packets_folder, f"{unique_filename}_packet.json")
        with open(packet_file, 'w', encoding='utf-8') as f:
            json.dump(packet_info, f, indent=2, ensure_ascii=False)

        # Send encrypted file
        upload_result = socket_service.upload_file(data_packet, unique_filename)
        
        if upload_result['success']:
            # Store file info for download
            file_info = {
                'original_filename': filename,
                'stored_filename': unique_filename,
                'session_key': session_key.hex(),
                'metadata': metadata,
                'timestamp': timestamp
            }
            
            # Store file info in a simple JSON file (in production, use a database)
            info_file = os.path.join(UPLOAD_FOLDER, f"{unique_filename}.info")
            with open(info_file, 'w') as f:
                json.dump(file_info, f)
            
            # Create a user-friendly key file for easy access
            key_info = {
                'file_id': unique_filename,
                'session_key': session_key.hex(),
                'original_filename': filename,
                'upload_time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp)),
                'instructions': {
                    'vi': 'Sử dụng file_id và session_key để download file',
                    'en': 'Use file_id and session_key to download the file'
                }
            }
            
            # Save to keys folder
            keys_folder = os.path.join(UPLOAD_FOLDER, 'keys')
            os.makedirs(keys_folder, exist_ok=True)
            key_file = os.path.join(keys_folder, f"{unique_filename}_keys.json")
            with open(key_file, 'w', encoding='utf-8') as f:
                json.dump(key_info, f, indent=2, ensure_ascii=False)
            
            # Save encrypted file with nonce + ciphertext + tag
            encrypted_file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
            with open(encrypted_file_path, 'wb') as f:
                f.write(encryption_result['nonce'] + encryption_result['ciphertext'] + encryption_result['tag'])
            
            # Redirect to success page with session key display
            return render_template('upload_success.html', 
                                 file_id=unique_filename,
                                 session_key=session_key.hex(),
                                 original_filename=filename)
        else:
            flash(f'Upload failed: {upload_result["message"]}', 'error')
            return redirect(request.url)
            
    except Exception as e:
        app.logger.error(f"Upload error: {str(e)}")
        flash(f'Upload error: {str(e)}', 'error')
        return redirect(request.url)

@app.route('/download', methods=['GET'])
def download_file():
    try:
        files = []
        for filename in os.listdir(UPLOAD_FOLDER):
            if filename.endswith('.info'):
                info_file = os.path.join(UPLOAD_FOLDER, filename)
                with open(info_file, 'r') as f:
                    file_info = json.load(f)
                    files.append({
                        'file_id': file_info['stored_filename'],
                        'original_name': file_info['original_filename'],
                        'size': file_info['metadata']['file_size'],
                        'upload_time': time.strftime('%Y-%m-%d %H:%M:%S', 
                                                     time.localtime(file_info['timestamp']))
                    })
        # Truyền files ra template download.html
        return render_template('download.html', files=files)
    except Exception as e:
        app.logger.error(f"Error loading files: {str(e)}")
        flash(f'Lỗi tải danh sách file: {str(e)}', 'error')
        return render_template('download.html', files=[])


# Route 2: Xử lý tải file về (auto lấy key, kiểm integrity)
@app.route('/download-auto', methods=['POST'])
def download_file_auto():
    try:
        file_id = request.form.get('file_id')
        if not file_id:
            flash('Thiếu thông tin file!', 'error')
            return redirect(url_for('download_file'))

        info_file = os.path.join(UPLOAD_FOLDER, f"{file_id}.info")
        encrypted_file_path = os.path.join(UPLOAD_FOLDER, file_id)
        
        if not os.path.exists(info_file) or not os.path.exists(encrypted_file_path):
            flash('File không tồn tại', 'error')
            return redirect(url_for('download_file'))

        with open(info_file, 'r') as f:
            file_info = json.load(f)
        session_key = bytes.fromhex(file_info['session_key'])
        
        # Đọc file mã hóa
        with open(encrypted_file_path, 'rb') as f:
            encrypted_data = f.read()
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:-16]
        tag = encrypted_data[-16:]

        try:
            decrypted_content = crypto_service.decrypt_file(ciphertext, tag, session_key, nonce)
            temp_filename = f"decrypted_{file_info['original_filename']}"
            temp_path = os.path.join(UPLOAD_FOLDER, temp_filename)
            with open(temp_path, 'wb') as f:
                f.write(decrypted_content)
            return send_file(
                temp_path,
                as_attachment=True,
                download_name=file_info['original_filename'],
                mimetype='application/octet-stream'
            )
        except Exception as decrypt_error:
            app.logger.error(f"AES-GCM tag verification failed: {str(decrypt_error)}")
            flash('Phát hiện sửa đổi dữ liệu hoặc khóa phiên không đúng!', 'error')
            return redirect(url_for('download_file'))

    except Exception as e:
        app.logger.error(f"Download error: {str(e)}")
        flash(f'Lỗi tải xuống: {str(e)}', 'error')
        return redirect(url_for('download_file'))
@app.route('/files')
def list_files():
    """List all uploaded files"""
    try:
        files = []
        for filename in os.listdir(UPLOAD_FOLDER):
            if filename.endswith('.info'):
                info_file = os.path.join(UPLOAD_FOLDER, filename)
                with open(info_file, 'r') as f:
                    file_info = json.load(f)
                    files.append({
                        'file_id': file_info['stored_filename'],
                        'original_name': file_info['original_filename'],
                        'size': file_info['metadata']['file_size'],
                        'upload_time': time.strftime('%Y-%m-%d %H:%M:%S', 
                                                   time.localtime(file_info['timestamp']))
                    })
        
        return render_template('index.html', files=files)
    except Exception as e:
        app.logger.error(f"Error listing files: {str(e)}")
        flash(f'Error loading files: {str(e)}', 'error')
        return render_template('index.html', files=[])

@app.route('/keys')
def list_keys():
    """List all saved file keys"""
    try:
        keys_folder = os.path.join(UPLOAD_FOLDER, 'keys')
        keys = []
        
        if os.path.exists(keys_folder):
            for filename in os.listdir(keys_folder):
                if filename.endswith('_keys.json'):
                    key_file = os.path.join(keys_folder, filename)
                    with open(key_file, 'r', encoding='utf-8') as f:
                        key_info = json.load(f)
                        keys.append(key_info)
        
        # Sort by upload time (newest first)
        keys.sort(key=lambda x: x.get('upload_time', ''), reverse=True)
        
        return render_template('keys_list.html', keys=keys)
    except Exception as e:
        app.logger.error(f"Error listing keys: {str(e)}")
        flash(f'Lỗi khi tải danh sách keys: {str(e)}', 'error')
        return render_template('keys_list.html', keys=[])

@app.route('/packets')
def list_packets():
    """List all saved socket packets"""
    try:
        packets_folder = os.path.join(UPLOAD_FOLDER, 'packets')
        packets = []
        
        if os.path.exists(packets_folder):
            for filename in os.listdir(packets_folder):
                if filename.endswith('_packet.json'):
                    packet_file = os.path.join(packets_folder, filename)
                    with open(packet_file, 'r', encoding='utf-8') as f:
                        packet_info = json.load(f)
                        packets.append(packet_info)
        
        # Sort by upload time (newest first)
        packets.sort(key=lambda x: x.get('upload_info', {}).get('upload_time', ''), reverse=True)
        
        return render_template('packets_list.html', packets=packets)
    except Exception as e:
        app.logger.error(f"Error listing packets: {str(e)}")
        flash(f'Lỗi khi tải danh sách packets: {str(e)}', 'error')
        return render_template('packets_list.html', packets=[])

@app.route('/download-project')
def download_project():
    """Download entire project as ZIP"""
    import zipfile
    import tempfile
    from werkzeug.utils import secure_filename
    
    try:
        # Create temporary zip file
        temp_dir = tempfile.mkdtemp()
        zip_path = os.path.join(temp_dir, 'SpotifySecure_Project.zip')
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Add all Python files
            for root, dirs, files in os.walk('.'):
                # Skip hidden directories and files
                dirs[:] = [d for d in dirs if not d.startswith('.') and d != '__pycache__']
                
                for file in files:
                    if file.startswith('.'):
                        continue
                    
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, '.')
                    zipf.write(file_path, arcname)
        
        # Send file
        return send_file(zip_path, 
                        as_attachment=True, 
                        download_name='SpotifySecure_Project.zip',
                        mimetype='application/zip')
                        
    except Exception as e:
        app.logger.error(f"Error creating project ZIP: {str(e)}")
        flash(f'Lỗi khi tạo file ZIP: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.errorhandler(413)
def too_large(e):
    flash('File too large. Maximum size is 100MB.', 'error')
    return redirect(url_for('upload_file'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=4000, debug=True)













