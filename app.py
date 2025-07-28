from flask import Flask, render_template, request, send_file, redirect, url_for, flash
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Required for flashing messages

UPLOAD_FOLDER = 'uploads'
KEY_PATH = 'keys/key.bin'

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(os.path.dirname(KEY_PATH), exist_ok=True)

# Generate AES key if not exists
if not os.path.exists(KEY_PATH):
    key = get_random_bytes(16)  # 128-bit key
    with open(KEY_PATH, 'wb') as f:
        f.write(key)

# Load AES key
with open(KEY_PATH, 'rb') as f:
    key = f.read()

# Encrypt file
def encrypt_file(data):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ciphertext

# Decrypt file
def decrypt_file(data):
    nonce = data[:16]
    tag = data[16:32]
    ciphertext = data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

@app.route('/')
def index():
    files = os.listdir(UPLOAD_FOLDER)
    return render_template('index.html', files=files)

@app.route('/upload', methods=['POST'])
def upload_file():
    uploaded_file = request.files['file']
    if uploaded_file:
        filename = secure_filename(uploaded_file.filename)
        data = uploaded_file.read()
        encrypted_data = encrypt_file(data)
        save_path = os.path.join(UPLOAD_FOLDER, filename + '.enc')
        with open(save_path, 'wb') as f:
            f.write(encrypted_data)
        flash(f"{filename} uploaded and encrypted successfully!")
    return redirect(url_for('index'))

@app.route('/download/<filename>')
def download_file(filename):
    path = os.path.join(UPLOAD_FOLDER, filename)
    with open(path, 'rb') as f:
        encrypted_data = f.read()
    try:
        decrypted_data = decrypt_file(encrypted_data)
    except Exception as e:
        return f"Decryption failed: {str(e)}"
    original_filename = filename.replace('.enc', '')
    temp_path = os.path.join("uploads", original_filename)
    with open(temp_path, 'wb') as f:
        f.write(decrypted_data)
    return send_file(temp_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
