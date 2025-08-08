# Import necessary libraries
from flask import Flask, render_template, request, send_file, redirect, url_for, flash
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

# Initialize the Flask app
app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Required for flashing messages (e.g., success or error)

# Define upload directory and key file path
UPLOAD_FOLDER = 'uploads'           # Directory to store encrypted files
KEY_PATH = 'keys/key.bin'           # Path to the AES key

# Create necessary directories if they don't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(os.path.dirname(KEY_PATH), exist_ok=True)

# Generate AES key if it does not already exist
if not os.path.exists(KEY_PATH):
    key = get_random_bytes(16)  # 128-bit AES key
    with open(KEY_PATH, 'wb') as f:
        f.write(key)

# Load the AES key from file
with open(KEY_PATH, 'rb') as f:
    key = f.read()

# Function to encrypt file data using AES EAX mode
def encrypt_file(data):
    cipher = AES.new(key, AES.MODE_EAX)                # Create a new AES cipher object with EAX mode
    ciphertext, tag = cipher.encrypt_and_digest(data)  # Encrypt and create tag for verification
    return cipher.nonce + tag + ciphertext             # Combine nonce, tag, and ciphertext for storage

# Function to decrypt file data using AES EAX mode
def decrypt_file(data):
    nonce = data[:16]                          # Extract the nonce
    tag = data[16:32]                          # Extract the tag
    ciphertext = data[32:]                     # Extract the actual ciphertext
    cipher = AES.new(key, AES.MODE_EAX, nonce) # Recreate the cipher object with the same nonce
    return cipher.decrypt_and_verify(ciphertext, tag)  # Decrypt and verify the integrity

# Route to render homepage with file list
@app.route('/')
def index():
    files = os.listdir(UPLOAD_FOLDER)     # Get list of encrypted files in upload directory
    return render_template('index.html', files=files)  # Render homepage with file listing

# Route to handle file upload
@app.route('/upload', methods=['POST'])
def upload_file():
    uploaded_file = request.files['file']  # Get uploaded file from the form
    if uploaded_file:
        filename = secure_filename(uploaded_file.filename)  # Sanitize the filename
        data = uploaded_file.read()                         # Read file content
        encrypted_data = encrypt_file(data)                 # Encrypt file content
        save_path = os.path.join(UPLOAD_FOLDER, filename + '.enc')  # Save as .enc file
        with open(save_path, 'wb') as f:
            f.write(encrypted_data)
        flash(f"{filename} uploaded and encrypted successfully!")  # Flash success message
    return redirect(url_for('index'))  # Redirect back to homepage

# Route to handle file download and decryption
@app.route('/download/<filename>')
def download_file(filename):
    path = os.path.join(UPLOAD_FOLDER, filename)  # Get the full path of the encrypted file
    with open(path, 'rb') as f:
        encrypted_data = f.read()                # Read encrypted file content
    try:
        decrypted_data = decrypt_file(encrypted_data)  # Attempt to decrypt the file
    except Exception as e:
        return f"Decryption failed: {str(e)}"          # Show error if decryption fails
    original_filename = filename.replace('.enc', '')   # Remove .enc to get original filename
    temp_path = os.path.join("uploads", original_filename)  # Path to temporarily save decrypted file
    with open(temp_path, 'wb') as f:
        f.write(decrypted_data)  # Write decrypted content to a temporary file
    return send_file(temp_path, as_attachment=True)  # Send the decrypted file to user for download

# Start the Flask app
if __name__ == '__main__':
    app.run(debug=True)  # Run in debug mode for development
