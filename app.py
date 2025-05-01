from flask import Flask, render_template, request, session, redirect, url_for
from cryptography.fernet import Fernet, InvalidToken
import os
from flask_talisman import Talisman

# Initialize Flask app
app = Flask(__name__, template_folder='templates')
app.secret_key = os.urandom(24)

# Configure Talisman with a custom CSP
csp = {
    'default-src': "'self'",
    'style-src': "'self'",
    'script-src': "'self'"
}
Talisman(app, content_security_policy=csp)

@app.route('/')
def index():
    app.jinja_env.cache = {}
    print("Rendering index.html")
    return render_template('index.html')

@app.route('/generate_keys', methods=['POST'])
def generate_keys():
    key = Fernet.generate_key()
    session['key'] = key
    return redirect(url_for('index'))

@app.route('/encrypt', methods=['POST'])
def encrypt():
    print("Encrypt route called")
    if 'key' not in session:
        print("No key in session")
        return render_template('result.html', action="Encrypt", success=False, result="Error: Please generate a key first.")
    try:
        print("Attempting to encrypt")
        message = request.form['message'].encode()
        if not message:
            return render_template('result.html', action="Encrypt", success=False, result="Error: Message cannot be empty.")
        cipher = Fernet(session['key'])
        ciphertext = cipher.encrypt(message)
        print("Encryption successful")
        return render_template('result.html', action="Encrypt", success=True, result=f"Ciphertext: {ciphertext.hex()}")
    except Exception as e:
        print(f"Encryption error: {str(e)}")
        return render_template('result.html', action="Encrypt", success=False, result=f"Error: Invalid input. {str(e)}")

@app.route('/decrypt', methods=['POST'])
def decrypt():
    print("Decrypt route called")
    if 'key' not in session:
        print("No key in session")
        return render_template('result.html', action="Decrypt", success=False, result="Error: Please generate a key first.")
    try:
        print("Attempting to decrypt")
        ciphertext = bytes.fromhex(request.form['ciphertext'])
        cipher = Fernet(session['key'])
        decrypted_message = cipher.decrypt(ciphertext)
        print("Decryption successful")
        return render_template('result.html', action="Decrypt", success=True, result=f"Decrypted Message: {decrypted_message.decode()}")
    except (InvalidToken, ValueError) as e:
        print(f"Decryption error: {str(e)}")
        return render_template('result.html', action="Decrypt", success=False, result=f"Error: Invalid ciphertext or key. {str(e)}")

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)