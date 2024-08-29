from flask import Flask, render_template, request, redirect, url_for, send_from_directory
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os
import secrets
import base64
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'enc', 'zip', 'mp4', 'mp3','docx'}

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def derive_key(password: str):
    """Deriva una clave AES a partir de una contraseña usando PBKDF2."""
    salt = b'\x00' * 16  # En producción, utiliza un salt aleatorio y almacénalo
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

def encrypt_file(file_path, password: str):
    """Cifra un archivo usando AES con una clave derivada de la contraseña."""
    key = derive_key(password)    
    with open(file_path, 'rb') as f:
        data = f.read()

    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    encrypted_file_path = file_path + '.enc'
    with open(encrypted_file_path, 'wb') as f:
        f.write(iv + encrypted_data)

    return encrypted_file_path

def decrypt_file(file_path, password: str):
    """Descifra un archivo usando AES con una clave derivada de la contraseña."""
    key = derive_key(password)
    
    if not file_path.endswith('.enc'):
        raise ValueError("El archivo no está cifrado")

    with open(file_path, 'rb') as f:
        iv = f.read(16)
        encrypted_data = f.read()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    
    decrypted_file_path = file_path.replace('.enc','')

    indice_punto = decrypted_file_path.rfind('.')
    
    # Si se encontró un punto
    if indice_punto != -1:
        # Extrae la parte desde el final hasta el punto
        extension = decrypted_file_path[indice_punto:]
        # Extrae la parte restante
        resultado_final = decrypted_file_path[:indice_punto]
    else:
        # Si no se encontró un punto, asignar la cadena original a parte_extraida y resultado_final
        extension = ''
        resultado_final = decrypted_file_path

    decrypted_file_path=resultado_final+'_decrypted'+extension

    with open(decrypted_file_path, 'wb') as f:
        f.write(data)

    return decrypted_file_path

def encrypt_text(text: str, password: str) -> str:
    """Cifra un texto usando AES con una clave derivada de la contraseña."""
    key = derive_key(password)
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(text.encode()) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_data).decode('utf-8')

def decrypt_text(encrypted_text: str, password: str) -> str:
    """Descifra un texto usando AES con una clave derivada de la contraseña."""
    key = derive_key(password)
    encrypted_data = base64.b64decode(encrypted_text)
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data.decode('utf-8')
# RSA key generation
def generate_rsa_keys(passphrase: str):
    """Genera una clave pública y privada RSA, y devuelve las claves en formato PEM."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode())
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'file' in request.files:
            file = request.files['file']
            password = request.form.get('password')
            action = request.form.get('action')

            if file.filename == '' or not password:
                return redirect(request.url)

            if file and allowed_file(file.filename):
                filename = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
                file.save(filename)

                if action == 'encrypt':
                    encrypted_file = encrypt_file(filename, password)
                    return redirect(url_for('download_file', filename=os.path.basename(encrypted_file)))
                else:
                        decrypted_file = decrypt_file(filename, password)
                        return redirect(url_for('download_file', filename=os.path.basename(decrypted_file)))
                    

        elif 'text' in request.form:
            text = request.form['text']
            password = request.form.get('password')
            action = request.form.get('action')
            
            if not text or not password:
                return redirect(request.url)

            if action == 'encrypt':
                encrypted_text = encrypt_text(text, password)
                return render_template('index.html', encrypted_text=encrypted_text)
            elif action == 'decrypt':
                try:
                    decrypted_text = decrypt_text(text, password)
                    return render_template('index.html', decrypted_text=decrypted_text)
                except ValueError as e:
                    return f"Error: {str(e)}"
        elif 'generate-keys' in request.form:
            passphrase = request.form.get('passphrase')
            if not passphrase:
                return redirect(request.url)
            
            private_key, public_key = generate_rsa_keys(passphrase)
             # Combine keys into a single file content
            combined_keys = (
                "   CLAVE PÚBLICA :\n" +
                public_key.decode() +
                "\n\n" +
                "   CLAVE PRIVADA: \n" +
                private_key.decode() 
                
            )
            
            # Save combined keys to a file
            combined_keys_path = os.path.join(app.config['UPLOAD_FOLDER'], 'rsa_keys.txt')
            with open(combined_keys_path, 'w') as f:
                f.write(combined_keys)
            
            return redirect(url_for('download_combined_keys'))

    return render_template('index.html')

@app.route('/uploads/<filename>')
def download_file(filename):
    """Envía el archivo para descarga con el encabezado de Content-Disposition."""
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
@app.route('/download-combined-keys')
def download_combined_keys():
    """Permite descargar el archivo combinado de claves públicas y privadas."""
    return send_from_directory(app.config['UPLOAD_FOLDER'], 'rsa_keys.txt', as_attachment=True, download_name='rsa_keys.txt')
if __name__ == '__main__':
    app.run(debug=True)
