from flask import Flask, render_template, request, redirect, url_for, send_file, session
import os
from crypto_utils import *
import hashlib
import base64

app = Flask(__name__)
app.secret_key = 'clave_segura'
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Claves
if not os.path.exists("a_priv.pem"):
    priv_a, pub_a = generar_claves()
    guardar_clave_privada(priv_a, "a_priv.pem")
    guardar_clave_publica(pub_a, "a_pub.pem")
else:
    priv_a = cargar_clave_privada("a_priv.pem")
    pub_a = cargar_clave_publica("a_pub.pem")

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    user = request.form['username']
    session['user'] = user
    if user == 'institucion_a':
        return redirect(url_for('panel_a'))
    elif user == 'institucion_b':
        return redirect(url_for('panel_b'))
    return "Usuario no válido"

@app.route('/panel_a')
def panel_a():
    if session.get('user') != 'institucion_a':
        return redirect(url_for('index'))
    return render_template('panel_a.html')

@app.route('/firmar', methods=['POST'])
def firmar():
    file = request.files['file']
    filename = file.filename
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    # Leer el documento
    with open(filepath, 'rb') as f:
        documento_bytes = f.read()

    # Calcular el hash
    hash_val = calcular_hash(documento_bytes)
    hash_bytes = bytes.fromhex(hash_val)

    # Guardar hash como archivo opcional
    hash_filename = os.path.splitext(filename)[0] + ".hash.txt"
    hash_path = os.path.join(UPLOAD_FOLDER, hash_filename)
    with open(hash_path, 'w') as f:
        f.write(hash_val)

    # Firmar el hash
    signature = firmar_hash(hash_bytes, priv_a)
    signature_filename = os.path.splitext(filename)[0] + ".sig"
    signature_path = os.path.join(UPLOAD_FOLDER, signature_filename)
    with open(signature_path, 'wb') as f:
        f.write(signature)

    return render_template('panel_a.html',
                           hash_file=hash_filename,
                           signature_file=signature_filename,
                           documento=filename)

@app.route('/descargar/<filename>')
def descargar(filename):
    return send_file(os.path.join(UPLOAD_FOLDER, filename), as_attachment=True)

@app.route('/panel_b')
def panel_b():
    if session.get('user') != 'institucion_b':
        return redirect(url_for('index'))
    return render_template('panel_b.html')

@app.route('/verificar', methods=['POST'])
def verificar():
    doc = request.files['documento']
    sig_file = request.files['signature_file']

    documento_bytes = doc.read()
    signature_bytes = sig_file.read()

    # Calcular hash local
    hash_val_local = calcular_hash(documento_bytes)
    hash_bytes_local = bytes.fromhex(hash_val_local)

    # Verificar la firma
    valido = verificar_firma(hash_bytes_local, signature_bytes, pub_a)

    return render_template('resultado_b.html',
                           valido=valido,
                           hash_local=hash_val_local,
                           signature=base64.b64encode(signature_bytes).decode())

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
