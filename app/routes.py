# app/routes.py
import os
import base64
from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from werkzeug.utils import secure_filename

from . import crypto

bp = Blueprint('main', __name__)

# Filenames fijos
RSA_PRIV = "private_rsa.pem"
RSA_PUB = "public_rsa.pem"
EC_PRIV = "private_ec.pem"
EC_PUB = "public_ec.pem"

def keys_folder():
    path = current_app.config.get('KEYS_FOLDER', 'keys')
    os.makedirs(path, exist_ok=True)
    return path

def allowed_text_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ['txt', 'text', 'md']

# ---------------- Keys page -------------------------------------------------------

@bp.route('/')
def index():
    return redirect(url_for('main.keys'))

@bp.route('/keys', methods=['GET', 'POST'])
def keys():
    folder = keys_folder()
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'generate':
            alg = request.form.get('algorithm', 'RSA')
            key_size = int(request.form.get('key_size') or 2048)
            try:
                if alg == 'RSA':
                    priv, pub = crypto.generate_rsa(key_size)
                    priv_pem = crypto.private_key_to_pem(priv)
                    pub_pem = crypto.public_key_to_pem(pub)
                    crypto.save_key_to_file(os.path.join(folder, RSA_PRIV), priv_pem)
                    crypto.save_key_to_file(os.path.join(folder, RSA_PUB), pub_pem)
                    flash('Par de claves RSA generado y guardado.', 'success')
                else:
                    priv, pub = crypto.generate_ec()
                    priv_pem = crypto.private_key_to_pem(priv)
                    pub_pem = crypto.public_key_to_pem(pub)
                    crypto.save_key_to_file(os.path.join(folder, EC_PRIV), priv_pem)
                    crypto.save_key_to_file(os.path.join(folder, EC_PUB), pub_pem)
                    flash('Par de claves ECC (P-256) generado y guardado.', 'success')
            except Exception as e:
                flash(f'Error al generar claves: {str(e)}', 'danger')

        elif action == 'upload':
            priv_file = request.files.get('private_key_file')
            pub_file = request.files.get('public_key_file')
            try:
                if priv_file and priv_file.filename:
                    data = priv_file.read()
                    #buscar 'RSA' en PEM header para decidir ubicación
                    if b'RSA' in data:
                        out = os.path.join(folder, RSA_PRIV)
                    else:
                        out = os.path.join(folder, EC_PRIV)
                    crypto.save_key_to_file(out, data)
                    flash(f'Clave privada cargada y guardada como {os.path.basename(out)}', 'success')
                if pub_file and pub_file.filename:
                    data = pub_file.read()
                    if b'RSA' in data:
                        out = os.path.join(folder, RSA_PUB)
                    else:
                        out = os.path.join(folder, EC_PUB)
                    crypto.save_key_to_file(out, data)
                    flash(f'Clave pública cargada y guardada como {os.path.basename(out)}', 'success')
            except Exception as e:
                flash(f'Error al guardar claves: {str(e)}', 'danger')

        return redirect(url_for('main.keys'))

    #mostrar estado de claves
    keys_present = {
        'rsa_priv': os.path.exists(os.path.join(folder, RSA_PRIV)),
        'rsa_pub': os.path.exists(os.path.join(folder, RSA_PUB)),
        'ec_priv': os.path.exists(os.path.join(folder, EC_PRIV)),
        'ec_pub': os.path.exists(os.path.join(folder, EC_PUB)),
    }
    return render_template('keys.html', keys=keys_present)

# ---------------- Crypto page (encrypt/decrypt) ----------------------------------

@bp.route('/crypto', methods=['GET', 'POST'])
def crypto_page():
    folder = keys_folder()
    encrypted_text = ''
    decrypted_text = ''
    if request.method == 'POST':
        action = request.form.get('action')
        # asegurar algoritmo por defecto RSA si no se envía
        alg = request.form.get('algorithm', 'RSA')

        # --- ENCRYPT ---
        if action == 'encrypt':
            # leer texto o archivo
            plaintext = None
            if request.form.get('plaintext'):
                plaintext = request.form.get('plaintext').encode('utf-8')
            elif 'file' in request.files and request.files['file']:
                f = request.files['file']
                if f and f.filename and allowed_text_file(f.filename):
                    plaintext = f.read()
                else:
                    flash('Archivo no permitido o vacío (solo .txt)', 'warning')
                    return redirect(url_for('main.crypto_page'))

            if plaintext is None:
                flash('Proporciona texto o archivo para cifrar.', 'warning')
                return redirect(url_for('main.crypto_page'))

            try:
                if alg == 'RSA':
                    pub_path = os.path.join(folder, RSA_PUB)
                    if not os.path.exists(pub_path):
                        flash('No se encontró clave pública RSA. Genérala o súbela.', 'danger')
                        return redirect(url_for('main.crypto_page'))
                    pub_pem = crypto.load_pem_file(pub_path)
                    pub = crypto.load_public_key(pub_pem)
                    encrypted_text = crypto.rsa_encrypt(pub, plaintext)
                else:
                    pub_path = os.path.join(folder, EC_PUB)
                    if not os.path.exists(pub_path):
                        flash('No se encontró clave pública EC. Genérala o súbela.', 'danger')
                        return redirect(url_for('main.crypto_page'))
                    pub_pem = crypto.load_pem_file(pub_path)
                    pub = crypto.load_public_key(pub_pem)
                    encrypted_text = crypto.ec_encrypt(pub, plaintext)
                flash('Cifrado realizado con éxito.', 'success')
            except Exception as e:
                flash(f'Error al cifrar: {str(e)}', 'danger')

        # --- DECRYPT ---
        elif action == 'decrypt':
            b64_ct = request.form.get('ciphertext')
            if not b64_ct:
                flash('Proporciona texto cifrado (base64 / paquete) para descifrar.', 'warning')
                return redirect(url_for('main.crypto_page'))

            try:
                if alg == 'RSA':
                    priv_path = os.path.join(folder, RSA_PRIV)
                    if not os.path.exists(priv_path):
                        flash('No se encontró clave privada RSA. Genérala o súbela.', 'danger')
                        return redirect(url_for('main.crypto_page'))
                    priv_pem = crypto.load_pem_file(priv_path)
                    priv = crypto.load_private_key(priv_pem)
                    plaintext_bytes = crypto.rsa_decrypt(priv, b64_ct)
                else:
                    priv_path = os.path.join(folder, EC_PRIV)
                    if not os.path.exists(priv_path):
                        flash('No se encontró clave privada EC. Genérala o súbela.', 'danger')
                        return redirect(url_for('main.crypto_page'))
                    priv_pem = crypto.load_pem_file(priv_path)
                    priv = crypto.load_private_key(priv_pem)
                    plaintext_bytes = crypto.ec_decrypt(priv, b64_ct)

                # intentar decodificar a UTF-8, si no es texto, mostrar base64 del contenido
                try:
                    decrypted_text = plaintext_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    decrypted_text = "[AVISO: contenido no UTF-8] Base64: " + base64.b64encode(plaintext_bytes).decode('utf-8')

                flash('Descifrado correcto.', 'success')
            except Exception as e:
                flash(f'Error al descifrar: {str(e)}', 'danger')

    return render_template('crypto.html', encrypted_text=encrypted_text, decrypted_text=decrypted_text)

# ---------------- Sign page (sign / verify) --------------------------------------

@bp.route('/sign', methods=['GET', 'POST'])
def sign_page():
    folder = keys_folder()
    signature = ''
    verify_status = None

    if request.method == 'POST':
        action = request.form.get('action')
        alg = request.form.get('algorithm', 'RSA')

        if action == 'sign':
            # igual leer mensaje o archivo
            msg = None
            if request.form.get('msg_to_sign'):
                msg = request.form.get('msg_to_sign').encode('utf-8')
            elif 'file_to_sign' in request.files and request.files['file_to_sign']:
                f = request.files['file_to_sign']
                if f and f.filename and allowed_text_file(f.filename):
                    msg = f.read()
                else:
                    flash('Archivo no permitido o vacío (solo .txt)', 'warning')
                    return redirect(url_for('main.sign_page'))

            if msg is None:
                flash('Proporciona mensaje o archivo para firmar.', 'warning')
                return redirect(url_for('main.sign_page'))

            try:
                if alg == 'RSA':
                    priv_path = os.path.join(folder, RSA_PRIV)
                    if not os.path.exists(priv_path):
                        flash('No se encontró clave privada RSA. Genérala o súbela.', 'danger')
                        return redirect(url_for('main.sign_page'))
                    priv_pem = crypto.load_pem_file(priv_path)
                    priv = crypto.load_private_key(priv_pem)
                    signature = crypto.sign_rsa(priv, msg)
                else:
                    priv_path = os.path.join(folder, EC_PRIV)
                    if not os.path.exists(priv_path):
                        flash('No se encontró clave privada EC. Genérala o súbela.', 'danger')
                        return redirect(url_for('main.sign_page'))
                    priv_pem = crypto.load_pem_file(priv_path)
                    priv = crypto.load_private_key(priv_pem)
                    signature = crypto.sign_ecdsa(priv, msg)
                flash('Firma generada correctamente.', 'success')
            except Exception as e:
                flash(f'Error al firmar: {str(e)}', 'danger')

        elif action == 'verify':
            msg = request.form.get('msg_to_verify')
            sig = request.form.get('signature_input')
            if not msg or not sig:
                flash('Proporciona mensaje y firma para verificar.', 'warning')
                return redirect(url_for('main.sign_page'))
            try:
                if request.form.get('algorithm') == 'RSA':
                    pub_path = os.path.join(folder, RSA_PUB)
                    if not os.path.exists(pub_path):
                        flash('No se encontró clave pública RSA. Genérala o súbela.', 'danger')
                        return redirect(url_for('main.sign_page'))
                    pub_pem = crypto.load_pem_file(pub_path)
                    pub = crypto.load_public_key(pub_pem)
                    ok = crypto.verify_rsa(pub, msg.encode('utf-8'), sig)
                else:
                    pub_path = os.path.join(folder, EC_PUB)
                    if not os.path.exists(pub_path):
                        flash('No se encontró clave pública EC. Genérala o súbela.', 'danger')
                        return redirect(url_for('main.sign_page'))
                    pub_pem = crypto.load_pem_file(pub_path)
                    pub = crypto.load_public_key(pub_pem)
                    ok = crypto.verify_ecdsa(pub, msg.encode('utf-8'), sig)
                verify_status = 'VÁLIDA' if ok else 'INVÁLIDA'
                flash(f'Verificación: {verify_status}', 'info')
            except Exception as e:
                flash(f'Error al verificar: {str(e)}', 'danger')

    return render_template('sign.html', signature=signature, verify_status=verify_status)
