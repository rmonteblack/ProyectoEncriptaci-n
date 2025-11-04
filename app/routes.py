# app/routes.py
import os
import base64
from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from werkzeug.utils import secure_filename

from . import crypto

# Se crea un Blueprint para organizar las rutas de la aplicación
bp = Blueprint('main', __name__)

# Filenames fijos que serán utilizados para guardar las claves generadas
RSA_PRIV = "private_rsa.pem"
RSA_PUB = "public_rsa.pem"
EC_PRIV = "private_ec.pem"
EC_PUB = "public_ec.pem"


# Función que devuelve la carpeta donde se guardarán las claves, crea la carpeta si no existe
def keys_folder():
    path = current_app.config.get('KEYS_FOLDER', 'keys')  # Recupera la ruta desde la configuración
    os.makedirs(path, exist_ok=True)  # Crea la carpeta si no existe
    return path


# Función que valida si el archivo es un archivo de texto permitido
def allowed_text_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ['txt', 'text', 'md']


# ---------------- Página de Claves (Keys page) --------------------------------------

@bp.route('/')  # Ruta por defecto
def index():
    # Redirige a la página de claves
    return redirect(url_for('main.keys'))


@bp.route('/keys', methods=['GET', 'POST'])  # Ruta para la gestión de claves
def keys():
    folder = keys_folder()  # Obtiene la carpeta donde se almacenarán las claves
    if request.method == 'POST':  # Si se recibe una solicitud POST
        action = request.form.get('action')  # Acción que se desea realizar
        if action == 'generate':  # Si la acción es generar claves
            alg = request.form.get('algorithm', 'RSA')  # Algoritmo a usar (por defecto RSA)
            key_size = int(request.form.get('key_size') or 2048)  # Tamaño de la clave (por defecto 2048)
            try:
                # Generación de claves RSA
                if alg == 'RSA':
                    priv, pub = crypto.generate_rsa(key_size)  # Genera las claves RSA
                    priv_pem = crypto.private_key_to_pem(priv)  # Convierte la clave privada a formato PEM
                    pub_pem = crypto.public_key_to_pem(pub)  # Convierte la clave pública a formato PEM
                    crypto.save_key_to_file(os.path.join(folder, RSA_PRIV),
                                            priv_pem)  # Guarda la clave privada en el archivo
                    crypto.save_key_to_file(os.path.join(folder, RSA_PUB),
                                            pub_pem)  # Guarda la clave pública en el archivo
                    flash('Par de claves RSA generado y guardado.', 'success')
                else:  # Si el algoritmo es ECC (Elliptic Curve Cryptography)
                    priv, pub = crypto.generate_ec()  # Genera las claves ECC
                    priv_pem = crypto.private_key_to_pem(priv)  # Convierte la clave privada a formato PEM
                    pub_pem = crypto.public_key_to_pem(pub)  # Convierte la clave pública a formato PEM
                    crypto.save_key_to_file(os.path.join(folder, EC_PRIV),
                                            priv_pem)  # Guarda la clave privada ECC en el archivo
                    crypto.save_key_to_file(os.path.join(folder, EC_PUB),
                                            pub_pem)  # Guarda la clave pública ECC en el archivo
                    flash('Par de claves ECC (P-256) generado y guardado.', 'success')
            except Exception as e:
                flash(f'Error al generar claves: {str(e)}', 'danger')

        elif action == 'upload':  # Si la acción es cargar claves
            priv_file = request.files.get('private_key_file')  # Clave privada subida
            pub_file = request.files.get('public_key_file')  # Clave pública subida
            try:
                # Guardar la clave privada
                if priv_file and priv_file.filename:
                    data = priv_file.read()  # Leer el archivo de la clave privada
                    # Decidir si es una clave RSA o EC según el contenido
                    if b'RSA' in data:
                        out = os.path.join(folder, RSA_PRIV)
                    else:
                        out = os.path.join(folder, EC_PRIV)
                    crypto.save_key_to_file(out, data)  # Guardar la clave en el archivo correspondiente
                    flash(f'Clave privada cargada y guardada como {os.path.basename(out)}', 'success')

                # Guardar la clave pública
                if pub_file and pub_file.filename:
                    data = pub_file.read()  # Leer el archivo de la clave pública
                    if b'RSA' in data:
                        out = os.path.join(folder, RSA_PUB)
                    else:
                        out = os.path.join(folder, EC_PUB)
                    crypto.save_key_to_file(out, data)  # Guardar la clave pública en el archivo correspondiente
                    flash(f'Clave pública cargada y guardada como {os.path.basename(out)}', 'success')
            except Exception as e:
                flash(f'Error al guardar claves: {str(e)}', 'danger')

        return redirect(url_for('main.keys'))  # Redirigir nuevamente a la página de claves

    # Mostrar estado de las claves (si existen)
    keys_present = {
        'rsa_priv': os.path.exists(os.path.join(folder, RSA_PRIV)),
        'rsa_pub': os.path.exists(os.path.join(folder, RSA_PUB)),
        'ec_priv': os.path.exists(os.path.join(folder, EC_PRIV)),
        'ec_pub': os.path.exists(os.path.join(folder, EC_PUB)),
    }
    return render_template('keys.html', keys=keys_present)  # Renderizar la página de claves con el estado de las claves


# ---------------- Página de Criptografía (Crypto page: encrypt/decrypt) --------------

@bp.route('/crypto', methods=['GET', 'POST'])  # Ruta para cifrar y descifrar datos
def crypto_page():
    folder = keys_folder()  # Obtener la carpeta de claves
    encrypted_text = ''
    decrypted_text = ''
    if request.method == 'POST':  # Si es una solicitud POST
        action = request.form.get('action')  # Acción a realizar (cifrar o descifrar)
        alg = request.form.get('algorithm', 'RSA')  # Algoritmo a usar (por defecto RSA)

        # --- ENCRYPT (Cifrar) ---
        if action == 'encrypt':
            plaintext = None
            # Obtener el texto a cifrar desde el formulario o un archivo
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
                # Realizar cifrado con RSA
                if alg == 'RSA':
                    pub_path = os.path.join(folder, RSA_PUB)
                    if not os.path.exists(pub_path):
                        flash('No se encontró clave pública RSA. Genérala o súbela.', 'danger')
                        return redirect(url_for('main.crypto_page'))
                    pub_pem = crypto.load_pem_file(pub_path)
                    pub = crypto.load_public_key(pub_pem)
                    encrypted_text = crypto.rsa_encrypt(pub, plaintext)  # Cifrar con RSA
                else:
                    # Realizar cifrado con EC (Elliptic Curve)
                    pub_path = os.path.join(folder, EC_PUB)
                    if not os.path.exists(pub_path):
                        flash('No se encontró clave pública EC. Genérala o súbela.', 'danger')
                        return redirect(url_for('main.crypto_page'))
                    pub_pem = crypto.load_pem_file(pub_path)
                    pub = crypto.load_public_key(pub_pem)
                    encrypted_text = crypto.ec_encrypt(pub, plaintext)  # Cifrar con EC

                flash('Cifrado realizado con éxito.', 'success')
            except Exception as e:
                flash(f'Error al cifrar: {str(e)}', 'danger')

        # --- DECRYPT (Descifrar) ---
        elif action == 'decrypt':
            b64_ct = request.form.get('ciphertext')
            if not b64_ct:
                flash('Proporciona texto cifrado (base64) para descifrar.', 'warning')
                return redirect(url_for('main.crypto_page'))

            try:
                # Realizar descifrado con RSA
                if alg == 'RSA':
                    priv_path = os.path.join(folder, RSA_PRIV)
                    if not os.path.exists(priv_path):
                        flash('No se encontró clave privada RSA. Genérala o súbela.', 'danger')
                        return redirect(url_for('main.crypto_page'))
                    priv_pem = crypto.load_pem_file(priv_path)
                    priv = crypto.load_private_key(priv_pem)
                    plaintext_bytes = crypto.rsa_decrypt(priv, b64_ct)  # Descifrar con RSA
                else:
                    # Realizar descifrado con EC (Elliptic Curve)
                    priv_path = os.path.join(folder, EC_PRIV)
                    if not os.path.exists(priv_path):
                        flash('No se encontró clave privada EC. Genérala o súbela.', 'danger')
                        return redirect(url_for('main.crypto_page'))
                    priv_pem = crypto.load_pem_file(priv_path)
                    priv = crypto.load_private_key(priv_pem)
                    plaintext_bytes = crypto.ec_decrypt(priv, b64_ct)  # Descifrar con EC

                # Intentar decodificar el texto descifrado como UTF-8, si no es posible, mostrarlo en base64
                try:
                    decrypted_text = plaintext_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    decrypted_text = "[AVISO: contenido no UTF-8] Base64: " + base64.b64encode(plaintext_bytes).decode(
                        'utf-8')

                flash('Descifrado correcto.', 'success')
            except Exception as e:
                flash(f'Error al descifrar: {str(e)}', 'danger')

    return render_template('crypto.html', encrypted_text=encrypted_text,
                           decrypted_text=decrypted_text)  # Renderizar la página de criptografía


# ---------------- Página de Firma (Sign page: sign / verify) ------------------------

@bp.route('/sign', methods=['GET', 'POST'])  # Ruta para firmar y verificar mensajes
def sign_page():
    folder = keys_folder()  # Obtener la carpeta de claves
    signature = ''
    verify_status = None

    if request.method == 'POST':  # Si es una solicitud POST
        action = request.form.get('action')  # Acción a realizar (firmar o verificar)
        alg = request.form.get('algorithm', 'RSA')  # Algoritmo a usar (por defecto RSA)

        if action == 'sign':  # Si la acción es firmar un mensaje
            msg = None
            # Obtener el mensaje o archivo a firmar
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
                # Firmar con RSA
                if alg == 'RSA':
                    priv_path = os.path.join(folder, RSA_PRIV)
                    if not os.path.exists(priv_path):
                        flash('No se encontró clave privada RSA. Genérala o súbela.', 'danger')
                        return redirect(url_for('main.sign_page'))
                    priv_pem = crypto.load_pem_file(priv_path)
                    priv = crypto.load_private_key(priv_pem)
                    signature = crypto.sign_rsa(priv, msg)  # Firmar con RSA
                else:
                    # Firmar con EC (Elliptic Curve)
                    priv_path = os.path.join(folder, EC_PRIV)
                    if not os.path.exists(priv_path):
                        flash('No se encontró clave privada EC. Genérala o súbela.', 'danger')
                        return redirect(url_for('main.sign_page'))
                    priv_pem = crypto.load_pem_file(priv_path)
                    priv = crypto.load_private_key(priv_pem)
                    signature = crypto.sign_ecdsa(priv, msg)  # Firmar con EC

                flash('Firma generada correctamente.', 'success')
            except Exception as e:
                flash(f'Error al firmar: {str(e)}', 'danger')

        elif action == 'verify':  # Si la acción es verificar una firma
            msg = request.form.get('msg_to_verify')
            sig = request.form.get('signature_input')
            if not msg or not sig:
                flash('Proporciona mensaje y firma para verificar.', 'warning')
                return redirect(url_for('main.sign_page'))
            try:
                # Verificar con RSA
                if request.form.get('algorithm') == 'RSA':
                    pub_path = os.path.join(folder, RSA_PUB)
                    if not os.path.exists(pub_path):
                        flash('No se encontró clave pública RSA. Genérala o súbela.', 'danger')
                        return redirect(url_for('main.sign_page'))
                    pub_pem = crypto.load_pem_file(pub_path)
                    pub = crypto.load_public_key(pub_pem)
                    ok = crypto.verify_rsa(pub, msg.encode('utf-8'), sig)  # Verificar con RSA
                else:
                    # Verificar con EC (Elliptic Curve)
                    pub_path = os.path.join(folder, EC_PUB)
                    if not os.path.exists(pub_path):
                        flash('No se encontró clave pública EC. Genérala o súbela.', 'danger')
                        return redirect(url_for('main.sign_page'))
                    pub_pem = crypto.load_pem_file(pub_path)
                    pub = crypto.load_public_key(pub_pem)
                    ok = crypto.verify_ecdsa(pub, msg.encode('utf-8'), sig)  # Verificar con EC

                verify_status = 'VÁLIDA' if ok else 'INVÁLIDA'  # Resultado de la verificación
                flash(f'Verificación: {verify_status}', 'info')
            except Exception as e:
                flash(f'Error al verificar: {str(e)}', 'danger')

    return render_template('sign.html', signature=signature,
                           verify_status=verify_status)  # Renderizar la página de firma
