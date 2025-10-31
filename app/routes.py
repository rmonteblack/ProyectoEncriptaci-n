from flask import Blueprint, render_template, request, flash, redirect, url_for, send_file, current_app
import os

bp = Blueprint('main', __name__)

@bp.route('/')
def index():
    return redirect(url_for('main.keys'))

@bp.route('/keys', methods=['GET', 'POST'])
def keys():
    # formulario para generar/guardar/cargar claves
    return render_template('keys.html')

@bp.route('/crypto', methods=['GET', 'POST'])
def crypto_page():
    # cifrar y descifrar
    return render_template('crypto.html')

@bp.route('/sign', methods=['GET', 'POST'])
def sign_page():
    # firmar y verificar
    return render_template('sign.html')
