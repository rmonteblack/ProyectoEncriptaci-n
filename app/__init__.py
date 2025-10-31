from flask import Flask

def create_app():
    app = Flask(__name__, instance_relative_config=True)
    # configuración por defecto; override en instance/config.py
    app.config.from_mapping(
        SECRET_KEY='dev-key-change-me',
        UPLOAD_FOLDER='uploads',
        KEYS_FOLDER='keys',
        MAX_CONTENT_LENGTH=5 * 1024 * 1024,  # límite 5MB
    )

    # cargar config de instancia si existe
    try:
        app.config.from_pyfile('../instance/config.py', silent=True)
    except Exception:
        pass

    # registrar rutas
    from .routes import bp as routes_bp
    app.register_blueprint(routes_bp)

    return app
