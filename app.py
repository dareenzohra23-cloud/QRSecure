from flask import Flask, render_template
from config import Config
from database.database import init_db
from crypto.key_manager import KeyManager
from database.models import get_active_authority
from auth.authentication import get_current_user

# Import Blueprints
from routes.auth_routes import auth_bp
from routes.dashboard_routes import dashboard_bp
from routes.qr_routes import qr_bp
from routes.verify_routes import verify_bp
from routes.authority_routes import authority_bp
import os

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Ensure keys and database exist on startup
    with app.app_context():
        KeyManager().ensure_keys_exist()
        init_db()

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(qr_bp)
    app.register_blueprint(verify_bp)
    app.register_blueprint(authority_bp)

    # Global context processors for templates
    @app.context_processor
    def inject_global_data():
        user = get_current_user()
        authority = get_active_authority()
        return {
            'current_user': user,
            'active_authority': authority,
            'current_year': 2026
        }

    # Error handlers
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('base.html', error_title="Page Not Found (404)", error_msg="The requested URL was not found on this server."), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template('base.html', error_title="Internal Error (500)", error_msg="An unexpected error occurred. Please check server logs."), 500

    return app

app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )
