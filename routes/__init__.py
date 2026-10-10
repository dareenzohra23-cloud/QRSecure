from .auth_routes import auth_bp
from .dashboard_routes import dashboard_bp
from .qr_routes import qr_bp
from .verify_routes import verify_bp
from .authority_routes import authority_bp

__all__ = [
    'auth_bp',
    'dashboard_bp',
    'qr_bp',
    'verify_bp',
    'authority_bp'
]
