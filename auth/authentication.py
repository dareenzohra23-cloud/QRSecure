from functools import wraps
from flask import session, redirect, url_for, flash, request, jsonify
from typing import Optional, Dict, Any, Tuple
from database.models import get_user_by_username, get_user_by_id
from .password import verify_password

def login_user(username: str, password: str) -> Tuple[bool, Optional[Dict[str, Any]], str]:
    """
    Authenticates a user by username and password.
    Returns (success: bool, user_dict, message: str)
    """
    if not username or not password:
        return False, None, "Username and password are required"

    user = get_user_by_username(username.strip())
    if not user:
        return False, None, "Invalid username or password"

    if not verify_password(password, user['password_hash']):
        return False, None, "Invalid username or password"

    # Store in session
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['role'] = user['role']

    return True, user, "Login successful"

def logout_user() -> None:
    session.clear()

def get_current_user() -> Optional[Dict[str, Any]]:
    user_id = session.get('user_id')
    if not user_id:
        return None
    return get_user_by_id(user_id)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'Authentication required'}), 401
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('auth.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def role_required(required_role: str):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                if request.path.startswith('/api/'):
                    return jsonify({'success': False, 'error': 'Authentication required'}), 401
                flash("Please log in to access this page.", "warning")
                return redirect(url_for('auth.login', next=request.url))

            user_role = session.get('role')
            if user_role != required_role and user_role != 'ADMIN':
                if request.path.startswith('/api/'):
                    return jsonify({'success': False, 'error': 'Insufficient privileges'}), 403
                flash("You do not have permission to access this resource.", "danger")
                return redirect(url_for('dashboard.dashboard_view'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator
