from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from auth.authentication import login_user, logout_user

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Support both form data and JSON
        if request.is_json:
            data = request.get_json()
            username = data.get('username', '').strip()
            password = data.get('password', '')
        else:
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')

        success, user, msg = login_user(username, password)
        if success:
            if request.is_json:
                return jsonify({'success': True, 'user': {'username': user['username'], 'role': user['role']}})
            flash(f"Welcome back, {user['username']}! Logged in as {user['role']}.", "success")
            next_url = request.args.get('next') or url_for('dashboard.dashboard_view')
            return redirect(next_url)
        else:
            if request.is_json:
                return jsonify({'success': False, 'error': msg}), 401
            flash(msg, "danger")

    return render_template('login.html')

@auth_bp.route('/logout')
def logout():
    logout_user()
    flash("You have been securely logged out.", "info")
    return redirect(url_for('auth.login'))

@auth_bp.route('/api/auth/status')
def auth_status():
    if 'user_id' in session:
        return jsonify({
            'authenticated': True,
            'user': {
                'id': session.get('user_id'),
                'username': session.get('username'),
                'role': session.get('role')
            }
        })
    return jsonify({'authenticated': False})
